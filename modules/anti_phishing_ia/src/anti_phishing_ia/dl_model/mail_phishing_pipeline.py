#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pipeline pour la détection de phishing dans les emails.

Train  : MailPhishingTrain
Predict: MailPhishingPredict

Auteur: HOUNSOU Samuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import torch
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split as tts
from torch.utils.data import DataLoader
import joblib

from anti_phishing_ia.phishing_utils.logger import get_logger
from anti_phishing_ia.dl_model.mail_encoder import MailEncoder, MailEncoderDataset
from anti_phishing_ia.dl_model.constrative_loss import SupervisedConstrativeLoss
from anti_phishing_ia.dl_model.model import MailPhishing, MailPhishingDataset
from anti_phishing_ia.dl_model.mail_phishing_trainer import MailPhishingTrainer
from anti_phishing_ia.dl_model.mail_encoder_trainer import MailEncoderTrainer
from anti_phishing_ia.dl_model.callbacks import EarlyStopping
from anti_phishing_ia.dl_model.models_config import TEXT_MODEL_PATHS as MAIL_MODEL_PATHS
logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ════════════════════════════════════════════════════════════════════════════
# PARAMÈTRES — tout configurable ici
# ════════════════════════════════════════════════════════════════════════════

# ── Chemins ─────────────────────────────────────────────────────────────────
BASEDIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASEDIR, "mail_model"))
os.makedirs(MODELS_DIR, exist_ok=True)
# ── MailEncoder (contrastive) ──────────────────────────────────────────────
ENCODER_D_MODEL = 384 #256 384
ENCODER_NUM_FREEZE = 0.4      # fraction des couches à geler
ENCODER_DROPOUT = 0.2

# ── Contrastive Training ─────────────────────────────────────────────────────
CONTRASTIVE_TEMPERATURE = 0.07
CONTRASTIVE_LR = 2e-5
CONTRASTIVE_EPOCHS = 15 #10
CONTRASTIVE_BATCH_SIZE = 8
CONTRASTIVE_PATIENCE = 5
CONTRASTIVE_MAX_LENGTH = 512

# ── MailPhishing (classifier) ──────────────────────────────────────────────
MODEL_D_MODEL = 384 #256 384
MODEL_NUM_HEADS = 12
MODEL_NUM_LAYERS = 6
MODEL_FFN_FACTOR = 4
MODEL_DROPOUT = 0.2
MODEL_N_CLASSES = 2           # phishing / safe
MODEL_N_LAYERS = 256           # nombre de tokens à garder

# ── Classifier Training ────────────────────────────────────────────────────
CLASSIFIER_LR = 1e-4
CLASSIFIER_EPOCHS = 15 #20
CLASSIFIER_BATCH_SIZE = 8
CLASSIFIER_PATIENCE = 5
CLASSIFIER_TASK = "binary"    # "binary" ou "multiclass"


# ════════════════════════════════════════════════════════════════════════════
# CLASSE TRAIN
# ════════════════════════════════════════════════════════════════════════════
# try:
#     torch.set_num_threads(10)
# except:
#     pass

# try:
#     torch.set_num_interop_threads(10)
# except:
#     pass

class MailPhishingTrain:
    """
    Pipeline d'entraînement complet pour détection de phishing dans emails.

    Flow :
        Phase 1 → fit_encoder()   : contrastive training du MailEncoder
        Phase 2 → fit_classifier(): entraînement du MailPhishing
        
        Ou tout en une fois : fit_all()

    Save :
        save() → sauvegarde dans un dossier :
            encoder.zstd
            classifier.zstd
    """

    def __init__(
        self,
        model_type: str = "fast",     # very_fast / fast / full
        save_dir: str = None,
    ):
        assert model_type in MAIL_MODEL_PATHS, f"model_type invalide : {model_type}"
        self.model_type = model_type
        self.save_dir = save_dir or os.path.join(BASEDIR, "checkpoints", model_type)
        os.makedirs(self.save_dir, exist_ok=True)

        self.bert_path = MAIL_MODEL_PATHS[model_type]

        # Composants — initialisés dans les méthodes fit_*
        self.encoder = None
        self.classifier = None

        logger.print(f"🚀 MailPhishingTrain — mode : {model_type}")
        logger.print(f"   Save dir : {self.save_dir}")

    def __repr__(self):
        status_encoder = "✅" if self.encoder is not None else "⬜"
        status_classifier = "✅" if self.classifier is not None else "⬜"

        encoder_params = f"{self.encoder.num_params:,}" if self.encoder else "—"
        classifier_params = f"{self.classifier.num_params:,}" if self.classifier else "—"

        return (
            f"\n╔══════════════════════════════════════════════════════════════╗\n"
            f"║  🚀 MailPhishingTrain — Détection phishing emails             ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  📦 Modèle        : {self.model_type:<10s}                     ║\n"
            f"║  💾 Save dir      : {self.save_dir:<40s}                        ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  Phases :                                                      ║\n"
            f"║    {status_encoder}  MailEncoder    (contrastive)              ║\n"
            f"║    {status_classifier}  MailPhishing  (classification)         ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  🧠 Encoder       : {encoder_params:<15s} params               ║\n"
            f"║  🤖 Classifier    : {classifier_params:<15s} params            ║\n"
            f"╚════════════════════════════════════════════════════════════════╝"
        )

    def __str__(self):
        return self.__repr__()

    # ── Phase 1 : MailEncoder contrastif ────────────────────────────────────
    def fit_encoder(
        self,
        train_df,
        val_df=None,
        compile_model: bool = False,
    ):
        """
        Phase 1 — Entraîne le MailEncoder avec contrastive loss.

        Args:
            train_df: DataFrame avec colonnes ['text', 'label']
            val_df: DataFrame optionnel pour validation
            compile_model: Activer torch.compile
        """
        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 1 : Entraînement MailEncoder (Contrastive)")
        logger.print("═" * 60)

        # ── Encoder ──────────────────────────────────────────────────────────
        self.encoder = MailEncoder(
            bert_path_or_bert=self.bert_path,
            d_model=ENCODER_D_MODEL,
            model_type=self.model_type,
            num_layer_to_freeze=ENCODER_NUM_FREEZE,
            dropout=ENCODER_DROPOUT,
        )
        logger.print(f"   Paramètres encoder : {self.encoder.num_params:,}")

        # ── Datasets ─────────────────────────────────────────────────────────
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        train_dataset = MailEncoderDataset(
            tokenizer_or_model=tokenizer,
            text_dataset_path_or_df=train_df,
            max_length=CONTRASTIVE_MAX_LENGTH,
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size=CONTRASTIVE_BATCH_SIZE,
            shuffle=True,
            num_workers=0,
        )

        val_loader = None
        if val_df is not None:
            val_dataset = MailEncoderDataset(
                tokenizer_or_model=tokenizer,
                text_dataset_path_or_df=val_df,
                max_length=CONTRASTIVE_MAX_LENGTH,
            )
            val_loader = DataLoader(
                val_dataset,
                batch_size=CONTRASTIVE_BATCH_SIZE,
                shuffle=False,
                num_workers=0,
            )

        # ── Loss + Optimizer + Scheduler ─────────────────────────────────────
        loss = SupervisedConstrativeLoss(temperature=CONTRASTIVE_TEMPERATURE)
        optimizer = torch.optim.AdamW(
            filter(lambda p: p.requires_grad, self.encoder.parameters()),
            lr=CONTRASTIVE_LR
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=CONTRASTIVE_EPOCHS
        )
        early_stopping = EarlyStopping(patience=CONTRASTIVE_PATIENCE, mode="min")

        # ── Trainer ──────────────────────────────────────────────────────────
        trainer = MailEncoderTrainer(
            model=self.encoder,
            loss=loss,
            optimizer=optimizer,
            scheduler=scheduler,
            each_epochs=True,
            compile_model=compile_model,
            compile_loss=False,
            compile_steps=False,
        )

        history = trainer.fit(
            dataloader=train_loader,
            valloader=val_loader,
            epochs=CONTRASTIVE_EPOCHS,
            early_stopping=early_stopping,
            plot_history=True,
        )

        logger.print("✅ Phase 1 terminée")
        return history

    # ── Phase 2 : MailPhishing classifier ────────────────────────────────────
    def fit_classifier(
        self,
        train_df,
        val_df=None,
        compile_model: bool = False,
    ):
        """
        Phase 2 — Entraîne le MailPhishing sur les embeddings 3D.

        Args:
            train_df: DataFrame avec colonnes ['text', 'label']
            val_df: DataFrame optionnel pour validation
            compile_model: Activer torch.compile
        """
        if self.encoder is None:
            raise RuntimeError("fit_encoder() doit être appelé avant fit_classifier() !")

        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 2 : Entraînement MailPhishing")
        logger.print("═" * 60)

        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        # ── Modèle ───────────────────────────────────────────────────────────
        self.classifier = MailPhishing(
            d_model=MODEL_D_MODEL,
            num_heads=MODEL_NUM_HEADS,
            feed_forward_factor=MODEL_FFN_FACTOR,
            dropout=MODEL_DROPOUT,
            num_layer=MODEL_NUM_LAYERS,
            num_classe=MODEL_N_CLASSES,
            cls_only=False,           # Garde les tokens pour le transformer
            n_layers=MODEL_N_LAYERS,
        )
        logger.print(f"   Paramètres classifier : {self.classifier.num_params:,}")

        # ── Dataset ──────────────────────────────────────────────────────────
        train_dataset = MailPhishingDataset(
            tokenizer_or_model=tokenizer,
            text_dataset_path_or_df=train_df,
            max_length=CONTRASTIVE_MAX_LENGTH,
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size=CLASSIFIER_BATCH_SIZE,
            shuffle=True,
            num_workers=0,
        )

        val_loader = None
        if val_df is not None:
            val_dataset = MailPhishingDataset(
                tokenizer_or_model=tokenizer,
                text_dataset_path_or_df=val_df,
                max_length=CONTRASTIVE_MAX_LENGTH,
            )
            val_loader = DataLoader(
                val_dataset,
                batch_size=CLASSIFIER_BATCH_SIZE,
                shuffle=False,
                num_workers=0,
            )

        # ── Loss + Optimizer + Scheduler ─────────────────────────────────────
        loss = torch.nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(self.classifier.parameters(), lr=CLASSIFIER_LR)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=CLASSIFIER_EPOCHS
        )
        early_stopping = EarlyStopping(patience=CLASSIFIER_PATIENCE, mode="min")

        # ── Trainer (encoder frozen) ─────────────────────────────────────────
        is_trainable = {
            i: p.requires_grad
            for i, p in enumerate(self.encoder.parameters())
        }
        for param in self.encoder.parameters():
            param.requires_grad = False

        trainer = MailPhishingTrainer(
            model=self.classifier,
            loss=loss,
            optimizer=optimizer,
            scheduler=scheduler,
            mail_encoder=self.encoder,
            task=CLASSIFIER_TASK,
            num_classe=MODEL_N_CLASSES,
            each_epochs=True,
            compile_model=compile_model,
            compile_loss=False,
            compile_steps=False,
        )
        for i, param in enumerate(self.encoder.parameters()): 
            param.requires_grad = is_trainable[i]
        history = trainer.fit(
            dataloader=train_loader,
            valloader=val_loader,
            epochs=CLASSIFIER_EPOCHS,
            early_stopping=early_stopping,
            plot_history=True,
        )

        logger.print("✅ Phase 2 terminée")
        return history

    # ── fit_all ──────────────────────────────────────────────────────────────
    def fit_all(
        self,
        train_df,
        val_df=None,
        compile_model: bool = False,
    ):
        """
        Lance les deux phases d'entraînement d'un seul coup.
        """
        self.fit_encoder(train_df, val_df, compile_model)
        self.fit_classifier(train_df, val_df, compile_model)
        logger.print("\n🎉 Pipeline complet terminé !")

    # ── Save ─────────────────────────────────────────────────────────────────
    def save(self, directory: str = None):
        """
        Sauvegarde tous les composants dans un dossier :
            encoder.zstd
            classifier.zstd
        """
        directory = directory or self.save_dir
        os.makedirs(directory, exist_ok=True)

        logger.print(f"\n💾 Sauvegarde dans {directory}...")

        if self.encoder:
            self.encoder.save(os.path.join(directory, "encoder.zstd"))

        if self.classifier:
            self.classifier.save(os.path.join(directory, "classifier.zstd"))

        logger.print("✅ Tous les composants sauvegardés !")


# ════════════════════════════════════════════════════════════════════════════
# CLASSE PREDICT
# ════════════════════════════════════════════════════════════════════════════

class MailPhishingPredict:
    """
    Pipeline d'inférence pour détection de phishing dans emails.

    Usage :
        predictor = MailPhishingPredict.from_directory("checkpoints/fast")
        result = predictor.predict("Votre compte a été compromis: https://fake.com")
    """

    def __init__(
        self,
        model_type: str,
        encoder: MailEncoder,
        classifier: MailPhishing,
    ):
        self.model_type = model_type
        self.encoder = encoder
        self.classifier = classifier
        self.bert_path = MAIL_MODEL_PATHS[model_type]

        from transformers import AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        # Mode évaluation
        self.encoder.eval()
        self.classifier.eval()

        logger.print(f"✅ MailPhishingPredict prêt — mode : {model_type}")

    def __repr__(self):
        encoder_params = f"{self.encoder.num_params:,}" if self.encoder else "—"
        classifier_params = f"{self.classifier.num_params:,}" if self.classifier else "—"

        return (
            f"\n╔══════════════════════════════════════════════════════════════╗\n"
            f"║  🔮 MailPhishingPredict — Détection phishing emails            ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  📦 Modèle        : {self.model_type:<10s}                     ║\n"
            f"║  🧠 Encoder       : {encoder_params:<15s} params               ║\n"
            f"║  🤖 Classifier    : {classifier_params:<15s} params            ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  Usage :                                                       ║\n"
            f"║    predictor = MailPhishingPredict.from_directory()            ║\n"
            f"║    result   = predictor('Ton email ici')                       ║\n"
            f"╚════════════════════════════════════════════════════════════════╝"
        )

    def __str__(self):
        return self.__repr__()

    @classmethod
    def from_directory(cls, directory: str, model_type: str = "fast"):
        """
        Charge tous les composants depuis un dossier.
        """
        logger.print(f"📂 Chargement depuis {directory}...")

        bert_path = MAIL_MODEL_PATHS[model_type]

        # ── Encoder ──────────────────────────────────────────────────────────
        encoder = MailEncoder(
            bert_path_or_bert=bert_path,
            d_model=ENCODER_D_MODEL,
            model_type=model_type,
            num_layer_to_freeze=ENCODER_NUM_FREEZE,
            dropout=ENCODER_DROPOUT,
        )
        encoder.load(os.path.join(directory, "encoder.zstd"))

        # ── Classifier ───────────────────────────────────────────────────────
        classifier = MailPhishing(
            d_model=MODEL_D_MODEL,
            num_heads=MODEL_NUM_HEADS,
            feed_forward_factor=MODEL_FFN_FACTOR,
            dropout=MODEL_DROPOUT,
            num_layer=MODEL_NUM_LAYERS,
            num_classe=MODEL_N_CLASSES,
            cls_only=False,
            n_layers=MODEL_N_LAYERS,
        )
        classifier.load(os.path.join(directory, "classifier.zstd"))

        logger.print("✅ Tous les composants chargés !")

        return cls(
            model_type=model_type,
            encoder=encoder,
            classifier=classifier,
        )

    def _prepare_input(self, text: str):
        """Tokenise le texte pour l'inférence."""
        tokens = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=CONTRASTIVE_MAX_LENGTH,
            padding="max_length",
        )
        return {k: v.to(DEVICE) for k, v in tokens.items()}

    def predict(self, email_text: str, threshold: float = 0.5) -> dict:
        """
        Prédit si un email est phishing ou safe.

        Returns:
            dict: {
                'label': 'phishing' | 'safe',
                'confidence': float,
                'proba_phishing': float,
                'proba_safe': float,
                'risk_score': int (0-100)
            }
        """
        tokenizer_output = self._prepare_input(email_text)

        with torch.inference_mode():
            # Embedding 3D via encoder
            embeddings = self.encoder.predict(tokenizer_output, cache=True, output2d=False)  # [1, seq_len, d_model]
            
            # Classification
            logits = self.classifier(embeddings)  # [1, 2]
            probs = torch.softmax(logits, dim=-1)  # [1, 2]

        proba_phishing = probs[0, 1].item()
        proba_safe = probs[0, 0].item()
        confidence = max(proba_phishing, proba_safe)
        risk_score = int(proba_phishing * 100)

        return {
            'label': 'phishing' if proba_phishing > threshold else 'safe',
            'confidence': confidence,
            'proba_phishing': proba_phishing,
            'proba_safe': proba_safe,
            'risk_score': risk_score,
        }

    def predict_batch(self, texts: list[str], threshold: float = 0.5) -> list[dict]:
        """Prédit pour une liste d'emails."""
        return [self.predict(t, threshold) for t in texts]

    def __call__(self, text: str, threshold: float = 0.5):
        return self.predict(text, threshold)


# ════════════════════════════════════════════════════════════════════════════
# MAIN — test rapide
# ════════════════════════════════════════════════════════════════════════════

def create_test_dataset():
    """
    Crée un dataset synthétique pour tester le pipeline.
    
    Returns:
        train_df, val_df : DataFrames avec colonnes ['text', 'label']
        label: 1 = phishing, 0 = safe
    """
    data = [
        # Phishing (1)
        {"text": "URGENT: Votre compte bancaire a été compromis! Cliquez ici: https://fake-bank.com", "label": 1},
        {"text": "PayPal: Vérification requise de votre identité: https://paypal-verify.tk", "label": 1},
        {"text": "Votre colis ne peut pas être livré: https://amazon-delivery.xyz", "label": 1},
        {"text": "Alerte de sécurité Microsoft: https://microsoft-account-security.cf", "label": 1},
        {"text": "Facture impayée: Veuillez régulariser votre situation: https://fake-facture.com", "label": 1},
        
        # Safe (0)
        {"text": "Votre relevé bancaire du mois est disponible sur l'application", "label": 0},
        {"text": "Newsletter hebdomadaire: les meilleures offres de la semaine", "label": 0},
        {"text": "Confirmation de votre commande #12345 sur Amazon", "label": 0},
        {"text": "Votre rendez-vous du 15 mai est confirmé", "label": 0},
        {"text": "Facture mensuelle d'électricité - payez en ligne", "label": 0},
    ]
    
    df = pd.DataFrame(data)
    
    train_df, val_df = tts(df, test_size=0.3, stratify=df['label'], random_state=42)
    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)
    
    print(f"\n📊 Dataset créé :")
    print(f"   Train: {len(train_df)} ({train_df['label'].value_counts().to_dict()})")
    print(f"   Val: {len(val_df)} ({val_df['label'].value_counts().to_dict()})")
    
    return train_df, val_df

def test():
    logger.print("=== Test MailPhishing Pipeline ===\n")
    
    # Créer le dataset
    train_df, val_df = create_test_dataset()
    pth = "./data/email_dataset"
    # ── Train ─────────────────────────────────────────────────────────────────
    trainer = MailPhishingTrain(
        model_type="fast",
        save_dir="mail_model", #"/tmp/mail_phishing_test",
    )
    train_df, val_df = pd.read_csv(pth + "/train.csv"), pd.read_csv(pth + "/val.csv")
    # Lancer l'entraînement complet
    trainer.fit_all(train_df, val_df, compile_model=False)
    trainer.save()
    
    # Charger un modèle sauvegardé
    predictor = MailPhishingPredict.from_directory(
        directory="mail_model", #"/tmp/mail_phishing_test",
        model_type="very_fast"
    )
    
    # Tester
    result = predictor("URGENT: Votre compte a été piraté! https://secure-login.tk")
    print(result)
    
    result = predictor("Votre commande a été expédiée")
    print(result)
    
    logger.print("\nPipeline initialisé avec succès ✅")

def fit(
    path, 
    read_func, 
    test_size: float = 0.2,
    model_type: str = "fast", 
    save_dir: str = MODELS_DIR,
    compile_model: bool = False
):
    df = pd.DataFrame(read_func(path))
    try:
        train_df, val_df = tts(df, test_size=test_size, stratify=df['label'], random_state=42)
    except Exception:
        train_df, val_df = tts(df, test_size=test_size, random_state=42)
    
    try:
        val_df, test_df = tts(val_df, test_size=test_size / 2, random_state=42)
        trainer = MailPhishingTrain(
            model_type=model_type,
            save_dir=save_dir,
        )
        train_df = train_df.reset_index(drop=True)
        val_df = val_df.reset_index(drop=True)
        test_df = test_df.reset_index(drop=True)
        trainer.fit_all(train_df, val_df, compile_model=compile_model)
        trainer.save(directory=save_dir)
        
        # Charger un modèle sauvegardé
        predictor = MailPhishingPredict.from_directory(
            directory="mail_model", #"/tmp/mail_phishing_test",
            model_type=model_type
        )
    except KeyboardInterrupt:
        if "trainer" in locals():
            trainer.save()
    
    # Tester
    result = predictor("URGENT: Votre compte a été piraté! https://secure-login.tk")
    print(result)
    
    result = predictor("Votre commande a été expédiée")
    print(result)
    
    logger.print("\nPipeline initialisé avec succès ✅")
    return dict(
        trainer=trainer,
        predictor=predictor,
        df=df, 
        train_df=train_df, 
        test_df=test_df, 
        val_df=val_df
    )
    

# import os
# import torch
# from torch.utils.data import DataLoader
# from sklearn.model_selection import train_test_split as tts
# from transformers import AutoTokenizer

# from anti_phishing_ia.dl_model.mail_encoder import MailEncoder, MailEncoderDataset
# from anti_phishing_ia.dl_model.model import MailPhishing, MailPhishingDataset
# from anti_phishing_ia.dl_model.constrative_loss import SupervisedConstrativeLoss
# from anti_phishing_ia.dl_model.mail_encoder_trainer import MailEncoderTrainer
# from anti_phishing_ia.dl_model.mail_phishing_trainer import MailPhishingTrainer
# from anti_phishing_ia.dl_model.callbacks import EarlyStopping
# import anti_phishing_ia.dl_model.mail_phishing_pipeline as pipeline

# device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# def fit_chunk(trainer, chunk_df, test_size=0.2):
#     """
#     Continue l'entraînement de trainer.encoder et trainer.classifier
#     sur un nouveau chunk, en réutilisant les poids existants.

#     Fallback : si trainer.encoder est None, tente de charger depuis
#     le checkpoint "best" de MailEncoderTrainer.
#     """
#     chunk_df = chunk_df.reset_index(drop=True)
#     train_df, val_df = tts(chunk_df, test_size=test_size, stratify=chunk_df['label'], random_state=42)
#     train_df = train_df.reset_index(drop=True)
#     val_df = val_df.reset_index(drop=True)

#     tokenizer = AutoTokenizer.from_pretrained(trainer.bert_path)

#     # ════════════════════════════════════════════════════════════════════
#     # PHASE 1 — Continuer l'encoder (contrastive)
#     # ════════════════════════════════════════════════════════════════════

#     if trainer.encoder is None:
#         print("⚠️ trainer.encoder absent — recherche d'un checkpoint 'best'...")
#         trainer.encoder = MailEncoder(
#             bert_path_or_bert=trainer.bert_path,
#             d_model=pipeline.ENCODER_D_MODEL,
#             model_type=trainer.model_type,
#             num_layer_to_freeze=pipeline.ENCODER_NUM_FREEZE,
#             dropout=pipeline.ENCODER_DROPOUT,
#         )

#         # Chercher un checkpoint best dans CHECKPOINTS_DIR du mail_encoder_trainer
#         import anti_phishing_ia.dl_model.mail_encoder_trainer as met
#         ckpt_path = os.path.join(met.CHECKPOINTS_DIR, "checkpoint_best")
#         if os.path.exists(ckpt_path):
#             ckpt = torch.load(ckpt_path, map_location=device)
#             trainer.encoder.load_state_dict(ckpt["model"])
#             print(f"✅ Encoder restauré depuis {ckpt_path} (epoch {ckpt['epoch']})")
#         else:
#             print("⚠️ Aucun checkpoint trouvé — encoder repart de XLM-RoBERTa pré-entraîné")

#     train_dataset_enc = MailEncoderDataset(tokenizer, train_df, max_length=pipeline.CONTRASTIVE_MAX_LENGTH)
#     val_dataset_enc   = MailEncoderDataset(tokenizer, val_df,   max_length=pipeline.CONTRASTIVE_MAX_LENGTH)

#     train_loader_enc = DataLoader(train_dataset_enc, batch_size=pipeline.CONTRASTIVE_BATCH_SIZE, shuffle=True)
#     val_loader_enc   = DataLoader(val_dataset_enc,   batch_size=pipeline.CONTRASTIVE_BATCH_SIZE, shuffle=False)

#     enc_loss = SupervisedConstrativeLoss(temperature=pipeline.CONTRASTIVE_TEMPERATURE)
#     enc_optimizer = torch.optim.AdamW(
#         filter(lambda p: p.requires_grad, trainer.encoder.parameters()),
#         lr=pipeline.CONTRASTIVE_LR
#     )
#     enc_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(enc_optimizer, T_max=pipeline.CONTRASTIVE_EPOCHS)
#     enc_early_stopping = EarlyStopping(patience=pipeline.CONTRASTIVE_PATIENCE, mode="min")

#     encoder_trainer = MailEncoderTrainer(
#         model=trainer.encoder,
#         loss=enc_loss,
#         optimizer=enc_optimizer,
#         scheduler=enc_scheduler,
#         each_epochs=True,
#         compile_model=False,
#         compile_loss=False,
#     )

#     print("\n" + "═" * 60)
#     print("  PHASE 1 (chunk) : MailEncoder contrastif")
#     print("═" * 60)

#     history_encoder = encoder_trainer.fit(
#         dataloader=train_loader_enc,
#         valloader=val_loader_enc,
#         epochs=pipeline.CONTRASTIVE_EPOCHS,
#         early_stopping=enc_early_stopping,
#         plot_history=True,
#     )

#     # ════════════════════════════════════════════════════════════════════
#     # PHASE 2 — Continuer le classifier
#     # ════════════════════════════════════════════════════════════════════

#     if trainer.classifier is None:
#         print("⚠️ trainer.classifier absent — recherche d'un checkpoint 'best'...")
#         trainer.classifier = MailPhishing(
#             d_model=pipeline.MODEL_D_MODEL,
#             num_heads=pipeline.MODEL_NUM_HEADS,
#             feed_forward_factor=pipeline.MODEL_FFN_FACTOR,
#             dropout=pipeline.MODEL_DROPOUT,
#             num_layer=pipeline.MODEL_NUM_LAYERS,
#             num_classe=pipeline.MODEL_N_CLASSES,
#             cls_only=False,
#             n_layers=pipeline.MODEL_N_LAYERS,
#         )

#         import anti_phishing_ia.dl_model.mail_phishing_trainer as mpt
#         ckpt_path = os.path.join(mpt.CHECKPOINTS_DIR, "checkpoint_best")
#         if os.path.exists(ckpt_path):
#             ckpt = torch.load(ckpt_path, map_location=device)
#             trainer.classifier.load_state_dict(ckpt["model"])
#             print(f"✅ Classifier restauré depuis {ckpt_path} (epoch {ckpt['epoch']})")
#         else:
#             print("⚠️ Aucun checkpoint trouvé — classifier repart de zéro")

#     train_dataset_cls = MailPhishingDataset(tokenizer, train_df, max_length=pipeline.CONTRASTIVE_MAX_LENGTH)
#     val_dataset_cls   = MailPhishingDataset(tokenizer, val_df,   max_length=pipeline.CONTRASTIVE_MAX_LENGTH)

#     train_loader_cls = DataLoader(train_dataset_cls, batch_size=pipeline.CLASSIFIER_BATCH_SIZE, shuffle=True)
#     val_loader_cls   = DataLoader(val_dataset_cls,   batch_size=pipeline.CLASSIFIER_BATCH_SIZE, shuffle=False)

#     cls_loss = torch.nn.CrossEntropyLoss()
#     cls_optimizer = torch.optim.AdamW(trainer.classifier.parameters(), lr=pipeline.CLASSIFIER_LR)
#     cls_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(cls_optimizer, T_max=pipeline.CLASSIFIER_EPOCHS)
#     cls_early_stopping = EarlyStopping(patience=pipeline.CLASSIFIER_PATIENCE, mode="min")

#     # Encoder gelé pour la phase classifier
#     for param in trainer.encoder.parameters():
#         param.requires_grad = False

#     classifier_trainer = MailPhishingTrainer(
#         model=trainer.classifier,
#         loss=cls_loss,
#         optimizer=cls_optimizer,
#         scheduler=cls_scheduler,
#         mail_encoder=trainer.encoder,
#         task=pipeline.CLASSIFIER_TASK,
#         num_classe=pipeline.MODEL_N_CLASSES,
#         each_epochs=True,
#         compile_model=False,
#         compile_loss=False,
#     )

#     print("\n" + "═" * 60)
#     print("  PHASE 2 (chunk) : MailPhishing classifier")
#     print("═" * 60)

#     history_classifier = classifier_trainer.fit(
#         dataloader=train_loader_cls,
#         valloader=val_loader_cls,
#         epochs=pipeline.CLASSIFIER_EPOCHS,
#         early_stopping=cls_early_stopping,
#         plot_history=True,
#     )

#     return {
#         "trainer": trainer,
#         "history_encoder": history_encoder,
#         "history_classifier": history_classifier,
#         "train_df": train_df,
#         "val_df": val_df,
#     }

# ════════════════════════════════════════════════════════════════════════════
# USAGE
# ════════════════════════════════════════════════════════════════════════════

# trainer = result["trainer"]
# chunk_result = fit_chunk(trainer, df.loc[10000:20000])
#
# # Sauvegarder après chaque chunk
# trainer.save(directory=SAVE_DIR)
if __name__ == "__main__":
    # test()
    # fit(
    #     path="./datasets/generated/dataset.csv", #dataset_sample_1000
    #     read_func=pd.read_csv,
    #     test_size=0.2,
    #     model_type="full",
    # )
    predictor = MailPhishingPredict.from_directory(
        directory="./mail_model", 
        model_type="full"
    )
