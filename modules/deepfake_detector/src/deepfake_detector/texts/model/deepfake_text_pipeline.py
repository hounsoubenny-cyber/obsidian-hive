#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrustSignal — Pipeline Text Complet
Train  : DeepFakeDetectorTextTrain
Predict: DeepFakeDetectorTextPredict

Auteurs : Sam Hounsou + Claude
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import torch
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split as tts
from torch.utils.data import DataLoader
import joblib

from deepfake_detector.deepfake_utils.logger import get_logger
from deepfake_detector.texts.model.text_encoder import TextEncoder, TextEncoderDataset
from deepfake_detector.texts.model.text_encoder_trainer import Trainer as TextEncoderTrainer
from deepfake_detector.texts.model.constrative_loss import SupervisedConstrativeLoss
from deepfake_detector.texts.model.model import DeepFakeDetectorText, DeepFakeDetectorTextDataset
from deepfake_detector.texts.model.deepfake_text_trainer import Trainer as DeepFakeTrainer
from deepfake_detector.texts.model.stacking_ml import StackingML
from deepfake_detector.texts.model.callbacks import EarlyStopping
from deepfake_detector.texts.features.features_extractor import FeaturesExtractor
from deepfake_detector.models_config import TEXT_MODEL_PATHS
logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ════════════════════════════════════════════════════════════════════════════
# PARAMÈTRES — tout configurable ici
# ════════════════════════════════════════════════════════════════════════════

# ── Chemins ─────────────────────────────────────────────────────────────────
BASEDIR        = os.path.dirname(os.path.abspath(__file__))

# ── TextEncoder ──────────────────────────────────────────────────────────────
ENCODER_D_MODEL          = 256      # dimension de sortie de l'encoder
ENCODER_NUM_FREEZE       = 0.5      # fraction des couches à geler (0.5 = 50%)
ENCODER_DROPOUT          = 0.2
ENCODER_CLS_ONLY         = False    # False = full hidden state 3D

# ── Contrastive Training ─────────────────────────────────────────────────────
CONTRASTIVE_TEMPERATURE  = 0.07
CONTRASTIVE_LR           = 2e-5
CONTRASTIVE_EPOCHS       = 2 #10
CONTRASTIVE_BATCH_SIZE   = 32
CONTRASTIVE_PATIENCE     = 5        # EarlyStopping patience
CONTRASTIVE_MAX_LENGTH   = 512      # longueur max tokenizer

# ── Features ─────────────────────────────────────────────────────────────────
N_GRAM                   = 2        # n-gram pour entropy_n_gram

# ── Stacking ML ──────────────────────────────────────────────────────────────
ML_N_ESTIMATORS          = 100
ML_MAX_DEPTH             = 6
ML_CV                    = 5
ML_RANDOM_STATE          = 42
ML_OPTIMIZE              = False    # True = Optuna
ML_N_TRIALS              = 50       # trials Optuna si ML_OPTIMIZE=True

# ── DeepFakeDetectorText ─────────────────────────────────────────────────────
MODEL_D_MODEL            = 256
MODEL_NUM_HEADS          = 8
MODEL_NUM_LAYERS         = 4
MODEL_FFN_FACTOR         = 4
MODEL_DROPOUT            = 0.2
MODEL_N_CLASSES          = 2
MODEL_CLS_ONLY           = False
MODEL_N_LAYERS           = 64       # nombre de tokens de l'encoder à garder

# ── DeepFake Training ────────────────────────────────────────────────────────
DEEPFAKE_LR              = 1e-4
DEEPFAKE_EPOCHS          = 2 # 20
DEEPFAKE_BATCH_SIZE      = 32
DEEPFAKE_PATIENCE        = 5
DEEPFAKE_TASK            = "multiclass"  # "binary" ou "multiclass"

# ════════════════════════════════════════════════════════════════════════════
# CLASSE TRAIN
# ════════════════════════════════════════════════════════════════════════════

class DeepFakeDetectorTextTrain:
    """
    Pipeline d'entraînement complet pour TrustSignal Text.

    Flow :
        Phase 1 → fit_encoder()   : contrastive training du TextEncoder
        Phase 2 → fit_ml()        : fit le StackingML sur embeddings + features
        Phase 3 → fit_model()     : fit DeepFakeDetectorText
        
        Ou tout en une fois : fit_all()

    Save :
        save() → sauvegarde dans un dossier :
            encoder.zstd
            model.zstd
            ml.zstd
            scaler_embeddings.pkl
            scaler_features.pkl
            scaler_ml.pkl
    """

    def __init__(
        self,
        model_type:str = "full",       # very_fast / fast / full
        save_dir:str   = None,
    ):
        assert model_type in TEXT_MODEL_PATHS, f"model_type invalide : {model_type}"
        self.model_type = model_type
        self.save_dir   = save_dir or os.path.join(BASEDIR, "checkpoints", model_type)
        os.makedirs(self.save_dir, exist_ok=True)

        self.bert_path  = TEXT_MODEL_PATHS[model_type]

        # Composants — initialisés dans les méthodes fit_*
        self.encoder         = None
        self.model           = None
        self.ml              = None
        self.features        = FeaturesExtractor()
        self.scaler_emb      = RobustScaler()
        self.scaler_feat     = RobustScaler()
        self.scaler_ml       = RobustScaler()

        logger.print(f"🚀 TrustSignal Text Train — mode : {model_type}")
        logger.print(f"   Save dir : {self.save_dir}")

    def __repr__(self): # Affichage stylé
        status_encoder = "✅" if self.encoder is not None else "⬜"
        status_ml      = "✅" if self.ml is not None else "⬜"
        status_model   = "✅" if self.model is not None else "⬜"
        
        if self.encoder is not None:
            encoder_params = f"{self.encoder.num_params:,}"
        else:
            encoder_params = "—"
        
        if self.model is not None:
            model_params = f"{self.model.num_params:,}"
        else:
            model_params = "—"
        
        return (
            f"\n╔══════════════════════════════════════════════════════════════╗\n"
            f"║  🚀 DeepFakeDetectorTextTrain — TrustSignal v2                 ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  📦 Modèle        : {self.model_type:<10s}                     ║\n"
            f"║  💾 Save dir      : {self.save_dir:<40s}                        ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  Phases :                                                      ║\n"
            f"║    {status_encoder}  TextEncoder   (contrastive)               ║\n"
            f"║    {status_ml}  StackingML    (features + embedding)           ║\n"
            f"║    {status_model}  DeepFakeModel (transformer)                 ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  🧠 Encoder       : {encoder_params:<15s} params               ║\n"
            f"║  🤖 Model         : {model_params:<15s} params                  ║\n"
            f"╚════════════════════════════════════════════════════════════════╝"
        )
    def __str__(self):
        return self.__repr__()
    
    # ── Phase 1 : TextEncoder contrastif ────────────────────────────────────
    def fit_encoder(
        self,
        train_df,
        val_df   = None,
        compile_model:bool = False,
    ):
        """
        Phase 1 — Entraîne le TextEncoder avec contrastive loss.

        train_df : DataFrame avec colonnes ['text', 'label']
        val_df   : optionnel, même format
        """
        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 1 : Entraînement TextEncoder (Contrastive)")
        logger.print("═" * 60)

        # ── Encoder ──────────────────────────────────────────────────────────
        self.encoder = TextEncoder(
            bert_path_or_bert  = self.bert_path,
            d_model            = ENCODER_D_MODEL,
            model_type         = self.model_type,
            num_layer_to_freeze= ENCODER_NUM_FREEZE,
            dropout            = ENCODER_DROPOUT,
            cls_only           = ENCODER_CLS_ONLY,
        )
        logger.print(f"   Paramètres encoder : {self.encoder.num_params:,}")

        # ── Datasets ─────────────────────────────────────────────────────────
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        train_dataset = TextEncoderDataset(
            tokenizer_or_model       = tokenizer,
            text_dataset_path_or_df  = train_df,
            max_length               = CONTRASTIVE_MAX_LENGTH,
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size  = CONTRASTIVE_BATCH_SIZE,
            shuffle     = True,
            num_workers = 0,
        )

        val_loader = None
        if val_df is not None:
            val_dataset = TextEncoderDataset(
                tokenizer_or_model      = tokenizer,
                text_dataset_path_or_df = val_df,
                max_length              = CONTRASTIVE_MAX_LENGTH,
            )
            val_loader = DataLoader(
                val_dataset,
                batch_size  = CONTRASTIVE_BATCH_SIZE,
                shuffle     = False,
                num_workers = 0,
            )

        # ── Loss + Optimizer + Scheduler ─────────────────────────────────────
        loss      = SupervisedConstrativeLoss(temperature=CONTRASTIVE_TEMPERATURE)
        optimizer = torch.optim.AdamW(
            filter(lambda p: p.requires_grad, self.encoder.parameters()), # Filtrer seulement ceux qui on requires_grad=True
            lr=CONTRASTIVE_LR
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=CONTRASTIVE_EPOCHS
        )
        early_stopping = EarlyStopping(patience=CONTRASTIVE_PATIENCE, mode="min")

        # ── Trainer ──────────────────────────────────────────────────────────
        trainer = TextEncoderTrainer(
            model         = self.encoder,
            loss          = loss,
            optimizer     = optimizer,
            scheduler     = scheduler,
            each_epochs   = True,
            compile_model = compile_model,
            compile_loss  = False,
            compile_steps = False,
        )

        history = trainer.fit(
            dataloader     = train_loader,
            valloader      = val_loader,
            epochs         = CONTRASTIVE_EPOCHS,
            early_stopping = early_stopping,
            plot_history   = True,
        )

        logger.print("✅ Phase 1 terminée")
        return history

    # ── Phase 2 : Stacking ML ────────────────────────────────────────────────
    def fit_ml(self, train_df, val_df=None):
        """
        Phase 2 — Extrait embeddings + features, fit les scalers, fit le StackingML.

        Le TextEncoder doit être entraîné avant (fit_encoder).
        
        Flow :
            1. Extraire embeddings via encoder (frozen, output2d=True)
            2. Extraire features via FeaturesExtractor
            3. Fit scaler_emb sur embeddings
            4. Fit scaler_feat sur features
            5. Concatener → fit StackingML
            6. Extraire pred_proba → fit scaler_ml
        """
        if self.encoder is None:
            raise RuntimeError("fit_encoder() doit être appelé avant fit_ml() !")

        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 2 : Fit Stacking ML")
        logger.print("═" * 60)

        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        embeddings_list = []
        features_list   = []
        labels_list     = []

        self.encoder.eval()
        logger.print("   Extraction embeddings + features...")

        for _, row in train_df.iterrows():
            text  = str(row["text"])
            label = int(row["label"])

            # ── Embedding via encoder (2D pour ML) ───────────────────────────
            tokens = tokenizer(
                text,
                return_tensors = "pt",
                truncation     = True,
                max_length     = CONTRASTIVE_MAX_LENGTH,
                padding        = "max_length",
            )
            tokens = {k: v.to(DEVICE) for k, v in tokens.items()}
            with torch.inference_mode():
                emb = self.encoder(tokens, output2d=True)  # [1, d_model]
            embeddings_list.append(emb.cpu().numpy().squeeze())

            # ── Features handcraftées ────────────────────────────────────────
            _, feat_tensor = self.features(text, n_gram=N_GRAM)
            features_list.append(feat_tensor.numpy())

            labels_list.append(label)

        embeddings_arr = np.array(embeddings_list)   # [N, d_model]
        features_arr   = np.array(features_list)     # [N, n_features]
        labels_arr     = np.array(labels_list)       # [N]

        # ── Fit scalers ──────────────────────────────────────────────────────
        logger.print("   Fit scalers...")
        emb_scaled  = self.scaler_emb.fit_transform(embeddings_arr)
        feat_scaled = self.scaler_feat.fit_transform(features_arr)

        # ── Concatener pour le ML ─────────────────────────────────────────────
        X = np.concatenate([emb_scaled, feat_scaled], axis=1)  # [N, d+f]

        # ── Fit StackingML ───────────────────────────────────────────────────
        logger.print("   Fit StackingML...")
        self.ml = StackingML(
            n_classes     = MODEL_N_CLASSES,
            n_estimators  = ML_N_ESTIMATORS,
            max_depth     = ML_MAX_DEPTH,
            cv            = ML_CV,
            random_state  = ML_RANDOM_STATE,
        )
        self.ml.fit(X, labels_arr, optimize=ML_OPTIMIZE, n_trials=ML_N_TRIALS)

        # ── Évaluation rapide ────────────────────────────────────────────────
        self.ml.evaluate(X, labels_arr)

        # ── Fit scaler_ml sur pred_proba ─────────────────────────────────────
        # pred_proba sera utilisé comme ml_features dans DeepFakeDetectorText
        pred_proba = self.ml.predict_proba(X)   # [N, n_classes]
        self.scaler_ml.fit(pred_proba)

        logger.print("✅ Phase 2 terminée")

    # ── Phase 3 : DeepFakeDetectorText ──────────────────────────────────────
    def fit_model(
        self,
        train_df,
        val_df        = None,
        compile_model : bool = False,
    ):
        """
        Phase 3 — Entraîne DeepFakeDetectorText.

        Le TextEncoder et le StackingML doivent être entraînés avant.
        
        Flow :
            Input → encoder (frozen) → embeddings 3D
                  → features → scaler → ml → pred_proba → scaler_ml
                  → DeepFakeDetectorText → CrossEntropyLoss
        """
        if self.encoder is None:
            raise RuntimeError("fit_encoder() doit être appelé avant fit_model() !")
        if self.ml is None:
            raise RuntimeError("fit_ml() doit être appelé avant fit_model() !")

        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 3 : Entraînement DeepFakeDetectorText")
        logger.print("═" * 60)

        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        # Calculer n_features dynamiquement depuis un sample
        sample_text = str(train_df["text"].iloc[0])
        _, sample_feat = self.features(sample_text, n_gram=N_GRAM)
        n_features = len(sample_feat)
        n_ml_features = MODEL_N_CLASSES  # pred_proba shape

        logger.print(f"   N features handcraftées : {n_features}")
        logger.print(f"   N ml features           : {n_ml_features}")

        # ── Modèle ───────────────────────────────────────────────────────────
        self.model = DeepFakeDetectorText(
            d_model            = MODEL_D_MODEL,
            num_heads          = MODEL_NUM_HEADS,
            num_features       = n_features,
            ml_proba_features  = n_ml_features,
            feed_forward_factor= MODEL_FFN_FACTOR,
            dropout            = MODEL_DROPOUT,
            num_layer          = MODEL_NUM_LAYERS,
            num_classe         = MODEL_N_CLASSES,
            cls_only           = MODEL_CLS_ONLY,
            n_layers           = MODEL_N_LAYERS,
        )
        logger.print(f"   Paramètres modèle : {self.model.num_params:,}")

        # ── Dataset ──────────────────────────────────────────────────────────
        # On pré-calcule les ml_features pour tout le dataset
        train_ml_preds = self._compute_ml_preds(train_df, tokenizer)
        val_ml_preds   = self._compute_ml_preds(val_df, tokenizer) if val_df is not None else None

        train_dataset = DeepFakeDetectorTextDataset(
            features_extractor      = lambda t: self.features(t, n_gram=N_GRAM)[1].numpy(), # Elegent
            tokenizer_or_model      = tokenizer,
            text_dataset_path_or_df = train_df,
            ml_preds_path_or_df     = train_ml_preds,
            max_length              = CONTRASTIVE_MAX_LENGTH,
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size  = DEEPFAKE_BATCH_SIZE,
            shuffle     = True,
            num_workers = 0,
        )

        val_loader = None
        if val_df is not None and val_ml_preds is not None:
            val_dataset = DeepFakeDetectorTextDataset(
                features_extractor      = lambda t: self.features(t, n_gram=N_GRAM)[1].numpy(),
                tokenizer_or_model      = tokenizer,
                text_dataset_path_or_df = val_df,
                ml_preds_path_or_df     = val_ml_preds,
                max_length              = CONTRASTIVE_MAX_LENGTH,
            )
            val_loader = DataLoader(
                val_dataset,
                batch_size  = DEEPFAKE_BATCH_SIZE,
                shuffle     = False,
                num_workers = 0,
            )

        # ── Loss + Optimizer + Scheduler ─────────────────────────────────────
        loss      = torch.nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=DEEPFAKE_LR)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=DEEPFAKE_EPOCHS
        )
        early_stopping = EarlyStopping(patience=DEEPFAKE_PATIENCE, mode="min")

        # ── Trainer ──────────────────────────────────────────────────────────
        # Encoder frozen pendant phase 3
        is_trainable = {
            i: p.requires_grad
            for i, p in enumerate(self.encoder.parameters())
        }
        for param in self.encoder.parameters():
            param.requires_grad = False

        trainer = DeepFakeTrainer(
            model         = self.model,
            loss          = loss,
            optimizer     = optimizer,
            scheduler     = scheduler,
            text_encoder  = self.encoder,
            task          = DEEPFAKE_TASK,
            num_classe    = MODEL_N_CLASSES,
            each_epochs   = True,
            compile_model = compile_model,
            compile_loss  = False,
        )
        
        for i, param in enumerate(self.encoder.parameters()): 
            param.requires_grad = is_trainable[i]
            
        history = trainer.fit(
            dataloader     = train_loader,
            valloader      = val_loader,
            epochs         = DEEPFAKE_EPOCHS,
            early_stopping = early_stopping,
            plot_history   = True,
        )

        logger.print("✅ Phase 3 terminée")
        return history

    def _compute_ml_preds(self, df, tokenizer) -> "pd.DataFrame":
        """
        Calcule les pred_proba du StackingML pour tout un DataFrame.
        Retourne un DataFrame des prédictions — utilisé comme ml_preds dans le Dataset.
        """
        import pandas as pd

        preds = []
        self.encoder.eval()

        for _, row in df.iterrows():
            text = str(row["text"])

            tokens = tokenizer(
                text,
                return_tensors = "pt",
                truncation     = True,
                max_length     = CONTRASTIVE_MAX_LENGTH,
                padding        = "max_length",
            )
            tokens = {k: v.to(DEVICE) for k, v in tokens.items()}

            with torch.inference_mode():
                emb = self.encoder(tokens, output2d=True).cpu().numpy().squeeze()

            _, feat = self.features(text, n_gram=N_GRAM)
            feat = feat.numpy()

            emb_scaled  = self.scaler_emb.transform(emb.reshape(1, -1))
            feat_scaled = self.scaler_feat.transform(feat.reshape(1, -1))
            X           = np.concatenate([emb_scaled, feat_scaled], axis=1)

            proba       = self.ml.predict_proba(X)                               # [1, n_classes]
            proba_scaled = self.scaler_ml.transform(proba).astype(np.float32)      # [1, n_classes]
            preds.append(proba_scaled.squeeze().tolist())

        return pd.DataFrame(preds)

    # ── fit_all ──────────────────────────────────────────────────────────────
    def fit_all(
        self,
        train_df,
        val_df        = None,
        compile_model : bool = False,
    ):
        """
        Lance les 3 phases d'entraînement d'un seul coup.
        """
        self.fit_encoder(train_df, val_df, compile_model)
        self.fit_ml(train_df, val_df)
        self.fit_model(train_df, val_df, compile_model)
        logger.print("\n🎉 Pipeline complet terminé !")

    # ── Save ─────────────────────────────────────────────────────────────────
    def save(self, directory:str = None):
        """
        Sauvegarde tous les composants dans un dossier :
            encoder.zstd
            model.zstd
            ml.zstd
            scaler_embeddings.pkl
            scaler_features.pkl
            scaler_ml.pkl
        """
        directory = directory or self.save_dir
        os.makedirs(directory, exist_ok=True)

        logger.print(f"\n💾 Sauvegarde dans {directory}...")

        if self.encoder:
            self.encoder.save(os.path.join(directory, "encoder.zstd"))

        if self.model:
            self.model.save(os.path.join(directory, "model.zstd"))

        if self.ml:
            self.ml.save(os.path.join(directory, "ml.zstd"))

        joblib.dump(self.scaler_emb,  os.path.join(directory, "scaler_embeddings.pkl"))
        joblib.dump(self.scaler_feat, os.path.join(directory, "scaler_features.pkl"))
        joblib.dump(self.scaler_ml,   os.path.join(directory, "scaler_ml.pkl"))

        logger.print("✅ Tous les composants sauvegardés !")


# ════════════════════════════════════════════════════════════════════════════
# CLASSE PREDICT
# ════════════════════════════════════════════════════════════════════════════

class DeepFakeDetectorTextPredict:
    """
    Pipeline d'inférence pour TrustSignal Text.

    Usage :
        predictor = DeepFakeDetectorTextPredict.from_directory("checkpoints/full")
        result = predictor.predict("Ce texte est-il généré par une IA ?")
    """

    def __init__(
        self,
        model_type : str,
        encoder    : TextEncoder,
        model      : DeepFakeDetectorText,
        ml         : StackingML,
        scaler_emb,
        scaler_feat,
        scaler_ml,
    ):
        self.model_type  = model_type
        self.encoder     = encoder
        self.model       = model
        self.ml          = ml
        self.scaler_emb  = scaler_emb
        self.scaler_feat = scaler_feat
        self.scaler_ml   = scaler_ml
        self.features    = FeaturesExtractor()
        self.bert_path   = TEXT_MODEL_PATHS[model_type]

        from transformers import AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.bert_path)

        # Tout en eval
        # self.encoder.to(torch.bfloat16)
        # self.model.to(torch.bfloat16)
        self.encoder.eval()
        self.model.eval()
        
        logger.print(f"✅ TrustSignal Predict prêt — mode : {model_type}")

    def __repr__(self): # Affichage stylé
        if self.encoder is not None:
            encoder_params = f"{self.encoder.num_params:,}"
        else:
            encoder_params = "—"
        
        if self.model is not None:
            model_params = f"{self.model.num_params:,}"
        else:
            model_params = "—"
        
        return (
            f"\n╔══════════════════════════════════════════════════════════════╗\n"
            f"║  🔮 DeepFakeDetectorTextPredict — TrustSignal v2               ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  📦 Modèle        : {self.model_type:<10s}                     ║\n"
            f"║  🧠 Encoder       : {encoder_params:<15s} params               ║\n"
            f"║  🤖 Model         : {model_params:<15s} params                  ║\n"
            f"║  📊 ML            : prêt                                       ║\n"
            f"║  📏 Scalers       : emb + feat + ml                            ║\n"
            f"╠════════════════════════════════════════════════════════════════╣\n"
            f"║  Usage :                                                       ║\n"
            f"║    predictor = DeepFakeDetectorTextPredict.from_directory()    ║\n"
            f"║    result   = predictor('Ton texte ici')                       ║\n"
            f"╚════════════════════════════════════════════════════════════════╝"
        )
    
    def __str__(self):
        return self.__repr__()
    
    @classmethod
    def from_directory(cls, directory:str, model_type:str = "full"):
        """
        Charge tous les composants depuis un dossier.
        Pattern inverse de DeepFakeDetectorTextTrain.save()
        """
        logger.print(f"📂 Chargement depuis {directory}...")

        bert_path = TEXT_MODEL_PATHS[model_type]

        # ── Encoder ──────────────────────────────────────────────────────────
        encoder = TextEncoder(
            bert_path_or_bert   = bert_path,
            d_model             = ENCODER_D_MODEL,
            model_type          = model_type,
            num_layer_to_freeze = ENCODER_NUM_FREEZE,
            dropout             = ENCODER_DROPOUT,
            cls_only            = ENCODER_CLS_ONLY,
        )
        encoder.load(os.path.join(directory, "encoder.zstd"))

        # ── Model ─────────────────────────────────────────────────────────────
        model = DeepFakeDetectorText(
            d_model             = MODEL_D_MODEL,
            num_heads           = MODEL_NUM_HEADS,
            num_features        = 1,           # sera écrasé par load()
            ml_proba_features   = MODEL_N_CLASSES,
            feed_forward_factor = MODEL_FFN_FACTOR,
            dropout             = MODEL_DROPOUT,
            num_layer           = MODEL_NUM_LAYERS,
            num_classe          = MODEL_N_CLASSES,
            cls_only            = MODEL_CLS_ONLY,
            n_layers            = MODEL_N_LAYERS,
        )
        model.load(os.path.join(directory, "model.zstd"))

        # ── ML ───────────────────────────────────────────────────────────────
        ml = StackingML(n_classes=MODEL_N_CLASSES)
        ml.load(os.path.join(directory, "ml.zstd"))

        # ── Scalers ───────────────────────────────────────────────────────────
        scaler_emb  = joblib.load(os.path.join(directory, "scaler_embeddings.pkl"))
        scaler_feat = joblib.load(os.path.join(directory, "scaler_features.pkl"))
        scaler_ml   = joblib.load(os.path.join(directory, "scaler_ml.pkl"))

        logger.print("✅ Tous les composants chargés !")

        return cls(
            model_type  = model_type,
            encoder     = encoder,
            model       = model,
            ml          = ml,
            scaler_emb  = scaler_emb,
            scaler_feat = scaler_feat,
            scaler_ml   = scaler_ml,
        )

    def _prepare_input(self, text:str):
        """
        Prépare toutes les entrées pour un texte donné.
        Retourne (embedding_3d, ml_features_tensor)
        """
        tokens = self.tokenizer(
            text,
            return_tensors = "pt",
            truncation     = True,
            max_length     = CONTRASTIVE_MAX_LENGTH,
            padding        = "max_length",
        )
        tokens = {k: v.to(DEVICE) for k, v in tokens.items()}
        
        with torch.inference_mode():
            # Embedding 3D pour DeepFakeDetectorText
            emb_3d = self.encoder(tokens, output2d=False)   # [1, T, d_model]

            # Embedding 2D pour le ML
            emb_2d = self.encoder(tokens, output2d=True)    # [1, d_model]

        emb_2d_np = emb_2d.cpu().numpy()

        # Features handcraftées
        _, feat_tensor = self.features(text, n_gram=N_GRAM)
        feat_np = feat_tensor.numpy().reshape(1, -1)

        # Scalers
        emb_scaled  = self.scaler_emb.transform(emb_2d_np)
        feat_scaled = self.scaler_feat.transform(feat_np)

        # ML pred_proba
        X           = np.concatenate([emb_scaled, feat_scaled], axis=1)
        proba_ml    = self.ml.predict_proba(X)
        proba_scaled = self.scaler_ml.transform(proba_ml).astype(np.float32)

        ml_features = torch.tensor(proba_scaled, dtype=torch.float32).to(DEVICE)
        feat_tensor = torch.tensor(feat_scaled, dtype=torch.float32).to(DEVICE)

        return emb_3d, feat_tensor, ml_features

    def predict_proba(self, text: str, threshold:float = 0.5) -> list:
        """Rerourne une liste des probabilités, utile si on veut juste les proba."""
        emb_3d, feat, ml_feat = self._prepare_input(text)
        with torch.inference_mode():
            logits = self.model(emb_3d, feat, ml_feat)          # [1, n_classes]
            proba, pred = self.model.predict(
                emb_3d, feat, ml_feat, logits, threshold
            )
            proba_list = proba.cpu().squeeze().tolist()
            return proba_list

    def predict(self, text:str, threshold:float = 0.5) -> dict:
        """
        Prédit si un texte est IA ou humain.

        Retourne un dict :
        {
            "label"      : "AI" ou "Human",
            "confidence" : float,
            "proba"      : [p_human, p_ia],
            "score"      : int 0-100 (score IA)
        }
        """
        emb_3d, feat, ml_feat = self._prepare_input(text)

        with torch.inference_mode():
            logits = self.model(emb_3d, feat, ml_feat)          # [1, n_classes]
            proba, pred = self.model.predict(
                emb_3d, feat, ml_feat, logits, threshold
            )

        proba_list = proba.cpu().squeeze().tolist()
        pred_int   = pred.cpu().item()

        # Score IA entre 0 et 100
        score_ia = int(proba_list[1] * 100) if len(proba_list) > 1 else int(proba_list[0] * 100)

        return {
            "label"      : "AI" if pred_int == 1 else "Human",
            "confidence" : max(proba_list),
            "proba"      : proba_list,
            "score"      : score_ia,
        }

    def predict_batch(self, texts:list[str], threshold:float = 0.5) -> list[dict]:
        """Prédit pour une liste de textes."""
        return [self.predict(t, threshold) for t in texts]

    def __call__(self, text:str, threshold:float = 0.5) -> dict|list[dict]:
        return self.predict(text, threshold) if isinstance(text, str) else self.predict_batch(text, threshold)

def create_test_dataset():
    """
    Crée un dataset synthétique équilibré pour tester le pipeline.
    
    Returns:
        train_df, val_df : DataFrames avec colonnes ['text', 'label']
    """
    # ── Corpus 1 : Textes formels vs informels ──────────────────────────
    data_formal = {
        "text": [
            # IA (1) — style formel, académique
            "Moreover, it is important to note that AI has significantly transformed society.",
            "Furthermore, these results clearly indicate that the model performs well.",
            "It is worth noting that this approach yields significant improvements.",
            "Additionally, the data suggests that further research is needed.",
            "Consequently, the implementation of these algorithms leads to better outcomes.",
            "The empirical evidence demonstrates a strong correlation between the variables.",
            # Humain (0) — style informel, oral
            "j'sais pas trop, ça dépend vraiment du moment.",
            "hier j'ai essayé et franchement c'était pas ouf du tout.",
            "bon bah voilà quoi, c'est la vie comme on dit.",
            "t'as vu le match hier ? incroyable ce but à la dernière minute !",
            "mdr t'as trop raison, j'avais pas pensé à ça",
            "franchement je sais pas quoi faire, help me please",
        ],
        "label": [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
    }
    
    # ── Corpus 2 : Textes IA vs Humains variés ──────────────────────────
    corpus_varied = [
        # Humains (0) — vie quotidienne, émotions, narration
        {"text": "Je suis allé au marché ce matin pour acheter des légumes frais.", "label": 0},
        {"text": "Hier soir, j'ai vu un film vraiment émouvant au cinéma.", "label": 0},
        {"text": "Ma grand-mère m'a préparé un délicieux gâteau au chocolat.", "label": 0},
        {"text": "Promenade au parc avec mon chien, il était tout fou.", "label": 0},
        {"text": "J'ai oublié mes clés à l'intérieur, quelle galère sérieux.", "label": 0},
        {"text": "Barbecue entre amis ce weekend, c'était trop cool !", "label": 0},
        {"text": "Je n'arrive pas à dormir avec cette chaleur, c'est insupportable.", "label": 0},
        {"text": "Mon fils a perdu sa première dent aujourd'hui, il était tout fier.", "label": 0},
        {"text": "J'ai renversé mon café sur mon clavier, je suis dégoûté.", "label": 0},
        {"text": "Ce matin, le réveil n'a pas sonné, du coup j'étais en retard.", "label": 0},
        
        # IA (1) — technique, académique, formel
        {"text": "L'intelligence artificielle révolutionne le paysage technologique contemporain.", "label": 1},
        {"text": "Les algorithmes d'apprentissage profond permettent une analyse prédictive avancée.", "label": 1},
        {"text": "L'optimisation des hyperparamètres améliore significativement les performances.", "label": 1},
        {"text": "Le traitement automatique du langage facilite l'extraction d'informations.", "label": 1},
        {"text": "Les réseaux de neurones convolutifs excellent dans la reconnaissance d'images.", "label": 1},
        {"text": "La descente de gradient stochastique optimise la fonction de coût.", "label": 1},
        {"text": "Les transformeurs utilisent des mécanismes d'attention pour capturer les dépendances.", "label": 1},
        {"text": "L'apprentissage par transfert exploite des modèles pré-entraînés.", "label": 1},
        {"text": "La régularisation L2 réduit le surapprentissage en pénalisant les poids élevés.", "label": 1},
        {"text": "Les modèles génératifs produisent des données synthétiques réalistes.", "label": 1},
    ]
    
    # ── Assembler ────────────────────────────────────────────────────────
    df1 = pd.DataFrame(data_formal)
    df2 = pd.DataFrame(corpus_varied)
    df = pd.concat([df1, df2], axis=0).reset_index(drop=True)
    
    # ── Split stratifié ──────────────────────────────────────────────────
    train_df, val_df = tts(
        df,
        test_size=0.25,
        stratify=df['label'],
        random_state=42
    )
    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)
    
    # ── Log ──────────────────────────────────────────────────────────────
    print("\n📊 Dataset créé :")
    print(f"   Total  : {len(df)} textes")
    print(f"   Train  : {len(train_df)} ({train_df['label'].value_counts().to_dict()})")
    print(f"   Val    : {len(val_df)} ({val_df['label'].value_counts().to_dict()})")
    print(f"   Classes: IA (1) = {df['label'].sum()}, Humain (0) = {len(df) - df['label'].sum()}")
    
    return train_df, val_df


# ═══════════════════════════════════════════════════════════════════════════
# MAIN — test rapide
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.print("=== Test Pipeline TrustSignal Text ===\n")
    
    # Créer le dataset
    train_df, val_df = create_test_dataset()
    
    # ── Train ─────────────────────────────────────────────────────────────────
    trainer = DeepFakeDetectorTextTrain(
        model_type = "fast",
        save_dir   = "/tmp/trustsignal_test",
    )

    # Juste le ML pour tester rapidement sans GPU
    # trainer.fit_all(train_df, val_df) # ← décommenter pour full pipeline
    # trainer.save()
    # Charger le modèle sauvegardé
    predictor = DeepFakeDetectorTextPredict.from_directory(
        directory="/home/hounsousamuel/PROJETS/deepfake_detector/texts/model/trustsignal_test",
        model_type="fast"
    )
    
    # Tester
    result = predictor("L'intelligence artificielle révolutionne le monde.")
    print(result)  # → {'label': 'AI', 'confidence': ..., 'score': ...}
    
    result = predictor("Je suis allé au marché ce matin.")
    print(result)  # → {'label': 'Human', 'confidence': ..., 'score': ...}
    
    # trainer.fit_model(train_df, val_df)

    logger.print("Pipeline initialisé avec succès ✅")
    logger.print("Décommenter fit_all() pour lancer l'entraînement complet.")