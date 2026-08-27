#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrustSignal — Pipeline Image Complet
Train  : DeepFakeDetectorImageTrain
Predict: DeepFakeDetectorImagePredict

Auteurs : Sam Hounsou + Claude
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import torch
import numpy as np
from PIL import Image
from sklearn.preprocessing import RobustScaler
from torch.utils.data import DataLoader
import torchvision as tvision
import joblib

from deepfake_detector.deepfake_utils.logger import get_logger
from deepfake_detector.images.model.image_encoder import ImageEncoder, ImageEncoderDataset
from deepfake_detector.images.model.image_encoder_trainer import Trainer as ImageEncoderTrainer
from deepfake_detector.images.model.model import (
    DeepFakeDetectorImage,
    DeepFakeDetectorImageDataset,
    DeepFakeDetectorImageProcessor,
)
from deepfake_detector.images.model.deepfake_image_trainer import Trainer as DeepFakeImageTrainer
from deepfake_detector.images.features.features_extractor import FeaturesExtractor
from deepfake_detector.texts.model.constrative_loss import SupervisedConstrativeLoss
from deepfake_detector.texts.model.callbacks import EarlyStopping
from deepfake_detector.models_config import IMAGE_MODEL_PATHS
logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ════════════════════════════════════════════════════════════════════════════
# PARAMÈTRES
# ════════════════════════════════════════════════════════════════════════════

# ── Chemins ──────────────────────────────────────────────────────────────────
BASEDIR       = os.path.dirname(os.path.abspath(__file__))
IS_CLIP = {
    "very_fast": False,   # ViT classique
    "fast"     : True,    # CLIP
    "full"     : True,    # CLIP
}

# ── ImageEncoder ─────────────────────────────────────────────────────────────
ENCODER_D_MODEL          = 256
ENCODER_NUM_FREEZE       = 0.5
ENCODER_DROPOUT          = 0.2
ENCODER_CLS_ONLY         = False

# ── Processor / Augmentation ─────────────────────────────────────────────────
PROCESSOR_RESIZE         = 224

# ── Contrastive Training ─────────────────────────────────────────────────────
CONTRASTIVE_LR           = 2e-5
CONTRASTIVE_EPOCHS       = 10
CONTRASTIVE_BATCH_SIZE   = 16    # plus petit que texte — images plus lourdes
CONTRASTIVE_PATIENCE     = 5
CONTRASTIVE_TEMPERATURE  = 0.07

# ── DeepFakeDetectorImage ─────────────────────────────────────────────────────
MODEL_D_MODEL            = 256
MODEL_NUM_HEADS          = 8
MODEL_NUM_LAYERS         = 4
MODEL_FFN_FACTOR         = 4
MODEL_DROPOUT            = 0.2
MODEL_N_CLASSES          = 2
MODEL_CLS_ONLY           = False
MODEL_N_PATCHES          = 64    # nombre de patches à garder (sur 197)

# ── DeepFake Training ────────────────────────────────────────────────────────
DEEPFAKE_LR              = 1e-4
DEEPFAKE_EPOCHS          = 20
DEEPFAKE_BATCH_SIZE      = 16
DEEPFAKE_PATIENCE        = 5
DEEPFAKE_TASK            = "multiclass"

# ── Classes du dataset ───────────────────────────────────────────────────────
# Structure attendue sur disque :
#   root/
#     real/   image1.jpg ...
#     ai/     image2.jpg ...
DEFAULT_CLASSES_MATCH = {
    "real": 0,
    "ai"  : 1,
}

# ════════════════════════════════════════════════════════════════════════════
# CLASSE TRAIN
# ════════════════════════════════════════════════════════════════════════════

class DeepFakeDetectorImageTrain:
    """
    Pipeline d'entraînement complet pour TrustSignal Image.

    Flow :
        Phase 1 → fit_encoder() : contrastive training de l'ImageEncoder
        Phase 2 → fit_model()   : fit DeepFakeDetectorImage

    Structure du dataset sur disque :
        train_root/
            real/   ← images réelles
            ai/     ← images générées par IA
        val_root/   ← même structure (optionnel)

    Save :
        save() → dossier contenant :
            encoder.zstd
            model.zstd
            scaler_features.pkl
            processor_params.pkl
    """

    def __init__(
        self,
        model_type    : str  = "fast",
        classes_match : dict = None,
        save_dir      : str  = None,
    ):
        assert model_type in IMAGE_MODEL_PATHS, f"model_type invalide : {model_type}"
        self.model_type    = model_type
        self.is_clip       = IS_CLIP[model_type]
        self.model_path    = IMAGE_MODEL_PATHS[model_type]
        self.classes_match = classes_match or DEFAULT_CLASSES_MATCH
        self.save_dir      = save_dir or os.path.join(BASEDIR, "checkpoints", "image", model_type)
        os.makedirs(self.save_dir, exist_ok=True)

        # Composants
        self.encoder      = None
        self.model        = None
        self.features     = FeaturesExtractor(model_type=model_type if model_type != "very_fast" else "fast")
        self.scaler_feat  = RobustScaler()

        # Processor HuggingFace — gère le preprocessing image
        self._build_processor()

        logger.print(f"🚀 TrustSignal Image Train — mode : {model_type}")
        logger.print(f"   CLIP : {self.is_clip}")
        logger.print(f"   Save dir : {self.save_dir}")

    def _build_processor(self):
        """Construit le DeepFakeDetectorImageProcessor selon le mode."""
        if self.is_clip:
            from transformers import CLIPProcessor
            hf_processor = CLIPProcessor.from_pretrained(self.model_path)
        else:
            from transformers import AutoImageProcessor
            hf_processor = AutoImageProcessor.from_pretrained(self.model_path, use_fast=True)

        self.transform = DeepFakeDetectorImageProcessor(
            resize    = PROCESSOR_RESIZE,
            is_vit    = not self.is_clip,
            processor = hf_processor,
        )

    # ── Phase 1 : ImageEncoder contrastif ───────────────────────────────────
    def fit_encoder(
        self,
        train_root    : str,
        val_root      : str  = None,
        compile_model : bool = False,
    ):
        """
        Phase 1 — Entraîne l'ImageEncoder avec contrastive loss.

        train_root : chemin vers le dossier d'entraînement
                     structure : train_root/real/ et train_root/ai/
        val_root   : optionnel, même structure
        """
        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 1 : Entraînement ImageEncoder (Contrastive)")
        logger.print("═" * 60)

        # ── Encoder ──────────────────────────────────────────────────────────
        self.encoder = ImageEncoder(
            image_model_path_or_image_model = self.model_path,
            d_model                         = ENCODER_D_MODEL,
            model_type                      = self.model_type,
            num_layer_to_freeze             = ENCODER_NUM_FREEZE,
            dropout                         = ENCODER_DROPOUT,
            cls_only                        = ENCODER_CLS_ONLY,
        )
        logger.print(f"   Paramètres encoder : {self.encoder.num_params:,}")

        # ── Datasets ─────────────────────────────────────────────────────────
        train_dataset = ImageEncoderDataset(
            root_path      = train_root,
            features_extractor = self.features,
            classes_match  = self.classes_match,
            transform      = self.transform,
        )
        # IMPORTANT : train() puis build() pour le mode entraînement
        train_dataset.train()
        train_dataset.build()

        train_loader = DataLoader(
            train_dataset,
            batch_size  = CONTRASTIVE_BATCH_SIZE,
            shuffle     = True,
            num_workers = 0,
        )

        val_loader = None
        if val_root:
            val_dataset = ImageEncoderDataset(
                root_path          = val_root,
                features_extractor = self.features,
                classes_match      = self.classes_match,
                transform          = self.transform,
            )
            # IMPORTANT : eval() puis build() pour le mode validation
            val_dataset.eval()
            val_dataset.build()

            val_loader = DataLoader(
                val_dataset,
                batch_size  = CONTRASTIVE_BATCH_SIZE,
                shuffle     = False,
                num_workers = 0,
            )

        # ── Loss + Optimizer + Scheduler ─────────────────────────────────────
        loss      = SupervisedConstrativeLoss(temperature=CONTRASTIVE_TEMPERATURE)
        optimizer = torch.optim.AdamW(
            filter(lambda p: p.requires_grad, self.encoder.parameters()),
            lr=CONTRASTIVE_LR
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=CONTRASTIVE_EPOCHS
        )
        early_stopping = EarlyStopping(patience=CONTRASTIVE_PATIENCE, mode="min")

        # ── Trainer ──────────────────────────────────────────────────────────
        trainer = ImageEncoderTrainer(
            model         = self.encoder,
            loss          = loss,
            optimizer     = optimizer,
            scheduler     = scheduler,
            each_epochs   = True,
            compile_model = compile_model,
            compile_loss  = False,
        )

        history = trainer.fit(
            dataloader     = train_loader,
            valloader      = val_loader,
            epochs         = CONTRASTIVE_EPOCHS,
            early_stopping = early_stopping,
            plot_history   = False,
        )

        logger.print("✅ Phase 1 terminée")
        return history

    # ── Phase 2 : DeepFakeDetectorImage ─────────────────────────────────────
    def fit_model(
        self,
        train_root    : str,
        val_root      : str  = None,
        compile_model : bool = False,
    ):
        """
        Phase 2 — Entraîne DeepFakeDetectorImage.

        L'ImageEncoder doit être entraîné avant (fit_encoder).

        Flow :
            Input image → encoder (frozen) → patches 3D
                        → features → scaler
                        → FeaturesExtractor.compute_model_pred() → logits CLIP
                        → DeepFakeDetectorImage → CrossEntropyLoss
        """
        if self.encoder is None:
            raise RuntimeError("fit_encoder() doit être appelé avant fit_model() !")

        logger.print("\n" + "═" * 60)
        logger.print("  PHASE 2 : Entraînement DeepFakeDetectorImage")
        logger.print("═" * 60)

        # Calculer n_features dynamiquement depuis un sample
        dummy = Image.new("RGB", (224, 224), color=(128, 128, 128))
        _, sample_feat = self.features(dummy)
        n_features = len(sample_feat)
        logger.print(f"   N features : {n_features}")

        # Fit scaler_feat sur le train set
        logger.print("   Fit scaler features...")
        self._fit_scaler(train_root)

        # ── Modèle ───────────────────────────────────────────────────────────
        self.model = DeepFakeDetectorImage(
            d_model             = MODEL_D_MODEL,
            num_heads           = MODEL_NUM_HEADS,
            num_features        = n_features,
            feed_forward_factor = MODEL_FFN_FACTOR,
            dropout             = MODEL_DROPOUT,
            num_layer           = MODEL_NUM_LAYERS,
            num_classe          = MODEL_N_CLASSES,
            cls_only            = MODEL_CLS_ONLY,
            n_layers            = MODEL_N_PATCHES,
        )
        logger.print(f"   Paramètres modèle : {self.model.num_params:,}")

        # ── Datasets ─────────────────────────────────────────────────────────
        train_dataset = DeepFakeDetectorImageDataset(
            root_path          = train_root,
            features_extractor = lambda img: self._extract_features_scaled(img),
            classes_match      = self.classes_match,
            transform          = self.transform,
        )
        train_dataset.train()
        train_dataset.build()

        train_loader = DataLoader(
            train_dataset,
            batch_size  = DEEPFAKE_BATCH_SIZE,
            shuffle     = True,
            num_workers = 0,
        )

        val_loader = None
        if val_root:
            val_dataset = DeepFakeDetectorImageDataset(
                root_path          = val_root,
                features_extractor = lambda img: self._extract_features_scaled(img),
                classes_match      = self.classes_match,
                transform          = self.transform,
            )
            val_dataset.eval()
            val_dataset.build()

            val_loader = DataLoader(
                val_dataset,
                batch_size  = DEEPFAKE_BATCH_SIZE,
                shuffle     = False,
                num_workers = 0,
            )

        # ── Encoder frozen ────────────────────────────────────────────────────
        is_trainable = {
            i: p.requires_grad
            for i, p in enumerate(self.encoder.parameters())
        }
        for param in self.encoder.parameters():
            param.requires_grad = False

        # ── Loss + Optimizer + Scheduler ─────────────────────────────────────
        loss      = torch.nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=DEEPFAKE_LR)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=DEEPFAKE_EPOCHS
        )
        early_stopping = EarlyStopping(patience=DEEPFAKE_PATIENCE, mode="min")

        # ── Trainer ──────────────────────────────────────────────────────────
        trainer = DeepFakeImageTrainer(
            model         = self.model,
            loss          = loss,
            optimizer     = optimizer,
            scheduler     = scheduler,
            image_encoder = self.encoder,
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
            plot_history   = False,
        )

        logger.print("✅ Phase 2 terminée")
        return history

    def _fit_scaler(self, root_path:str):
        """Fit le scaler_feat sur toutes les images du dataset."""
        from deepfake_detector.images.model.model import DeepFakeDetectorImageDataset
        all_features = []
        for classe in os.listdir(root_path):
            classe_path = os.path.join(root_path, classe)
            if not os.path.isdir(classe_path):
                continue
            for fname in os.listdir(classe_path):
                ext = os.path.splitext(fname)[-1].lower()
                if ext in DeepFakeDetectorImageDataset.EXT:
                    try:
                        img = Image.open(os.path.join(classe_path, fname)).convert("RGB")
                        _, feat = self.features(img)
                        all_features.append(feat.numpy())
                    except Exception:
                        continue

        if all_features:
            self.scaler_feat.fit(np.array(all_features))
            logger.print(f"   Scaler fit sur {len(all_features)} images ✅")

    def _extract_features_scaled(self, image) -> np.ndarray:
        """Extrait et scale les features d'une image."""
        _, feat = self.features(image)
        return self.scaler_feat.transform(feat.numpy().reshape(1, -1)).astype(np.float32).squeeze()

    # ── fit_all ──────────────────────────────────────────────────────────────
    def fit_all(
        self,
        train_root    : str,
        val_root      : str  = None,
        compile_model : bool = False,
    ):
        """Lance les 2 phases d'entraînement d'un seul coup."""
        self.fit_encoder(train_root, val_root, compile_model)
        self.fit_model(train_root, val_root, compile_model)
        logger.print("\n🎉 Pipeline image complet terminé !")

    # ── Save ─────────────────────────────────────────────────────────────────
    def save(self, directory:str = None):
        """
        Sauvegarde tous les composants dans un dossier :
            encoder.zstd
            model.zstd
            scaler_features.pkl
            processor_params.pkl  ← infos pour reconstruire le processor
        """
        directory = directory or self.save_dir
        os.makedirs(directory, exist_ok=True)

        logger.print(f"\n💾 Sauvegarde dans {directory}...")

        if self.encoder:
            self.encoder.save(os.path.join(directory, "encoder.zstd"))

        if self.model:
            self.model.save(os.path.join(directory, "model.zstd"))

        joblib.dump(self.scaler_feat, os.path.join(directory, "scaler_features.pkl"))

        # Sauvegarder les infos nécessaires pour reconstruire le processor
        processor_params = {
            "model_type"    : self.model_type,
            "is_clip"       : self.is_clip,
            "resize"        : PROCESSOR_RESIZE,
            "classes_match" : self.classes_match,
        }
        joblib.dump(processor_params, os.path.join(directory, "processor_params.pkl"))

        logger.print("✅ Tous les composants sauvegardés !")


# ════════════════════════════════════════════════════════════════════════════
# CLASSE PREDICT
# ════════════════════════════════════════════════════════════════════════════

class DeepFakeDetectorImagePredict:
    """
    Pipeline d'inférence pour TrustSignal Image.

    Accepte en entrée :
        - str  → chemin vers une image sur disque
        - PIL.Image.Image → image PIL
        - torch.Tensor    → tensor [C, H, W] ou [B, C, H, W]

    Usage :
        predictor = DeepFakeDetectorImagePredict.from_directory("checkpoints/image/fast")
        result = predictor.predict("path/to/image.jpg")
        result = predictor.predict(pil_image)
        result = predictor.predict(tensor)
    """

    def __init__(
        self,
        model_type  : str,
        encoder     : ImageEncoder,
        model       : DeepFakeDetectorImage,
        scaler_feat,
        transform   : DeepFakeDetectorImageProcessor,
        classes_match: dict,
        features    : FeaturesExtractor,
    ):
        self.model_type   = model_type
        self.encoder      = encoder
        self.model        = model
        self.scaler_feat  = scaler_feat
        self.transform    = transform
        self.classes_match= classes_match
        self.features     = features
        self.idx_to_class = {v: k for k, v in classes_match.items()}
        
        # self.encoder.to(torch.bfloat16)
        # self.model.to(torch.bfloat16)
        self.encoder.eval()
        self.model.eval()

        logger.print(f"✅ TrustSignal Image Predict prêt — mode : {model_type}")

    @classmethod
    def from_directory(cls, directory:str):
        """
        Charge tous les composants depuis un dossier.
        Pattern inverse de DeepFakeDetectorImageTrain.save()
        """
        logger.print(f"📂 Chargement depuis {directory}...")

        # ── Processor params ─────────────────────────────────────────────────
        proc_params   = joblib.load(os.path.join(directory, "processor_params.pkl"))
        model_type    = proc_params["model_type"]
        is_clip       = proc_params["is_clip"]
        resize        = proc_params["resize"]
        classes_match = proc_params["classes_match"]
        model_path    = IMAGE_MODEL_PATHS[model_type]

        # ── Processor HuggingFace ─────────────────────────────────────────────
        if is_clip:
            from transformers import CLIPProcessor
            hf_processor = CLIPProcessor.from_pretrained(model_path)
        else:
            from transformers import AutoImageProcessor
            hf_processor = AutoImageProcessor.from_pretrained(model_path, use_fast=True)

        transform = DeepFakeDetectorImageProcessor(
            resize    = resize,
            is_vit    = not is_clip,
            processor = hf_processor,
        )

        # ── Encoder ──────────────────────────────────────────────────────────
        encoder = ImageEncoder(
            image_model_path_or_image_model = model_path,
            d_model                         = ENCODER_D_MODEL,
            model_type                      = model_type,
            num_layer_to_freeze             = ENCODER_NUM_FREEZE,
            dropout                         = ENCODER_DROPOUT,
            cls_only                        = ENCODER_CLS_ONLY,
        )
        encoder.load(os.path.join(directory, "encoder.zstd"))

        # ── Model ─────────────────────────────────────────────────────────────
        model = DeepFakeDetectorImage(
            d_model             = MODEL_D_MODEL,
            num_heads           = MODEL_NUM_HEADS,
            num_features        = 1,          # écrasé par load()
            feed_forward_factor = MODEL_FFN_FACTOR,
            dropout             = MODEL_DROPOUT,
            num_layer           = MODEL_NUM_LAYERS,
            num_classe          = MODEL_N_CLASSES,
            cls_only            = MODEL_CLS_ONLY,
            n_layers            = MODEL_N_PATCHES,
        )
        model.load(os.path.join(directory, "model.zstd"))

        # ── Scaler + Features ─────────────────────────────────────────────────
        scaler_feat = joblib.load(os.path.join(directory, "scaler_features.pkl"))
        features    = FeaturesExtractor(
            model_type=model_type if model_type != "very_fast" else "fast"
        )

        logger.print("✅ Tous les composants chargés !")

        return cls(
            model_type    = model_type,
            encoder       = encoder,
            model         = model,
            scaler_feat   = scaler_feat,
            transform     = transform,
            classes_match = classes_match,
            features      = features,
        )

    def _to_pil(self, image) -> Image.Image:
        """
        Convertit n'importe quel format en PIL Image.

        Accepte :
            str            → chemin disque → PIL.open()
            PIL.Image      → passthrough
            torch.Tensor   → [C,H,W] ou [B,C,H,W] → ToPILImage()
        """
        if isinstance(image, str):
            if not os.path.exists(image):
                raise FileNotFoundError(f"Image introuvable : {image}")
            return Image.open(image).convert("RGB")

        if isinstance(image, Image.Image):
            return image.convert("RGB")

        if isinstance(image, torch.Tensor):
            # [B, C, H, W] → prendre le premier élément
            if image.ndim == 4:
                image = image[0]
            # [C, H, W] → PIL
            return tvision.transforms.v2.ToPILImage()(image.cpu())

        raise TypeError(f"Type non supporté : {type(image)}. Accepté : str, PIL, Tensor")

    def _prepare_input(self, pil_image:Image.Image):
        """
        Prépare toutes les entrées pour une image PIL.
        Retourne (embedding_3d [1, T, d], features_tensor [1, n_feat])
        """
        # ── Processor → pixel_values ──────────────────────────────────────────
        self.transform.eval()
        processor_output = self.transform(pil_image)
        processor_output = {
            k: v.to(DEVICE) if isinstance(v, torch.Tensor) else v
            for k, v in processor_output.items()
        }

        # ── Embedding 3D via encoder ──────────────────────────────────────────
        with torch.inference_mode():
            emb_3d = self.encoder(processor_output, output2d=False)  # [1, T, d_model]

        # ── Features handcraftées + scale ─────────────────────────────────────
        _, feat = self.features(pil_image)
        feat_scaled = self.scaler_feat.transform(feat.numpy().reshape(1, -1))
        feat_tensor = torch.tensor(feat_scaled, dtype=torch.float32).to(DEVICE)

        return emb_3d, feat_tensor

    def predict_proba(self, image, threshold:float = 0.5) -> dict:
        """Rerourne une liste des probabilités, utile si on veut juste les proba."""
        pil_image = self._to_pil(image)
        emb_3d, feat = self._prepare_input(pil_image)

        with torch.inference_mode():
            logits = self.model(emb_3d, feat)
            proba, pred = self.model.predict(emb_3d, feat, logits, threshold)
            return proba
    
    def predict(self, image, threshold:float = 0.5) -> dict:
        """
        Prédit si une image est réelle ou générée par IA.

        image : str (chemin), PIL.Image, ou torch.Tensor

        Retourne :
        {
            "label"      : "AI" ou "Real" (selon classes_match),
            "confidence" : float,
            "proba"      : [p_real, p_ai],
            "score"      : int 0-100 (score IA),
        }
        """
        pil_image = self._to_pil(image)
        emb_3d, feat = self._prepare_input(pil_image)

        with torch.inference_mode():
            logits = self.model(emb_3d, feat)
            proba, pred = self.model.predict(emb_3d, feat, logits, threshold)

        proba_list = proba.cpu().squeeze().tolist()
        pred_int   = pred.cpu().item()
        label      = self.idx_to_class.get(pred_int, str(pred_int))
        score_ia   = int(proba_list[1] * 100) if len(proba_list) > 1 else int(proba_list[0] * 100)

        return {
            "label"      : label,
            "confidence" : max(proba_list),
            "proba"      : proba_list,
            "score"      : score_ia,
        }

    def predict_batch(self, images:list, threshold:float = 0.5) -> list[dict]:
        """
        Prédit pour une liste d'images.
        Chaque élément peut être str, PIL ou Tensor.
        """
        return [self.predict(img, threshold) for img in images]

    def __call__(self, image, threshold:float = 0.5) -> dict:
        return self.predict(image, threshold) if not isinstance(image, list) else self.predict_batch(image, threshold)


# ════════════════════════════════════════════════════════════════════════════
# MAIN — test rapide
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.print("=== Test Pipeline TrustSignal Image ===\n")

    # ── Test _to_pil ──────────────────────────────────────────────────────────
    logger.print("Test conversion _to_pil...")

    # PIL → PIL
    pil_img = Image.new("RGB", (224, 224), color=(100, 150, 200))

    # Tensor → PIL
    tensor_img = torch.randint(0, 255, (3, 224, 224), dtype=torch.uint8)

    # Instanciation predict pour tester _to_pil
    # (sans charger les vrais modèles)
    class _MockPredict(DeepFakeDetectorImagePredict):
        def __init__(self):
            self.idx_to_class = {0: "real", 1: "ai"}

    mock = _MockPredict()
    pil_from_pil    = mock._to_pil(pil_img)
    pil_from_tensor = mock._to_pil(tensor_img)

    logger.print(f"PIL    → PIL : {pil_from_pil.size} ✅")
    logger.print(f"Tensor → PIL : {pil_from_tensor.size} ✅")

    # ── Train init ───────────────────────────────────────────────────────────
    trainer = DeepFakeDetectorImageTrain(
        model_type = "fast",
        save_dir   = "/tmp/trustsignal_image_test",
    )
    logger.print("\nPipeline image initialisé ✅")
    logger.print("Structure dataset attendue :")
    logger.print("  train_root/")
    logger.print("    real/   ← images réelles")
    logger.print("    ai/     ← images générées par IA")
    logger.print("\nAppeler trainer.fit_all(train_root, val_root) pour lancer.")