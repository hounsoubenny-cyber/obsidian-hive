#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon May 11 00:10:53 2026
@author: hounsousamuel
"""
import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import torch
import numpy as np
import torchvision as tvision
import torch.nn.functional as F
from PIL import Image
from transformers import CLIPModel, CLIPProcessor
from deepfake_detector.deepfake_utils.logger import get_logger

logger = get_logger()
BASEDIR = os.path.dirname(os.path.abspath(__file__))
CLIP_DIR = os.path.abspath(os.path.join(BASEDIR, "..", "..", "texts", "model", "models", "image"))

# Catégories zero-shot pour CLIP — signal sémantique fort
CLIP_CATEGORIES = [
    "a real photo taken by a camera",
    "an AI-generated image",
    "a GAN generated image",
    "a diffusion model image",
    "a deepfake image",
    "a painting or digital illustration"
]

class FeaturesExtractor:
    """
    Extrait des features statistiques d'une image pour détecter les artefacts IA.
    Équivalent de FeaturesExtractor pour les images.
    
    Features extraites :
        - model_pred        : proba zero-shot CLIP (N_cat features)
        - noise_level       : uniformité du bruit (images IA trop uniformes)
        - frequency_artifacts: artefacts en fréquence via FFT (typiques GANs)
        - color_distribution: statistiques des canaux RGB
        - edge_coherence    : cohérence des bords via gradient Sobel
        - compression_ratio : ratio compression PNG (entropie informationnelle)
    """
    def __init__(self, model_type:str = "fast"):
        self.model_type = model_type if model_type in ("fast", "full") else "fast"
        self.model_path = os.path.join(CLIP_DIR, self.model_type)

        # CLIPProcessor gère image ET texte ensemble — contrairement à AutoImageProcessor
        self.processor = CLIPProcessor.from_pretrained(self.model_path)
        self.model = CLIPModel.from_pretrained(self.model_path)
        self.model.eval()

        self._textes = CLIP_CATEGORIES
        self._compute_methodes = [
            method for method in sorted(dir(self))
            if method.startswith("compute_") and method != "compute_all"
        ]
        self._names = [m.replace("compute_", "") for m in self._compute_methodes]

        self.to_tensor = tvision.transforms.v2.Compose([
            tvision.transforms.v2.ToImage(),
            tvision.transforms.v2.ToDtype(torch.float32, scale=True),
        ])

    def _to_tensor(self, image: Image.Image | torch.Tensor) -> torch.Tensor:
        """Convertit PIL ou Tensor en tensor float32 [C, H, W]"""
        if isinstance(image, Image.Image):
            return self.to_tensor(image)
        return image.float()

    # ── Feature 1 : Prédictions zero-shot CLIP ──────────────────────────────
    def compute_model_pred(self, image: Image.Image | torch.Tensor, *args, **kwargs) -> torch.Tensor:
        """
        Prédictions zero-shot CLIP sur N_cat catégories.
        
        CLIP compare l'image à chaque description texte via produit matriciel
        dans l'espace embedding partagé image-texte.
        
        Retourne un vecteur [N_cat] de probabilités softmax.
        → "an AI-generated image" élevé → probablement IA
        → "a real photo" élevé → probablement humain
        
        C'est notre ml_features — signal sémantique le plus fort.
        """
        if isinstance(image, torch.Tensor):
            image = tvision.transforms.v2.ToPILImage()(image)

        with torch.inference_mode():
            inputs = self.processor(
                text=self._textes,
                images=image,
                return_tensors="pt",
                padding=True
            )
            outputs = self.model(**inputs)
            # logits_per_image : [1, N_cat] → softmax → [N_cat]
            probs = F.softmax(outputs.logits_per_image, dim=-1).squeeze(0)
        return probs  # [N_cat]

    # ── Feature 2 : Niveau de bruit ─────────────────────────────────────────
    def compute_noise_level(self, image: Image.Image | torch.Tensor, *args, **kwargs) -> float:
        """
        Mesure l'uniformité du bruit dans l'image.
        
        Principe :
            On calcule l'écart-type local des pixels via un filtre Laplacien.
            Le Laplacien amplifie les hautes fréquences (= bruit).
            
            Images IA → bruit très uniforme (généré par le modèle)
            Images réelles → bruit irrégulier (capteur photo, compression)
        
        Un bruit uniforme → std(noise_map) basse → score bas → IA
        Un bruit irrégulier → std(noise_map) haute → score haut → réel
        """
        t = self._to_tensor(image)  # [C, H, W]
        
        # Convertir en grayscale pour simplifier
        gray = t.mean(dim=0, keepdim=True)  # [1, H, W]
        
        # Filtre Laplacien — détecte les variations locales (bruit)
        # kernel 3x3 standard
        laplacian_kernel = torch.tensor([
            [0.,  1., 0.],
            [1., -4., 1.],
            [0.,  1., 0.]
        ]).view(1, 1, 3, 3)
        
        # Appliquer le filtre via convolution
        gray_batch = gray.unsqueeze(0)  # [1, 1, H, W]
        noise_map = F.conv2d(gray_batch, laplacian_kernel, padding=1).squeeze()
        
        # std du noise_map → mesure de l'irrégularité du bruit
        return noise_map.std().item()

    # ── Feature 3 : Artefacts en fréquence (FFT) ────────────────────────────
    def compute_frequency_artifacts(self, image: Image.Image | torch.Tensor, *args, **kwargs) -> float:
        """
        Détecte les artefacts en fréquence via FFT 2D.
        
        Principe :
            La FFT (Fast Fourier Transform) décompose l'image en fréquences.
            Les GANs et modèles de diffusion laissent des empreintes régulières
            dans le spectre de fréquences — invisibles à l'œil nu mais détectables.
            
            Images réelles → spectre décroissant naturellement
            Images IA → pics anormaux à certaines fréquences
        
        On mesure la concentration de l'énergie dans les hautes fréquences.
        Haute concentration → artefacts GAN → score haut → IA
        """
        t = self._to_tensor(image)
        gray = t.mean(dim=0)  # [H, W]
        
        # FFT 2D
        fft = torch.fft.fft2(gray)
        fft_shift = torch.fft.fftshift(fft)  # centre les basses fréquences
        magnitude = torch.abs(fft_shift)
        
        H, W = magnitude.shape
        cy, cx = H // 2, W // 2
        
        # Séparer hautes et basses fréquences
        # Rayon = 10% de la taille → zone basses fréquences
        radius = int(min(H, W) * 0.1)
        y, x = torch.meshgrid(torch.arange(H), torch.arange(W), indexing="ij")
        dist = ((y - cy) ** 2 + (x - cx) ** 2).float().sqrt()
        
        low_freq_energy  = magnitude[dist <= radius].sum().item()
        high_freq_energy = magnitude[dist >  radius].sum().item()
        total = low_freq_energy + high_freq_energy + 1e-8
        
        # Ratio hautes fréquences → plus haut = plus d'artefacts
        return high_freq_energy / total

    # ── Feature 4 : Distribution des couleurs ───────────────────────────────
    def compute_color_distribution(self, image: Image.Image | torch.Tensor, *args, **kwargs) -> float:
        """
        Mesure la "perfection" de la distribution des couleurs.
        
        Principe :
            Les images IA ont des distributions de couleurs trop régulières —
            le modèle génère des couleurs "moyennes" plutôt que les variations
            naturelles d'une vraie scène.
            
            On calcule le coefficient de variation (std/mean) de chaque canal RGB
            puis on fait la moyenne. 
            
            Valeur basse → distribution trop uniforme → IA
            Valeur haute → distribution naturelle → humain
        """
        t = self._to_tensor(image)  # [C, H, W]
        
        cv_list = []
        for c in range(t.shape[0]):  # R, G, B
            channel = t[c]
            mean = channel.mean()
            std  = channel.std()
            cv   = (std / (mean + 1e-8)).item()
            cv_list.append(cv)
        
        return float(np.mean(cv_list))

    # ── Feature 5 : Cohérence des bords ─────────────────────────────────────
    def compute_edge_coherence(self, image: Image.Image | torch.Tensor, *args, **kwargs) -> float:
        """
        Mesure la cohérence des bords via gradient Sobel.
        
        Principe :
            Le filtre Sobel détecte les bords (transitions de couleurs).
            Les images IA ont des bords trop nets ou trop flous selon le modèle.
            
            On mesure la kurtosis (aplatissement) de la distribution des gradients.
            Kurtosis élevée → distribution à longue queue → bords naturels → humain
            Kurtosis basse  → distribution gaussienne → bords artificiels → IA
            
            kurtosis = E[(X - μ)⁴] / σ⁴
        """
        t = self._to_tensor(image)
        gray = t.mean(dim=0, keepdim=True).unsqueeze(0)  # [1, 1, H, W]
        
        # Filtres Sobel horizontal et vertical
        sobel_x = torch.tensor([
            [-1., 0., 1.],
            [-2., 0., 2.],
            [-1., 0., 1.]
        ]).view(1, 1, 3, 3)
        
        sobel_y = torch.tensor([
            [-1., -2., -1.],
            [ 0.,  0.,  0.],
            [ 1.,  2.,  1.]
        ]).view(1, 1, 3, 3)
        
        grad_x = F.conv2d(gray, sobel_x, padding=1).squeeze()
        grad_y = F.conv2d(gray, sobel_y, padding=1).squeeze()
        
        # Magnitude du gradient
        gradient = (grad_x ** 2 + grad_y ** 2).sqrt().flatten()
        
        # Kurtosis de la distribution
        mean = gradient.mean()
        std  = gradient.std() + 1e-8
        kurtosis = ((gradient - mean) ** 4).mean() / (std ** 4)
        
        return kurtosis.item()

    # ── Feature 6 : Ratio de compression ────────────────────────────────────
    def compute_compression_ratio(self, image: Image.Image | torch.Tensor, *args, **kwargs) -> float:
        """
        Mesure l'entropie informationnelle via ratio de compression PNG.
        
        Principe identique au texte — indépendant du contenu sémantique.
        
        Images IA → pixels trop réguliers → très compressibles → ratio bas → IA
        Images réelles → bruit naturel → peu compressibles → ratio haut → humain
        
        ratio = taille_compressée / taille_originale
        """
        import io
        
        if isinstance(image, torch.Tensor):
            image = tvision.transforms.v2.ToPILImage()(image)
        
        # Sauvegarder en PNG sans compression (compression=0)
        buf_raw = io.BytesIO()
        image.save(buf_raw, format="PNG", compress_level=0)
        raw_size = buf_raw.tell()
        
        # Sauvegarder avec compression maximale
        buf_compressed = io.BytesIO()
        image.save(buf_compressed, format="PNG", compress_level=9)
        compressed_size = buf_compressed.tell()
        
        return compressed_size / max(raw_size, 1)

    # ── compute_all ─────────────────────────────────────────────────────────
    def compute_all(self, image: Image.Image | torch.Tensor, *args, **kwargs):
        """
        Calcule toutes les features et les retourne sous forme de dict + tensor.
        
        model_pred retourne [N_cat] → on la flatten dans le tensor final.
        Les autres features retournent un scalaire.
        
        Retourne : (dict, tensor [N_features])
        """
        features = {}
        tensors  = []

        for method in self._compute_methodes:
            name   = method.replace("compute_", "")
            result = getattr(self, method)(image)

            if isinstance(result, torch.Tensor):
                features[name] = result.tolist()
                tensors.append(result)
            else:
                features[name] = result
                tensors.append(torch.tensor([result], dtype=torch.float32))

        # Concatener tout en un seul vecteur
        feature_tensor = torch.cat(tensors, dim=0).float()
        return features, feature_tensor

    def __call__(self, image: Image.Image | torch.Tensor, *args, **kwargs):
        return self.compute_all(image)


if __name__ == "__main__":
    import requests
    from PIL import Image
    import io

    FE = FeaturesExtractor(model_type="fast")

    # Image de test — image grise factice (comme dans explore_model.py)
    img_fake = Image.new('RGB', (224, 224), color=(128, 128, 128))

    print("=== Image grise factice (IA-like) ===")
    features, values = FE(img_fake)
    for k, v in features.items():
        if isinstance(v, list):
            print(f"  {k:30s} : {[f'{x:.3f}' for x in v]}")
        else:
            print(f"  {k:30s} : {v:.4f}")

    print(f"\n  Tensor shape : {values.shape}")
    print(f"  N features   : {len(values)}")
    print(f"  Valeurs      : {values}")