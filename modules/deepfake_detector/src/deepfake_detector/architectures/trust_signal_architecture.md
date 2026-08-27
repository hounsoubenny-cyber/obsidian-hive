# TrustSignal — Architecture Complète
> Document de référence — Mai 2026

---

## 1. Architecture TEXT

### 1.1 TextEncoder (Couche 1 — Contrastive)

```
Texte
  ↓
Tokenizer (distilbert / distilroberta / xlm-roberta)
  ↓
BERT/RoBERTa Backbone
  └── Premières couches → gelées
  └── Dernières 3 couches → fine-tunées
  ↓
last_hidden_state [B, T, hidden_size]
  ↓
Linear(hidden_size → d_model) + GELU + Dropout + LayerNorm  ← head
  ↓
L2 Normalize (dim=-1)
  ↓
Si self.training → mean pooling [B, d_model]  → Contrastive Loss
Sinon           → séquence complète [B, T, d_model] → DeepFakeDetector
```

**Modes disponibles :**
| Mode | Modèle | Langues | Taille |
|------|--------|---------|--------|
| very_fast | distilbert-base-multilingual-cased | 104 | ~542 MB |
| fast | distilroberta-base | anglais | ~331 MB |
| full | xlm-roberta-base | 100 | ~1.1 GB |

**Entraînement :**
- Loss : `SupervisedContrastiveLoss(temperature=0.07)`
- Métriques : Silhouette, Davies-Bouldin, cosine intra/inter
- Objectif : séparer embeddings humains vs IA dans l'espace vectoriel

---

### 1.2 DeepFakeDetectorText (Couche 2 — Classification)

```
Texte
  ├──→ TextEncoder fine-tuné (frozen en phase 2)
  │       ↓
  │    last_hidden_state [:, :N_layers, :]  [B, N, d_model]
  │
  └──→ Feature Engineering
          ↓
       [perplexité, burstiness, TTR, hapax,
        n-gram entropy, compression ratio,
        discourse markers, hedge words]  [B, N_features]
          ↓
       Linear(N_features → d_model)  ← feature_head
          ↓
       unsqueeze(1) → [B, 1, d_model]

  ┌──→ XGBoost (pré-entraîné sur embeddings + features)
  │       ↓
  │    pred_proba + pred_label  [B, N_ml]
  │       ↓
  │    Linear(N_ml → d_model)  ← ml_proba_head
  │       ↓
  │    unsqueeze(1) → [B, 1, d_model]

  Concat sur dim=1 :
  [B, N, d_model]    ← text embedding
  [B, 1, d_model]    ← features projetées
  [B, 1, d_model]    ← ml_features projetées
  ─────────────────
  [B, N+2, d_model]
        ↓
  LayerNorm
        ↓
  Custom Transformer (Pre-LN, N layers, N heads)
        ↓
  MultiPooling :
    cls  = x[:, 0, :]
    mean = x[:, 1:, :].mean(dim=1)
    max  = x[:, 1:, :].max(dim=1).values
    min  = x[:, 1:, :].min(dim=1).values
    std  = x[:, 1:, :].std(dim=1)
    concat → [B, 5*d_model]
    LayerNorm(5*d_model)
        ↓
  Linear(5*d_model → d_model) + LayerNorm + GELU + Dropout
        ↓
  Head : Linear(d_model → d_model*4) + GELU + Dropout
         Linear(d_model*4 → n_classes)
        ↓
  Logits → CrossEntropyLoss
```

**Flow d'entraînement complet :**
```
Phase 1 → Entraîner TextEncoder avec contrastive loss
Phase 2 → Extraire embeddings + features → fit XGBoost
Phase 3 → Entraîner DeepFakeDetectorText (TextEncoder frozen)
```

**Perplexité :**
- Anglais → DistilGPT2 (`torch.exp(model(ids, labels=ids).loss)`)
- Autres langues → Pseudo-PLL via XLM-RoBERTa (masquage token par token)

---

## 2. Architecture IMAGE

### 2.1 ImageEncoder (Couche 1 — Contrastive)

```
Image (PIL)
  ↓
CLIPProcessor → pixel_values [B, 3, 224, 224]
  ↓
CLIP Vision Encoder (fine-tuné)
  └── Premières couches → gelées
  └── Dernières 2-3 couches → fine-tunées
  ↓
last_hidden_state [B, 197, d_model]
  └── 197 = 196 patches (14×14) + 1 CLS
  ↓
Linear(d_model → d_out) + GELU + Dropout + LayerNorm  ← head
  ↓
L2 Normalize (dim=-1)
  ↓
Si self.training → mean pooling [B, d_out]  → Contrastive Loss
Sinon           → séquence complète [B, 197, d_out] → DeepFakeDetector
```

**Modes disponibles :**
| Mode | Modèle | Dim | Taille |
|------|--------|-----|--------|
| very_fast | google/vit-base-patch16-224 | 768 | ~346 MB |
| fast | openai/clip-vit-base-patch32 | 512 | ~600 MB |
| full | openai/clip-vit-large-patch14 | 768 | ~1.7 GB |

> **Note :** On fine-tune uniquement le **vision encoder** de CLIP.
> Le text encoder n'est pas touché.

---

### 2.2 DeepFakeDetectorImage (Couche 2 — Classification)

```
Image
  ├──→ ImageEncoder fine-tuné (frozen en phase 2)
  │       ↓
  │    last_hidden_state [B, 197, d_model]  ← patches 3D
  │
  └──→ CLIP frozen (copie séparée, jamais fine-tunée)
          ↓
       logits_per_image bruts [B, N_cat]
          ↓
       F.softmax(dim=-1) → [B, N_cat]
          ↓
       Linear(N_cat → d_model)  ← logits_head
          ↓
       unsqueeze(1) → [B, 1, d_model]

  Concat sur dim=1 :
  [B, 197, d_model]  ← patches vision encoder
  [B, 1,   d_model]  ← logits CLIP frozen projetés
  ─────────────────
  [B, 198, d_model]
        ↓
  LayerNorm
        ↓
  Custom Transformer (Pre-LN, N layers, N heads)
        ↓
  MultiPooling :
    cls  = x[:, 0, :]
    mean = x[:, 1:, :].mean(dim=1)
    max  = x[:, 1:, :].max(dim=1).values
    min  = x[:, 1:, :].min(dim=1).values
    std  = x[:, 1:, :].std(dim=1)
    concat → [B, 5*d_model]
    LayerNorm(5*d_model)
        ↓
  Linear(5*d_model → d_model) + LayerNorm + GELU + Dropout
        ↓
  Head : Linear(d_model → d_model*4) + GELU + Dropout
         Linear(d_model*4 → n_classes)
        ↓
  Logits → CrossEntropyLoss
```

**Catégories CLIP frozen (N_cat) :**
```python
categories = [
    "a real photo",
    "an AI-generated image",
    "a GAN generated image",
    "a diffusion model image",
    "a deepfake",
    "a painting or illustration"
]
# N_cat = 6
```

**Flow d'entraînement complet :**
```
Phase 1 → Entraîner ImageEncoder (vision encoder CLIP) avec contrastive loss
Phase 2 → Entraîner DeepFakeDetectorImage (ImageEncoder frozen)
          CLIP frozen produit logits_per_image en parallèle
```

---

## 3. Custom Transformer (partagé TEXT et IMAGE)

```python
class TransformerLayer(nn.Module):
    # Pre-LN (LayerNorm avant attention)
    def forward(self, x):
        x_norm = self.layer_norm1(x)
        attn, _ = self.attention(x_norm, x_norm, x_norm)
        x = x + self.dropout(attn)
        x = x + self.dropout(self.feed_forward(self.layer_norm2(x)))
        return x

# Feed-Forward interne : Linear → GELU → Dropout → Linear
# FFN hidden dim = d_model * feed_forward_factor (défaut 4)
```

---

## 4. MultiPooling (partagé TEXT et IMAGE)

```python
cls  = x[:, 0, :]              # CLS token
mean = x[:, 1:, :].mean(dim=1) # moyenne tokens de contenu
max  = x[:, 1:, :].max(dim=1).values
min  = x[:, 1:, :].min(dim=1).values
std  = x[:, 1:, :].std(dim=1)

pooled = torch.cat([cls, mean, max, min, std], dim=-1)  # [B, 5*d_model]
pooled = LayerNorm(5*d_model)(pooled)
pooled = Linear(5*d_model → d_model) + LayerNorm + GELU + Dropout
```

---

## 5. Règles d'architecture (à garder en tête)

```
Normalisation → LayerNorm toujours en NLP/Transformer
Activation    → GELU partout sauf dernière couche du head
Dernière couche → pas d'activation (CrossEntropyLoss gère)
Pooling       → toujours x[:, 1:, :] pour mean/max/min/std
                (exclure CLS qui est déjà dans cls séparément)
L2 Normalize  → obligatoire sur les embeddings contrastifs
Softmax       → sur logits CLIP avant projection Linear
```

---

## 6. Modèles téléchargés

```
models/
  text/
    distilbert-multilingual/   (very_fast)
    distilroberta-base/        (fast)
    xlm-roberta-base/          (full)
  image/
    vit-base-patch16/          (very_fast — ViT classique)
    clip-vit-base/             (fast — CLIP-B/32)
    clip-vit-large/            (full — CLIP-L/14)
  perplexity/
    distilgpt2/                (anglais)
    + pseudo-PLL via xlm-roberta pour autres langues
```

---

*TrustSignal — Architecture v1.0 — Mai 2026*
*Co-designed by Sam Hounsou & Claude*
