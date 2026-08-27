#!/usr/bin/env python3
"""
TrustSignal - Exploration complète de tous les modèles (CORRIGÉ)
- Normalise les embeddings pour la similarité cosinus
- Utilise get_image_features / get_text_features pour CLIP
- Ajoute une démo zero-shot pour CLIP
"""

import torch
import torch.nn.functional as F
import os
from transformers import (
    AutoModel, AutoTokenizer, AutoImageProcessor, AutoModelForCausalLM,
    CLIPModel, CLIPProcessor, CLIPTokenizer
)
from PIL import Image
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = '/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/MODEL_SHARED'
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print(f"📍 Device : {DEVICE}")
print("=" * 80)

# ========== FONCTIONS ==========

def explore_text_model(name, path):
    """Charge et teste un modèle de texte"""
    print(f"\n{'='*60}")
    print(f"📝 {name}")
    print(f"{'='*60}")
    
    model = AutoModel.from_pretrained(path).to(DEVICE)
    tokenizer = AutoTokenizer.from_pretrained(path)
    model.eval()
    
    params = sum(p.numel() for p in model.parameters())
    print(f"   🔹 Paramètres : {params:,}")
    print(f"   🔹 Hidden size : {model.config.hidden_size}")
    print(f"   🔹 Vocab size : {tokenizer.vocab_size}")
    
    # Test
    textes = [
        "L'intelligence artificielle révolutionne le monde.",
        "Je suis allé au marché acheter des légumes.",
        "Les algorithmes de deep learning sont puissants."
    ]
    
    tokens = tokenizer(textes, return_tensors="pt", padding=True).to(DEVICE)
    with torch.no_grad():
        output = model(**tokens)
    
    cls_embeddings = output.last_hidden_state[:, 0, :]
    print(output.last_hidden_state.shape, output.last_hidden_state[:, 0, :].shape)
    print(f"   🔹 Sortie shape : {output.last_hidden_state.shape}")
    print(f"   🔹 CLS shape : {cls_embeddings.shape}")
    
    # ⚡ CORRECTION : Normaliser avant cosine similarity
    cls_norm = F.normalize(cls_embeddings, dim=1)
    sim = cls_norm @ cls_norm.T
    
    print(f"\n   📊 Similarité cosinus (normalisée) :")
    print(f"      IA1 vs IA2    : {sim[0, 2]:.4f} (devrait être > 0.5)")
    print(f"      IA1 vs Humain : {sim[0, 1]:.4f} (devrait être < 0.5)")
    
    return True

def explore_image_model(name, path, model_type):
    """Charge et teste un modèle d'image"""
    print(f"\n{'='*60}")
    print(f"🖼️  {name} ({model_type})")
    print(f"{'='*60}")
    
    # Chargement
    if model_type == "clip":
        # Pour CLIP, utiliser CLIPModel et CLIPProcessor
        model = CLIPModel.from_pretrained(path).to(DEVICE)
        processor = CLIPProcessor.from_pretrained(path)
    else:
        # Pour ViT classique
        model = AutoModel.from_pretrained(path).to(DEVICE)
        processor = AutoImageProcessor.from_pretrained(path)
    
    model.eval()
    params = sum(p.numel() for p in model.parameters())
    print(f"   🔹 Paramètres : {params:,}")
    
    # Image factice
    dummy_image = Image.new('RGB', (224, 224), color=(128, 128, 128))
    
    if model_type == "clip":
        # ⚡ CORRECTION : Utiliser get_image_features pour CLIP
        inputs = processor(images=dummy_image, return_tensors="pt").to(DEVICE)
        with torch.no_grad():
            image_features = model.get_image_features(
                pixel_values=inputs['pixel_values']
            )
            # print((image_features.last_hidden_state == model.vision_model(inputs['pixel_values']).last_hidden_state).all().sum())
            # print(model.vision_model(inputs["pixel_values"]))
        print(f"   🔹 Image features shape : {image_features}")
        
        # ⚡ CORRECTION : Tester aussi l'encodeur de texte
        tokenizer = CLIPTokenizer.from_pretrained(path)
        textes = ["a cat", "a dog", "a car"]
        text_inputs = tokenizer(textes, return_tensors="pt", padding=True).to(DEVICE)
        with torch.no_grad():
            text_features = model.get_text_features(
                input_ids=text_inputs['input_ids'],
                attention_mask=text_inputs['attention_mask']
            )
        print(f"   🔹 Text features shape : {text_features}")
        
        # ⚡ BONUS : Démo zero-shot avec l'image factice
        print(f"\n   🎯 Démo Zero-Shot (image grise factice) :")
        categories = ["a real photo", "an AI-generated image", "a painting"]
        zero_inputs = processor(
            text=categories,
            images=dummy_image,
            return_tensors="pt",
            padding=True
        ).to(DEVICE)
        with torch.no_grad():
            outputs = model(**zero_inputs)
            probs = outputs.logits_per_image.softmax(dim=1)[0]
            print(probs, "\n\n", outputs, "\n\n", outputs.logits_per_image)
            print(zero_inputs, "\n\n")
        for cat, prob in zip(categories, probs):
            print(f"      {cat}: {prob.item():.1%}")
    
    else:
        # ViT classique
        inputs = processor(images=dummy_image, return_tensors="pt").to(DEVICE)
        with torch.no_grad():
            output = model(**inputs)
        print(f"   🔹 Sortie shape : {output.last_hidden_state}")
        if hasattr(output, 'pooler_output') and output.pooler_output is not None:
            print(f"   🔹 Pooler shape : {output.pooler_output}")
    
    return True

def explore_gpt_model(name, path):
    """Charge et teste un modèle GPT"""
    print(f"\n{'='*60}")
    print(f"🤖 {name}")
    print(f"{'='*60}")
    
    model = AutoModelForCausalLM.from_pretrained(path).to(DEVICE)
    tokenizer = AutoTokenizer.from_pretrained(path)
    tokenizer.pad_token = tokenizer.eos_token
    model.eval()
    
    params = sum(p.numel() for p in model.parameters())
    print(f"   🔹 Paramètres : {params:,}")
    print(f"   🔹 Vocab size : {tokenizer.vocab_size}")
    
    # Génération en ANGLAIS pour de meilleurs résultats
    prompts = [
        "The future of artificial intelligence is",
        "Today I will go to the market to",
        "Deepfake detection is important because"
    ]
    
    for prompt in prompts:
        inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_length=50,
                temperature=0.8,
                do_sample=True,
                top_k=50,
                top_p=0.95,
                pad_token_id=tokenizer.eos_token_id,
                repetition_penalty=1.2
            )
        texte_genere = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"\n   📝 Prompt : '{prompt}'")
        print(f"   ✨ Généré  : '{texte_genere[:150]}...'")
    
    return True

# ========== EXPLORATION ==========

MODELS = {
    "text_very_fast": ("DistilBERT Multilingue", f"{BASE_DIR}/text/very_fast", "text"),
    "text_fast": ("DistilRoBERTa", f"{BASE_DIR}/text/fast", "text"),
    "text_full": ("XLM-RoBERTa", f"{BASE_DIR}/text/full", "text"),
    "image_very_fast": ("ViT-B/16", f"{BASE_DIR}/image/very_fast", "image"),
    # "image_fast": ("CLIP ViT-B/32", f"{BASE_DIR}/image/fast", "clip"),
    # "image_full": ("CLIP ViT-L/14", f"{BASE_DIR}/image/full", "clip"),
    # "gpt": ("DistilGPT2", f"{BASE_DIR}/distillGPT2", "gpt"),
}

print("\n" + "🚀" * 40)
print("EXPLORATION DE TOUS LES MODÈLES TRUSTSIGNAL")
print("🚀" * 40)

results = {}

for key, (name, path, model_type) in MODELS.items():
    print(f"\n🔍 Exploration : {key}")
    
    if not os.path.exists(path):
        print(f"   ⚠️  Dossier introuvable : {path}")
        results[key] = False
        continue
    
    try:
        if model_type == "text":
            results[key] = explore_text_model(name, path)
        # elif model_type in ("image", "clip"):
        #     results[key] = explore_image_model(name, path, model_type)
        # elif model_type == "gpt":
        #     results[key] = explore_gpt_model(name, path)
    except Exception as e:
        print(f"   ❌ Erreur : {e}")
        results[key] = False

# ========== RÉSUMÉ ==========

print("\n\n" + "=" * 80)
print(f"{'📊 RÉSUMÉ FINAL':^80}")
print("=" * 80)

for key, success in results.items():
    name, _, _ = MODELS[key]
    status = "✅ OK" if success else "❌ ÉCHEC"
    print(f"  {status} : {name} ({key})")

nb_ok = sum(results.values())
nb_total = len(results)
print(f"\n  🎯 {nb_ok}/{nb_total} modèles fonctionnels")
print("=" * 80)

print("\n✅ Exploration terminée !")




# image_features = model.get_image_features(pixel_values=...)  # [B, 512]
# text_features  = model.get_text_features(input_ids=...)       # [N_cat, 512]

# # Normalisation L2 d'abord
# image_features = F.normalize(image_features, dim=-1)
# text_features  = F.normalize(text_features, dim=-1)

# # Produit matriciel → logits
# logits_per_image = image_features @ text_features.T  # [B, N_cat]
# logits_per_text  = text_features @ image_features.T  # [N_cat, B]

# # CLIP multiplie aussi par une température apprise
# logits_per_image = logits_per_image * model.logit_scale.exp()