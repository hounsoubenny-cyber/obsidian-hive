from transformers import AutoModel, AutoTokenizer

# Définit le chemin vers ton modèle local
path = '/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/MODEL_SHARED/text/very_fast'

# Charge le tokenizer et le modèle
tokenizer = AutoTokenizer.from_pretrained(path)
model = AutoModel.from_pretrained(path)

# --- Évaluation rapide ---
texte_test = "Hello, i am human"
print("Test du modèle...")
tokens = tokenizer(texte_test, return_tensors="pt")
output = model(**tokens)

# Affiche les sorties principales (le modèle n'a pas de tête de classification, 
# donc il retourne 'last_hidden_state' et 'pooler_output')
print("\nClés de la sortie :")
for key in output.keys():
    if hasattr(output[key], 'shape'):
        print(f"  '{key}' : shape = {output[key].shape}")

# --- Exploration du modèle ---
print("\n" + "="*50)
print(" EXPLORATION DU MODÈLE ")
print("="*50)

# 1. Affiche l'architecture complète
print("\n--- Architecture ---")
print(model)

# 2. Affiche le nombre de paramètres
total_params = sum(p.numel() for p in model.parameters())
trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"\n--- Paramètres ---")
print(f"Total      : {total_params:,}")
print(f"Entrainables: {trainable_params:,}")

# 3. Affiche la configuration
print("\n--- Configuration ---")
print(model.config)

# 4. Liste les principaux modules (blocs Transformer)
if hasattr(model, 'encoder') and hasattr(model.encoder, 'layer'):
    print(f"\n--- Blocs Transformer ---")
    print(f"Nombre de couches (layers) : {len(model.encoder.layer)}")

print("\n✅ Test terminé.")