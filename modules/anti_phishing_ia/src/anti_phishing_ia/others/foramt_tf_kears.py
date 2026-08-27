import tensorflow as tf
import numpy as np
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from scikeras.wrappers import KerasClassifier
from sklearn.metrics import classification_report, accuracy_score

# 🎯 Création d'un petit dataset rapide
X, y = make_classification(
    n_samples=100,      # Très petit pour rapidité
    n_features=10,      # Peu de features
    n_informative=2,    # 8 features utiles
    n_redundant=2,      # 2 features redondantes
    random_state=42
)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Dataset: {X.shape}")
print(f"Train: {X_train.shape}, Test: {X_test.shape}")
print(f"Classes: {np.unique(y)}, Distribution: {np.bincount(y)}")

# 🏗️ Fonction de création du modèle
def create_model():
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(16, activation='relu', input_shape=(X_train.shape[1],)),
        tf.keras.layers.Dense(1, activation='sigmoid')  # Sortie binaire
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    return model

# 🚀 Création du KerasClassifier
keras_clf = KerasClassifier(
    model=create_model,
    epochs=2,           # Très peu d'epochs
    batch_size=2,
    verbose=1
)

# 🔧 Entraînement rapide
print("\n🔧 Entraînement du KerasClassifier...")
keras_clf.fit(X_train, y_train)

# 📊 Évaluation
train_score = keras_clf.score(X_train, y_train)
test_score = keras_clf.score(X_test, y_test)
print(f"\n📈 Scores - Train: {train_score:.4f}, Test: {test_score:.4f}")

# 🎯 FORMAT DES PRÉDICTIONS - CE QUI T'INTÉRESSE !

print("\n" + "="*50)
print("🎯 FORMAT predict_proba (KerasClassifier)")
print("="*50)

# predict_proba - Retourne les probabilités pour chaque classe
y_proba = keras_clf.predict_proba(X_test[:5])
print("predict_proba shape:", y_proba.shape)
print("predict_proba ([[P(classe0), P(classe1)], ...]):")
print(y_proba)

print("\n" + "="*50)
print("🎯 FORMAT predict (KerasClassifier)")
print("="*50)

# predict - Retourne les classes prédites
y_pred = keras_clf.predict(X_test[:5])
print("predict shape:", y_pred.shape)
print("predict (classes 0/1):")
print(y_pred)

# 🔍 Comparaison détaillée
print("\n" + "="*50)
print("🔍 COMPARAISON DÉTAILLÉE")
print("="*50)

for i in range(5):
    true_class = y_test[i]
    pred_class = y_pred[i]
    prob_class0 = y_proba[i][0]
    prob_class1 = y_proba[i][1]
    
    print(f"Exemple {i}:")
    print(f"  True: {true_class}")
    print(f"  Pred: {pred_class}")
    print(f"  Probabilities: [class0={prob_class0:.4f}, class1={prob_class1:.4f}]")
    print(f"  Correct: {true_class == pred_class}")
    print()

# 📋 Rapport complet
print("\n" + "="*50)
print("📊 RAPPORT DE CLASSIFICATION COMPLET")
print("="*50)

y_pred_all = keras_clf.predict(X_test)
print(classification_report(y_test, y_pred_all))

# 💾 Test de sauvegarde et rechargement
print("\n💾 Test sauvegarde...")
keras_clf.model_.save('keras_classifier_model.h5')

# 🔧 Test avec de nouvelles données
print("\n🧪 TEST AVEC NOUVELLES DONNÉES GÉNÉRÉES")
new_data, _ = make_classification(n_samples=3, n_features=10, random_state=999)
new_proba = keras_clf.predict_proba(new_data)
new_pred = keras_clf.predict(new_data)

print("Nouvelles données - predict_proba:")
print(new_proba)
print("Nouvelles données - predict:")
print(new_pred)

# 🎯 RÉSUMÉ DES FORMATS
print("\n" + "="*50)
print("🎯 RÉSUMÉ DES FORMATS KerasClassifier")
print("="*50)
print("""
predict_proba() → [[P(class0), P(class1)], ...]
                  [[0.1, 0.9], [0.8, 0.2], ...]

predict()       → [class0, class1, ...]
                  [1, 0, 1, ...]

• predict_proba: probabilities for each class
• predict:      predicted class (0 or 1)
• score:        accuracy score
""")