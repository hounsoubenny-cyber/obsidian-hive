import tensorflow as tf
import numpy as np
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 🎯 Création d'un petit dataset
X, y = make_classification(
    n_samples=100,    # Petit dataset pour entraînement rapide
    n_features=10,     # 20 features
    n_informative=2,  # 15 features utiles
    n_redundant=2,     # 5 features redondantes
    random_state=42
)

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Dataset shape: {X.shape}")
print(f"Labels: {np.unique(y)}")
print(f"Class distribution: {np.bincount(y)}")

# 🏗️ Modèle Keras simple et rapide
def create_simple_binary_model(input_dim):
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(32, activation='relu', input_shape=(input_dim,)),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(1, activation='sigmoid')  # Sortie binaire
    ])

    model.compile(
        optimizer='adam',
        loss='mse',
        metrics=['accuracy']
    )

    return model

# Création du modèle
model = create_simple_binary_model(X_train.shape[1])
model.summary()

# 🚀 Entraînement rapide
print("\n🔧 Entraînement...")
history = model.fit(
    X_train, y_train,
    epochs=10,           # Peu d'epochs pour rapidité
    batch_size=10,
    validation_split=0.2,
    verbose=1
)
print(history.history.keys())
import matplotlib.pyplot as plt

def plot_training_history(history):
    plt.figure(figsize=(12, 4))

    # Courbe de loss
    plt.subplot(1, 2, 1)
    plt.plot(history.history['loss'], label='Training Loss')
    if 'val_loss' in history.history:
        plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title('Model Loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend()

    # Zoom sur les dernières epochs
    plt.subplot(1, 2, 2)
    plt.plot(history.history['loss'][10:], label='Training Loss (from epoch 10)')
    if 'val_loss' in history.history:
        plt.plot(history.history['val_loss'][10:], label='Validation Loss')
    plt.title('Loss - Last Epochs')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend()

    plt.tight_layout()
    plt.show()

# Utilisation
plot_training_history(history)
# 📊 Évaluation
test_loss, test_accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f"\n📈 Accuracy sur test: {test_accuracy:.4f}")

# 🎯 PRÉDICTIONS - FORMAT IMPORTANT !
print("\n🎯 FORMAT DES PRÉDICTIONS:")

# Predict (classes)
y_pred = model.predict(X_test[:5])  # Probabilités
y_pred_classes = (y_pred > 0.5).astype(int).flatten()  # Classes 0/1

print("Predict (probabilités brutes):")
print(y_pred.flatten())
print("\nPredict (classes 0/1):")
print(y_pred_classes)

# Predict_proba équivalent
y_pred_proba = model.predict(X_test[:5])  # C'est déjà les probabilités!

print("\nPredict_proba (probabilités classe 1):")
print(y_pred_proba.flatten())

# 🔍 Comparaison avec les vraies labels
print("\n🔍 Comparaison prédictions vs vraies labels:")
for i in range(5):
    true_label = y_test[i]
    pred_prob = y_pred_proba[i][0]
    pred_class = y_pred_classes[i]
    print(f"Exemple {i}: True={true_label}, Prob={pred_prob:.4f}, Pred={pred_class}")

# 📋 Rapport de classification complet
y_pred_all = (model.predict(X_test) > 0.5).astype(int).flatten()
print("\n📊 Rapport de classification:")
print(classification_report(y_test, y_pred_all))
