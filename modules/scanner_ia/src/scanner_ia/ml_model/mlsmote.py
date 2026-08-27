# -*- coding: utf-8 -*-
"""
Module MLSMOTE (Multi-Label Synthetic Minority Over-sampling Technique)
Pour rééquilibrer les datasets multi-labels
"""

import numpy as np
import pandas as pd
import random
from sklearn.neighbors import NearestNeighbors
from collections import Counter
import logging
from sklearn.datasets import make_classification
logger = logging.getLogger(__name__)

def create_multilabel_dataset(n_samples=1000, n_classes=5):
    """
    Crée un vrai dataset multi-labels déséquilibré
    """
    from sklearn.datasets import make_multilabel_classification
    
    X, y = make_multilabel_classification(
        n_samples=n_samples,
        n_features=20,
        n_classes=n_classes,
        n_labels=2,  # Chaque échantillon a en moyenne 2 labels
        random_state=42,
        allow_unlabeled=False
    )
    
    # Convertir en DataFrame
    X = pd.DataFrame(X, columns=[f'feat_{i}' for i in range(20)])
    y = pd.DataFrame(y, columns=[f'class_{i}' for i in range(n_classes)])
    
    # Déséquilibrer artificiellement
    for i in range(n_classes):
        if i % 2 == 0:  # Classes paires deviennent minoritaires
            mask = y[f'class_{i}'] == 1
            y.loc[mask, f'class_{i}'] = np.random.choice([0, 1], size=mask.sum(), p=[0.9, 0.1])
    
    return X, y

class MLSMOTE:
    """
    Implémentation de MLSMOTE pour l'oversampling des données multi-labels déséquilibrées.
    
    Basé sur l'article : Charte et al. (2015) - "MLSMOTE: Approaching imbalanced multilabel 
    learning through synthetic instance generation"
    """
    
    def __init__(self, 
                 k_neighbors=5,
                 strategy='ranking',
                 random_state=42,
                 threshold_multiplier=1.0):
        """
        Args:
            k_neighbors (int): Nombre de voisins à considérer
            strategy (str): 'union', 'intersection' ou 'ranking' pour générer les labels
            random_state (int): Seed pour la reproductibilité
            threshold_multiplier (float): Multiplicateur pour le seuil des labels minoritaires
        """
        self.k_neighbors = k_neighbors
        self.strategy = strategy
        self.random_state = random_state
        self.threshold_multiplier = threshold_multiplier
        random.seed(random_state)
        np.random.seed(random_state)
        
    def _calculate_irpl(self, y):
        """
        Calcule l'Imbalance Ratio per Label (IRPL)
        """
        # Compter les occurrences de chaque label
        label_counts = np.sum(y, axis=0)
        max_count = np.max(label_counts)
        
        # Éviter la division par zéro
        irpl = np.zeros(len(label_counts))
        for i, count in enumerate(label_counts):
            if count > 0:
                irpl[i] = max_count / count
            else:
                irpl[i] = float('inf')
                
        return irpl
    
    def _identify_tail_labels(self, y):
        """
        Version améliorée qui gère les labels avec 0 occurrence
        """
        irpl = self._calculate_irpl(y)
        
        # Éviter les divisions par zéro / infini
        irpl = np.nan_to_num(irpl, nan=0.0, posinf=0.0)
        
        # Si tous les irpl sont 0, utiliser un seuil par défaut
        if np.max(irpl) == 0:
            # Considérer les labels avec moins de 10% de la moyenne comme tail
            label_counts = np.sum(y, axis=0)
            mean_count = np.mean(label_counts[label_counts > 0])
            tail_labels = np.where(label_counts < 0.1 * mean_count)[0]
        else:
            mir = np.mean(irpl[irpl > 0]) * self.threshold_multiplier
            tail_labels = np.where(irpl > mir)[0]
        
        return tail_labels
    
    def _get_minority_instances(self, X, y):
        """
        Récupère les instances contenant au moins un label minoritaire
        """
        tail_labels = self._identify_tail_labels(y)
        
        # Trouver les indices des instances avec au moins un tail label
        minority_indices = []
        for i in range(len(y)):
            if np.any(y[i, tail_labels] == 1):
                minority_indices.append(i)
                
        if len(minority_indices) == 0:
            logger.warning("Aucune instance minoritaire trouvée!")
            return X, y, []
            
        X_min = X[minority_indices] if hasattr(X, 'iloc') else X[minority_indices]
        y_min = y[minority_indices]
        
        return X_min, y_min, minority_indices
    
    def _find_neighbors(self, X):
        """
        Trouve les k plus proches voisins pour chaque instance
        """
        if len(X) < self.k_neighbors + 1:
            logger.warning(f"Pas assez d'échantillons ({len(X)}) pour {self.k_neighbors} voisins")
            # Réduire le nombre de voisins si nécessaire
            n_neighbors = min(len(X), self.k_neighbors)
            if n_neighbors < 2:
                return None
        else:
            n_neighbors = self.k_neighbors
            
        nn = NearestNeighbors(
            n_neighbors=n_neighbors + 1,  # +1 car l'instance elle-même est incluse
            metric='euclidean',
            algorithm='kd_tree',
            n_jobs=-1
        )
        nn.fit(X)
        distances, indices = nn.kneighbors(X)
        
        # Exclure l'instance elle-même (premier voisin)
        return indices[:, 1:]
    
    def _generate_labels_ranking(self, y_neighbors):
        """
        Génère les labels par la méthode 'ranking' : 
        un label est inclus s'il apparaît dans plus de la moitié des voisins
        """
        # Compter les occurrences de chaque label parmi les voisins
        label_counts = np.sum(y_neighbors, axis=0)
        threshold = len(y_neighbors) / 2
        return (label_counts > threshold).astype(int)
    
    def _generate_labels_union(self, y_neighbors):
        """
        Génère les labels par la méthode 'union' : 
        un label est inclus s'il apparaît chez au moins un voisin
        """
        return (np.sum(y_neighbors, axis=0) > 0).astype(int)
    
    def _generate_labels_intersection(self, y_neighbors):
        """
        Génère les labels par la méthode 'intersection' : 
        un label est inclus s'il apparaît chez tous les voisins
        """
        n_neighbors = len(y_neighbors)
        return (np.sum(y_neighbors, axis=0) == n_neighbors).astype(int)
    
    def __call__(self, X, y, n_samples=None):
        return self.fit_resample(X, y, n_samples)
    
    def fit_resample(self, X, y, n_samples=None):
        """
        Applique MLSMOTE pour générer des échantillons synthétiques
        
        Args:
            X: Features (DataFrame ou numpy array)
            y: Labels multi-labels (DataFrame ou numpy array)
            n_samples: Nombre d'échantillons à générer (si None, équilibre à la classe majoritaire)
            
        Returns:
            X_resampled, y_resampled: Données augmentées
        """
        # Conversion en numpy arrays si nécessaire
        if isinstance(X, pd.DataFrame):
            X = X.values
        if isinstance(y, pd.DataFrame):
            y = y.values
        elif isinstance(y, list):
            y = np.array(y)
            
        logger.info(f"Shape originale - X: {X.shape}, y: {y.shape}")
        
        # Statistiques avant oversampling
        label_counts = np.sum(y, axis=0)
        logger.info(f"Distribution originale des labels: {label_counts}")
        
        # Récupérer les instances minoritaires
        X_min, y_min, minority_idx = self._get_minority_instances(X, y)
        
        if len(X_min) == 0:
            logger.warning("Aucune instance minoritaire trouvée, retour des données originales")
            return X, y
            
        logger.info(f"Instances minoritaires: {len(X_min)}")
        
        # Trouver les voisins (dans l'espace des instances minoritaires uniquement)
        neighbor_indices = self._find_neighbors(X_min)
        
        if neighbor_indices is None:
            logger.warning("Pas assez de voisins, duplication aléatoire")
            return self._random_duplicate(X, y, n_samples)
        
        # Déterminer le nombre d'échantillons à générer
        if n_samples is None:
            # Équilibrer à la classe majoritaire
            target_count = np.max(label_counts)
            n_samples = target_count - np.min(label_counts[label_counts > 0])
            n_samples = max(n_samples, 0)
            
        n_samples = min(n_samples, 10000)  # Limite pour éviter une explosion
        logger.info(f"Génération de {n_samples} échantillons synthétiques")
        
        # Générer les nouveaux échantillons
        synthetic_X = []
        synthetic_y = []
        
        for i in range(n_samples):
            # Choisir une instance de référence aléatoire (dans X_min)
            ref_idx = random.randint(0, len(X_min) - 1)
            
            # Choisir un voisin aléatoire (dans X_min aussi)
            if len(neighbor_indices[ref_idx]) > 0:
                neighbor_idx = random.choice(neighbor_indices[ref_idx])
            else:
                continue
                
            # CORRECTION: On utilise directement les indices dans X_min
            # Plus besoin de minority_idx car X_min est notre référence
            X_ref = X_min[ref_idx]
            X_neighbor = X_min[neighbor_idx]
            
            # Récupérer les labels des voisins (pour générer les nouveaux labels)
            neighbor_labels = []
            for j in neighbor_indices[ref_idx][:self.k_neighbors]:
                neighbor_labels.append(y_min[j])
            
            # Générer le nouveau feature vector (interpolation)
            ratio = random.random()
            gap = X_ref - X_neighbor
            new_X = X_ref + ratio * gap
            
            # Générer les nouveaux labels selon la stratégie choisie
            if self.strategy == 'union':
                new_y = self._generate_labels_union(np.array(neighbor_labels))
            elif self.strategy == 'intersection':
                new_y = self._generate_labels_intersection(np.array(neighbor_labels))
            else:  # ranking (par défaut)
                new_y = self._generate_labels_ranking(np.array(neighbor_labels))
            
            synthetic_X.append(new_X)
            synthetic_y.append(new_y)
        
        if len(synthetic_X) == 0:
            logger.warning("Aucun échantillon synthétique généré")
            return X, y
            
        # Combiner avec les données originales
        synthetic_X = np.array(synthetic_X)
        synthetic_y = np.array(synthetic_y)
        
        X_resampled = np.vstack([X, synthetic_X])
        y_resampled = np.vstack([y, synthetic_y])
        
        logger.info(f"Shape finale - X: {X_resampled.shape}, y: {y_resampled.shape}")
        
        # Statistiques après oversampling
        new_label_counts = np.sum(y_resampled, axis=0)
        logger.info(f"Nouvelle distribution des labels: {new_label_counts}")
        
        return X_resampled, y_resampled
    
    def _random_duplicate(self, X, y, n_samples):
        """
        Version améliorée qui peut créer de nouvelles combinaisons
        """
        if n_samples is None or n_samples <= 0:
            return X, y
            
        n_samples = min(n_samples, 10000)
        
        X_min, y_min, minority_idx = self._get_minority_instances(X, y)
        
        if len(X_min) == 0:
            return X, y
        
        synthetic_X = []
        synthetic_y = []
        
        for _ in range(n_samples):
            # Prendre 2 indices différents
            idx1, idx2 = random.sample(range(len(minority_idx)), 2)
            
            # Interpolation entre deux instances minoritaires
            ratio = random.random()
            new_X = X[idx1] * (1 - ratio) + X[idx2] * ratio
            
            # Union des labels (pour créer des combinaisons)
            new_y = np.logical_or(y[idx1], y[idx2]).astype(int)
            
            synthetic_X.append(new_X)
            synthetic_y.append(new_y)
        
        synthetic_X = np.array(synthetic_X)
        synthetic_y = np.array(synthetic_y)
        
        X_resampled = np.vstack([X, synthetic_X])
        y_resampled = np.vstack([y, synthetic_y])
        
        return X_resampled, y_resampled


def balance_to_majority(X, y, majority_threshold=1.0, **mlsmote_kwargs):
    """
    Fonction utilitaire pour équilibrer toutes les classes minoritaires
    vers la classe majoritaire
    
    Args:
        X: Features
        y: Labels
        majority_threshold: Seuil pour définir la classe majoritaire
        **mlsmote_kwargs: Arguments pour MLSMOTE
        
    Returns:
        X_balanced, y_balanced
    """
    mlsmote = MLSMOTE(**mlsmote_kwargs)
    
    if isinstance(y, pd.DataFrame):
        y_array = y.values
    else:
        y_array = np.array(y)
    
    # Compter les occurrences
    label_counts = np.sum(y_array, axis=0)
    majority_count = np.max(label_counts)
    
    logger.info(f"Majority count: {majority_count}")
    
    # Appliquer MLSMOTE
    X_bal, y_bal = mlsmote.fit_resample(X, y_array)
    
    return X_bal, y_bal

    
if __name__ == "__main__":
    
    print("📊 Création d'un dataset multi-labels DÉSÉQUILIBRÉ...")
    from sklearn.datasets import make_multilabel_classification
    # Créer un dataset TRÈS déséquilibré
    X, y = make_multilabel_classification(
        n_samples=1000,
        n_features=20,
        n_classes=5,
        n_labels=1,  # Un seul label par échantillon pour plus de déséquilibre
        random_state=42
    )
    
    X = pd.DataFrame(X, columns=[f'feat_{i}' for i in range(20)])
    y = pd.DataFrame(y, columns=['class_0', 'class_1', 'class_2', 'class_3', 'class_4'])
    
    # Déséquilibrer FORTEMENT
    # Classe 4 devient ultra-minoritaire
    mask = y['class_4'] == 1
    y.loc[mask, 'class_4'] = np.random.choice([0, 1], size=mask.sum(), p=[0.95, 0.05])
    
    # Classe 0 devient minoritaire
    mask = y['class_0'] == 1
    y.loc[mask, 'class_0'] = np.random.choice([0, 1], size=mask.sum(), p=[0.8, 0.2])
    
    print(f"✅ Distribution originale:\n{y.sum()}")
    
    # Initialiser MLSMOTE
    mlsmote = MLSMOTE(k_neighbors=5, strategy='ranking')
    
    # ✅ Récupérer UNIQUEMENT les instances minoritaires
    X_min, y_min, idx = mlsmote._get_minority_instances(X.values, y.values)
    X_min = pd.DataFrame(X_min, columns=X.columns)
    y_min = pd.DataFrame(y_min, columns=y.columns)
    
    print(f"\n📊 Instances minoritaires: {len(X_min)}/{len(X)}")
    print(f"Distribution minoritaire:\n{y_min.sum()}")
    
    # Appliquer MLSMOTE
    X_res, y_res = mlsmote.fit_resample(X_min, y_min)
    
    print("\n📈 Résultats MLSMOTE:")
    print(f"   Avant: {X_min.shape}, {y_min.shape}")
    print(f"   Après: {X_res.shape}, {y_res.shape}")
    print(f"\n   Distribution avant (minoritaires):\n{y_min.sum()}")
    
    y_res_df = pd.DataFrame(y_res, columns=y.columns)
    print(f"\n   Distribution après (minoritaires + synthétiques):\n{y_res_df.sum()}")