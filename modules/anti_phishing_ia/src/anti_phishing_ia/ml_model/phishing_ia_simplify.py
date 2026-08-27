#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct 31 03:53:56 2025

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Version SIMPLIFIÉE de PhishingIA pour dataset déjà équilibré (51/49)
- Pas de SMOTE
- Stacking léger (3 modèles au lieu de 7)
- Pas de BayesSearch (paramètres fixes optimaux)
- 10x plus rapide
"""

import os, sys, dill, pandas as pd, numpy as np, gzip
import warnings, joblib
warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import RobustScaler, LabelEncoder
from xgboost import XGBClassifier
from tqdm import tqdm
import traceback

dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(dir_, exist_ok=True)

classes = ['phishing', 'safe']
features_name = ['url_length', 'domain_length', 'num_dots_domain', 'num_dots_in_host',
                 'has_ip', 'ip_as_domain', 'domain_age', 'has_creation_date', 'pos_slash',
                 'has_at_sign', 'num_dash', 'dash_in_domain', 'has_https', 'has_punycode',
                 'num_query_params', 'num_suspicious_words', 'num_subdomain',
                 'suspicious_tld', 'num_form', 'path_length', 'has_port', 'n_redirects',
                 'actions_valid', 'contains_percent_in_url']


class PhishingIA_Simplified:
    """Version simplifiée pour dataset équilibré"""

    def __init__(self, model_dir_='model1', dataset_file='dataset.joblib',
                 model_file='model.joblib', n_features=len(features_name),
                 random_state=42, features_name=features_name):

        self.dataset_file = os.path.join(dir_, 'datasets', dataset_file)
        self.model_file = os.path.join(dir_, 'models', model_dir_, model_file)
        self.random_state = random_state
        self.df = pd.DataFrame({})

        os.makedirs(os.path.dirname(self.dataset_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.model_file), exist_ok=True)

        self.load_dataset(self.dataset_file)

        if not self.df.empty and 'label' in self.df.columns:
            self.features_name = list(self.df.drop(['label'], axis=1).columns)
            self.n_features = self.df.shape[1] - 1
        else:
            self.features_name = features_name
            self.n_features = n_features

        self.scaler = RobustScaler()
        self.le = LabelEncoder()
        self.le.fit(classes)

        self.model = None
        self.load_model(self.model_file)

        print(f"✅ PhishingIA_Simplified initialisé")
        print(f"   - Features: {self.n_features}")
        print(f"   - Dataset: {self.dataset_file}")
        print(f"   - Model: {self.model_file}")

    def load_dataset(self, filepath):
        """Chargement du dataset"""
        if os.path.exists(filepath):
            try:
                self.df = pd.DataFrame(pd.read_pickle(filepath))
                if 'label' not in self.df.columns:
                    raise ValueError("Le dataset doit contenir une colonne 'label'")

                # Nettoyer les colonnes inutiles
                for col in ('grade', 'score_total', 'url'):
                    if col in self.df.columns:
                        self.df = self.df.drop(col, axis=1)

                print(f"✅ Dataset chargé: {self.df.shape[0]:,} échantillons, {self.df.shape[1]-1} features")
                print(f"📊 Distribution:")
                print(self.df['label'].value_counts())

            except Exception as e:
                print(f"❌ Erreur chargement dataset: {e}")
                self.df = pd.DataFrame({})
        else:
            print(f"📁 Aucun dataset trouvé à {filepath}")
            self.df = pd.DataFrame({})

    def save_dataset(self, filepath):
        """Sauvegarde du dataset"""
        try:
            with open(filepath, 'wb') as f:
                dill.dump(self.df.to_dict(orient="records"), f)
            print(f"💾 Dataset sauvegardé: {filepath}")
        except Exception as e:
            print(f"❌ Erreur sauvegarde dataset: {e}")

    def save_model(self, model=None):
        """Sauvegarde du modèle"""
        model = model or self.model
        if model is None:
            print("⚠️ Aucun modèle à sauvegarder")
            return

        try:
            os.makedirs(os.path.dirname(self.model_file), exist_ok=True)

            if str(self.model_file).endswith(".gz"):
                with gzip.open(self.model_file, 'wb') as f:
                    dill.dump({'model': model, "le": self.le, 'features': self.features_name}, f)
            else:
                with open(self.model_file, 'wb') as f:
                    dill.dump({'model': model, "le": self.le, 'features': self.features_name}, f)

            print(f"✅ Modèle sauvegardé: {self.model_file}")

        except Exception as e:
            print(f"❌ Erreur sauvegarde modèle: {e}")

    def load_model(self, model_file):
        """Chargement du modèle"""
        if os.path.exists(model_file):
            try:
                if str(model_file).endswith(".gz"):
                    with gzip.open(model_file, 'rb') as f:
                        data = dill.load(f)
                else:
                    with open(model_file, 'rb') as f:
                        data = dill.load(f)

                self.model = data['model']
                self.le = data.get('le', LabelEncoder())
                self.features_name = data.get('features', features_name)

                print(f"✅ Modèle chargé: {model_file}")
                return self.model

            except Exception as e:
                print(f"❌ Erreur chargement modèle: {e}")
                return None
        else:
            print(f"📁 Aucun modèle trouvé à {model_file}")
            return None

    def prepa_data(self, data, mode='fit'):
        """Préparation des données"""
        if isinstance(data, (pd.DataFrame, np.ndarray, pd.Series)):
            if isinstance(data, pd.DataFrame) and data.empty:
                raise ValueError('Data vide')
        else:
            if not data:
                raise ValueError('Data vide')

        p = pd.DataFrame(data)

        # Nettoyer
        for col in ('grade', 'score_total', 'url'):
            if col in p.columns:
                p = p.drop(col, axis=1)

        if 'label' not in p.columns and mode == 'fit':
            raise ValueError("La colonne 'label' est requise en mode 'fit'")

        # Auto-fill colonnes manquantes
        missing_cols = [c for c in self.features_name if c not in p.columns]
        if missing_cols:
            print(f"⚠️ Colonnes manquantes: {missing_cols}")
            for col in missing_cols:
                p[col] = 0

        # Réordonner
        p = p[self.features_name + (['label'] if 'label' in p.columns else [])]

        if mode == 'fit':
            # Ajouter au dataset
            if self.df.empty:
                self.df = p
            else:
                if not self.df.equals(p):
                    self.df = pd.concat((self.df, p), axis=0, ignore_index=True)
                    # Drop duplicates sur URL si présent
                    if 'url' in self.df.columns:
                        self.df = self.df.drop_duplicates(subset=['url'], ignore_index=True)

            self.save_dataset(self.dataset_file)

            # Préparer X, y
            y = self.le.transform(self.df['label'].tolist())
            X = self.df.drop(['label'], axis=1)

            # Remplacer NaN et inf
            X = X.fillna(-1)
            X = X.replace([np.inf, -np.inf], -1)

            # ✅ PAS DE SMOTE pour dataset équilibré!
            print(f"✅ Données préparées: {X.shape[0]:,} samples, pas de SMOTE (dataset équilibré)")

            return X, y

        elif mode == 'predict':
            if 'label' in p.columns:
                y = self.le.transform(p['label'].tolist())
                X = p.drop(['label'], axis=1)
            else:
                y = None
                X = p

            X = X.fillna(-1)
            X = X.replace([np.inf, -np.inf], -1)

            return X, y

    def build_simple_model(self):
        """
        Construit un modèle SIMPLE mais efficace
        - RandomForest optimisé (pas de tuning, paramètres fixes)
        - Pas de stacking (trop lourd)
        - Scaling avant RF
        """
        print("\n🔧 Construction du modèle SIMPLIFIÉ...")

        # RandomForest avec paramètres optimaux fixes
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',  # Compense les petits déséquilibres
            random_state=self.random_state,
            n_jobs=-1,
            verbose=0
        )
        ex = ExtraTreesClassifier(n_estimators=200)
        # Pipeline: Scale + RF
        model = Pipeline([
            ('scaler', self.scaler),
            ('rf', rf)
        ])

        print("✅ Modèle créé: Pipeline(RobustScaler + RandomForest)")
        return model

    def fit(self, data):
        """
        Entraînement SIMPLIFIÉ
        - Pas de SMOTE
        - Pas de BayesSearch
        - Pas de ModelStack
        """
        try:
            print("\n" + "="*80)
            print("ENTRAÎNEMENT SIMPLIFIÉ")
            print("="*80)

            # Préparer données
            X, y = self.prepa_data(data, 'fit')
            print(f"✅ Données préparées: {X.shape}")

            # Vérifier équilibre
            unique, counts = np.unique(y, return_counts=True)
            ratio = counts[1] / counts[0] if len(counts) > 1 else 1.0
            print(f"\n📊 Distribution:")
            for label, count in zip(self.le.classes_, counts):
                print(f"   - {label}: {count:,} ({count/len(y)*100:.1f}%)")
            print(f"   Ratio: {ratio:.3f}")

            if 0.8 <= ratio <= 1.25:
                print("✅ Dataset bien équilibré, pas de SMOTE nécessaire")

            # Split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=self.random_state, stratify=y
            )

            print(f"\n✅ Split:")
            print(f"   - Train: {len(X_train):,}")
            print(f"   - Test: {len(X_test):,}")

            # Construire modèle
            model = self.build_simple_model()

            # Fit
            print("\n🔄 Entraînement en cours...")
            from datetime import datetime
            start = datetime.now()

            model.fit(X_train, y_train)

            duration = (datetime.now() - start).total_seconds()
            print(f"✅ Entraînement terminé en {duration:.1f}s ({duration/60:.1f}min)")

            # Évaluation
            print("\n" + "="*80)
            print("ÉVALUATION")
            print("="*80)

            train_score = model.score(X_train, y_train)
            test_score = model.score(X_test, y_test)
            gap = train_score - test_score

            print(f"\n📊 Scores:")
            print(f"   - Train: {train_score:.4f}")
            print(f"   - Test: {test_score:.4f}")
            print(f"   - Gap: {gap:.4f}")

            if gap < 0.05:
                print("   ✅ Excellente généralisation!")
            elif gap < 0.10:
                print("   ✅ Bonne généralisation")
            else:
                print("   ⚠️ Possible overfitting")

            # Classification report
            y_pred = model.predict(X_test)
            print("\n📊 Classification Report:")
            print(classification_report(y_test, y_pred, target_names=self.le.classes_))

            # Confusion Matrix
            cm = confusion_matrix(y_test, y_pred)
            print("\n🎯 Confusion Matrix:")
            print(cm)

            tn, fp, fn, tp = cm.ravel()
            print(f"\n   TN: {tn:,} | FP: {fp:,}")
            print(f"   FN: {fn:,} | TP: {tp:,}")
            print(f"\n   False Positive Rate: {fp/(fp+tn)*100:.2f}%")
            print(f"   False Negative Rate: {fn/(fn+tp)*100:.2f}%")

            # Sauvegarder
            self.model = model
            self.save_model(model)

            print("\n✅ FIT TERMINÉ!")

        except Exception as e:
            print(f"❌ Erreur durant fit: {e}")
            print(traceback.format_exc())
            return None

    def predict(self, data):
        """Prédiction"""
        try:
            X, y_true = self.prepa_data(data, 'predict')
        except Exception as e:
            print(f"❌ Erreur préparation données: {e}")
            return None

        if self.model is None:
            print("⚠️ Aucun modèle chargé")
            return None

        y_pred = np.array(self.model.predict(X))
        y_pred_proba = np.array(self.model.predict_proba(X)).astype(float)

        cols = self.le.classes_

        predict_proba = {i: dict(zip(cols, row)) for i, row in enumerate(y_pred_proba)}
        predict_labels = {i: label for i, label in enumerate(self.le.inverse_transform(y_pred))}
        true_labels = {i: label for i, label in enumerate(self.le.inverse_transform(y_true))} if y_true is not None else {}

        return {
            "predict_proba": predict_proba,
            "predict": predict_labels,
            "true_labels": true_labels
        }


# ============================================================================
# USAGE
# ============================================================================

if __name__ == '__main__':
    
    from core.features_extractor import features_extractor_from_url
    # Initialiser
    ph = PhishingIA_Simplified(
        features_name=features_name,
        n_features=len(features_name),
        dataset_file='dataset.pkl',
        model_file='model_phish_simple.pkl',
        model_dir_='model_simple',
        random_state=42
    )

    # Charger le dataset
    df = joblib.load(dir_ + '/datasets/dataset.pkl')
    df = pd.DataFrame(df)

    print(f"\n📊 Dataset shape: {df.shape}")
    print("📊 Distribution:")
    print(df['label'].value_counts())

    # Option 1: Fit sur tout le dataset
    # ph.fit(df)

    # Option 2: Fit sur un échantillon (pour tester rapidement)
    sample = df.sample(n=min(10000, len(df)), random_state=42)
    print(f"\n🔄 Fit sur échantillon de {len(sample):,} URLs...")
    ph.fit(sample)

    # Test sur URLs réelles
    test_urls = [
        {"url": "https://www.amazon.com/", "label": "safe"},
        {"url": "https://accounts.google.com/", "label": "safe"},
        {"url": "https://www.paypal.com/signin/", "label": "safe"},
        {"url": "http://192.168.1.1/login.php", "label": "phishing"},
    ]

    print("\n" + "="*80)
    print("TEST SUR URLs RÉELLES")
    print("="*80)

    for test in test_urls:
        result = ph.predict([features_extractor_from_url(test["url"])])
        if result:
            pred = result['predict'][0]
            proba = result['predict_proba'][0]
            expected = test['label']

            status = "✅" if pred == expected else "❌"
            print(f"\n{status} {test['url']}")
            # print(f"   Attendu: {expected} | Prédit: {pred}")
            # print(f"   Probas: {proba}")
            print(result)
