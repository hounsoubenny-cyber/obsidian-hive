#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov  4 15:49:41 2025

@author: hounsousamuel
"""

import os, sys, dill, pandas as pd, numpy as np, joblib
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Supprime logs TensorFlow
pd.set_option("display.max_row",111)
pd.set_option("display.max_columns",111)

import tensorflow as tf
tf.get_logger().setLevel('ERROR')

import warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
from rules.rules1 import RulesManager
from scanner.ml_model import MLSMOTE
from sklearn.ensemble import ExtraTreesRegressor,HistGradientBoostingRegressor, StackingClassifier
from iterstrat.ml_stratifiers import MultilabelStratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split as tts
from sklearn.metrics import (classification_report,confusion_matrix,multilabel_confusion_matrix,
                             f1_score,accuracy_score,precision_score,recall_score)
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
from sklearn.preprocessing import RobustScaler,MultiLabelBinarizer
from tqdm import tqdm
from scanner.ml_model.modeloptimize import ModelOptimization, split_data
from scanner.ml_model.modelstack import ModelStack
import traceback, dill, gzip
import zstandard as zstd
from ml_model.dataset_builder import DatasetBuilder

dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)),'data')
os.makedirs(dir_, exist_ok=True)
rules = RulesManager(rules_file="signatures3.json",password_file="password.txt")
classes = rules.list_vulnerabilities()
features_name = ['url_length', 'has_https', 'query_num', 'domain_length', 'path_depth',
                 'domain_entropy', 'status_code', 'deep', 'num_balises_a', 'num_balises_form',
                 'num_balises_iframe', 'num_balises_script', 'num_balises_style',
                 'num_balises_img', 'num_balises_link', 'num_inputs', 'response_time',
                 'body_length', 'body_entropy', 'num_links', 'num_internal_links',
                 'external_links_ratio', 'num_issues_analyzer', 'num_event_start_by_on',
                 'mean_script_entropy', 'mean_style_entropy', 'strict_transport_security',
                 'x_frame_options', 'x_content_type_options', 'content_security_policy',
                 'cookies_secure', 'num_func_script', 'num_func_moyen', 'num_func_faible',
                 'num_func_eleve_percent', 'num_func_critical_percent', 'mean_length_func']

features_name = DatasetBuilder().get_all_features_names()[0]
features_name.remove('url')

classes = [
    'XSS',
    'SQLi',
    'CSRF',
    'OpenRedir',
    'LFI',
    'ConfigExpose',
    'BackupExpose',
    'DebugExpose',
    'AdminPanel',
    'SSTI',
    'XXE',
    'InsecUpload',
    'CMDi',
    'IDOR',
    'NoSQLi',
    'RFI',
    'CORS',
    'DirTrav',
    'GraphQLi',
    'XPathi',
    'LDAPi',
]

def get_features_name(X) :
    """ Recuperation des noms des features """
    if isinstance(X,pd.DataFrame) :
        features_name_ = X.columns.tolist()
    elif isinstance(X,np.ndarray) :
        features_name_ = features_name
    return features_name_

class ScannerIA:
    def __init__(self, model_dir='model0',dataset_file='dataset.joblib', model_file='model.joblib',classes=classes, n_features=len(features_name), cv=5,
                 scoring={}, random_state=42, learning_rate=0.01, save_dir='sam0',features_name=features_name,auto_fill_missing=True, compress=True,
                 compression_level=10):
        self.dataset_file = os.path.join(dir_,'datasets',dataset_file)
        self.model_file = os.path.join(dir_,'models', model_dir , model_file)

        self.classes = classes
        self.scoring = scoring or ['f1_samples', 'accuracy', 'precision_samples', 'recall_samples']
        self.random_state = random_state
        self.save_dir = save_dir
        self.learning_rate = learning_rate
        self.df = pd.DataFrame({})
        self.auto_fill_missing = auto_fill_missing
        self.compress = compress
        self.compression_level = compression_level
        os.makedirs(os.path.dirname(self.dataset_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
        self.load_dataset(self.dataset_file)

        if features_name and n_features:
            self.features_name = features_name
            self.n_features = n_features
        else:
            if not self.df.empty and 'label' in self.df.columns:
                self.features_name = get_features_name(self.df.drop(['label'],axis=1))
                self.n_features = self.df.shape[1] - 1
            else:
                raise ValueError("Données manquantes !")

        self.imputer = IterativeImputer(random_state=self.random_state,estimator=HistGradientBoostingRegressor(max_iter=100,learning_rate=0.01,n_iter_no_change=20))
        self.scaler = RobustScaler()
        self.cv = MultilabelStratifiedKFold(n_splits=min(cv,2), shuffle=True, random_state=self.random_state)
        self.smote = MLSMOTE
        self.mlb = MultiLabelBinarizer(classes=self.classes)
        #self.mlb.fit([])
        self.mlb.fit(self.df)
        self.model = None
        self.model_file = str(self.model_file)
        if self.compress:
            self.model_file = self.model_file + '.zst' if not self.model_file.endswith(".zst") else self.model_file
        self.load_model(self.model_file)
        print(f"ScannerIA initialisé avec {self.n_features} features, dataset dans {self.dataset_file}, model dans {self.model_file}")

    def load_dataset(self,filepath) :
        """ Chargement du dataset depuis un fichier """
        if os.path.exists(filepath) :
            try :
                self.df = pd.DataFrame(joblib.load(filename=filepath))
                if 'label' not in self.df.columns :
                    raise ValueError("Le dataset doit contenir une colonne 'label'")
                if self.df.empty :
                    print(f" ⚠️ Attention : Le dataset chargé depuis {filepath} est vide.")
                else :
                    print(f" ✅ Dataset chargé depuis {filepath} avec {self.df.shape[0]} échantillons et {self.df.shape[1]-1} features.")
                    print(f"Features : {self.df.columns.tolist()}.\n NOTE : 'label' serait la target pas un feature  ")
            except Exception as e :
                print(f" ❌ Erreur lors du chargement du dataset depuis {filepath} : \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
                self.df = pd.DataFrame({})
        else :
            print(f" 📁 Aucun dataset trouvé à {filepath}, démarrage avec un dataset vide.")
            self.df = pd.DataFrame({})

    def save_dataset(self,filepath) :
        """ Sauvegarde du dataset dans un fichier """
        try :
            joblib.dump(self.df.to_dict(orient="records"),filepath)
            print(f" 💾 Dataset sauvegardé dans {filepath} avec {self.df.shape[0]} échantillons et {self.df.shape[1]-1} features.")
            print(f"Features : {self.df.columns.tolist()}")
        except Exception as e :
            print(f" ❌ Erreur lors de la sauvegarde du dataset dans {filepath} : \n {type(e).__name__} - {e} \n {traceback.format_exc()}")

    def save_model(self, model=None) :
        """ Sauvegarde du model dans un fichier """
        model = model or self.model
        if model is None :
            print("Aucun model à sauvegarder.")
            return
        max_a = 3
        for i in range(max_a):
            try :
                os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
                self.model = model
                features_name = self.features_name
                stack = self.model.named_steps['stack']
                sc = self.model.named_steps['scaler']
                prefit = True
                classes_ = stack.classes_
                stack_method_ = stack.stack_method_
                final_estimator_ = stack.final_estimator_
                named_estimators_ = stack.named_estimators_
                label_encoder = stack._label_encoder
                dic = {
                        "mlb" : self.mlb,
                        "scaler":sc,
                        "classes_":classes_,
                        'features_name': features_name,
                        'final_estimator_':final_estimator_,
                        "named_estimators_":named_estimators_,
                        'prefit':int(prefit),
                        'stack_method_':stack_method_,
                        '_label_encoder':label_encoder
                    }
                mod_file = self.model_file
                # print(dic, model, self.model)
                
                with open(mod_file, "wb") as f:
                    if self.compress:
                        try:
                            com = zstd.ZstdCompressor(level=self.compression_level)
                            compress = com.stream_writer(f)
                            dill.dump(dic, compress, protocol=4, recurse=True)
                            compress.flush()
                            compress.close()
                        except Exception as e:
                            print('Erreur zstd : ', e)
                            dill.dump(dic, f, protocol=4, recurse=True)
                    else:
                        dill.dump(dic, f, protocol=4, recurse=True)
                try:
                    if os.path.exists(mod_file):
                        size = os.path.getsize(mod_file)
                        if size > 0:
                            size_mb = size / (1024 * 1024)
                            print('Taille de la sauvegarde : ', size_mb)
                            self.size_mb = size_mb
                        else:
                            print("Fichier vide après sauvegarde !")
                    else:
                        print('Fichier inexistant !')
                except Exception:
                    pass
                        
                # joblib.dump(dic,mod_file, compress=5)
                print(f" ✅ Model sauvegardé dans {self.model_file}.")
                break
            except Exception as e :
                print(f'Tentative de sauvegarde {i+1}/{max_a}')
                if i == max_a - 1:
                    print(f" ❌ Erreur lors de la sauvegarde du model dans {self.model_file} : \n {type(e).__name__} - {e} \n {traceback.format_exc()}")

    def load_model(self,model_file) :
        """ Chargement du model depuis un fichier """
        if os.path.exists(model_file) :
            try :
                # data = joblib.load(model_file)
                with open(model_file, 'rb') as f:
                    if self.compress:
                        try:
                            decom = zstd.ZstdDecompressor()
                            decompress = decom.stream_reader(f)
                            data = dill.load(decompress)
                        except Exception as e:
                            print('Erreur décompresseion zstd : ', e)
                            data = dill.load(f)
                    else:
                        data = dill.load(f)
                if not data :
                    return
                self.features_name = data.get('features_name', features_name)
                self.mlb = data.get('mlb',MultiLabelBinarizer(classes=self.classes))
                classes_ = data.get('classes_',[0,1])
                final_estimator_ =  data.get('final_estimator_')
                named_estimators_ = data.get("named_estimators_")
                stack_method_ = data.get('stack_method',["predict_proba"] * len(named_estimators_))
                scaler = data.get('scaler')
                prefit = data.get('prefit', 1)
                _label_encoder = data.get('_label_encoder')
                if not all(c for c in (final_estimator_,named_estimators_,scaler,_label_encoder)):
                    raise ValueError('[LOAD_MODEL] Un élément est absent')
                estimators = [(k,v) for k,v in named_estimators_.items()]
                stack = StackingClassifier(
                    estimators=estimators,
                    final_estimator=final_estimator_,
                    stack_method=stack_method_,
                    cv='prefit' if prefit else 2,
                    n_jobs=-1,
                    passthrough=True
                    )
                setattr(stack, "named_estimators_", named_estimators_)
                setattr(stack, 'classes_', classes_)
                setattr(stack, "estimators_", list(named_estimators_.values()))
                setattr(stack, "final_estimator_", final_estimator_)
                setattr(stack, "stack_method_", stack_method_)
                setattr(stack, "_label_encoder", _label_encoder)

                pip = Pipeline([
                    ('scaler', scaler),
                    ('stack',stack)
                    ])
                self.model = pip
                self.scaler = scaler
                self.features_name = features_name
                print(f" ✅ Model chargé depuis {model_file}.")
                return pip
            except Exception as e :
                print(f" ❌ Erreur lors du chargement du model depuis {model_file} : \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
                return None
        else :
            print(f" 📁 Aucun model trouvé à {model_file}.")
            return None

    def prepa_data(self,data,mode, smote=True):
        if isinstance(data, (pd.DataFrame,np.ndarray,pd.Series)):
            if data.empty:
                raise ValueError('Data vide')
        else:
            if not data:
                raise ValueError('Data vide')
        p = pd.DataFrame(data)
        if 'label' not in p.columns and mode == 'fit':
            raise ValueError("La colonne 'label' est requise en mode 'fit'")
        if 'label' in p.columns:
            p['label'] = p['label'].apply(lambda x: x if isinstance(x, list) else [str(x),])

        missing_cols = [c for c in self.features_name if c not in p.columns]
        if missing_cols :
           print(f"⚠️ Colonnes manquantes détectées : {missing_cols}")
           if self.auto_fill_missing:
               print("✅ Auto-remplissage activé: création des colonnes manquantes avec valeur 0")
               for col in missing_cols:
                   p[col] = 0
           else :
                raise ValueError((f"Colonnes manquantes dans les données: {missing_cols}"))
        # p = p[self.features_name + (['label'] if 'label' in p.columns else [])]
        if mode == 'fit':
            # Ajout des nouvelles données dans le dataset global
            if self.df.empty:
                self.df = p
            else :
                all_row_in = p.apply(lambda r: ((r == self.df).all(axis=1)).all(),axis=1).all()
                if all_row_in or self.df.equals(p):
                # if self.df.equals(p) :
                    print("⚠️ Les nouvelles données sont déjà présentes dans le dataset. Aucune concaténation effectuée.")
                else:
                    self.df = pd.concat((self.df, p), axis=0, ignore_index=True)
                    self.df.drop_duplicates(subset=['url'] ,ignore_index=True)
            self.save_dataset(self.dataset_file)
            for col in ('grade','score_total','url'):
                if col in self.df.columns:
                    self.df = self.df.drop(col,axis=1)
            print(self.df.head(3))
            y = self.mlb.transform(
                self.df.loc[:,'label'].apply(lambda x: x if isinstance(x, list) else [x]).to_list()
            )
            X = self.df.drop(['label'], axis=1)
#             print("Y début", self.df.loc[:,'label'])
            if X.isna().sum().sum() != 0:
                print("Imputation", X.isna().sum().sum())
                X_imputed = self.imputer.fit_transform(X=X)
                print(pd.DataFrame(X_imputed).isna().sum().sum())
            else:
                print('Imputation désactivée')
                X_imputed = X
            if smote:
                X_, y_ = self.smote(pd.DataFrame(X_imputed), pd.DataFrame(y))
            else :
                print('Smote désactivée')
                X_, y_ = pd.DataFrame(X_imputed), pd.DataFrame(y)
            y_ = y_.to_numpy()
#             print('Y apres transform de mlb', y)
            print(y.shape)
#             input()
            return X_ , y_
        elif mode == 'predict':
            for col in ('grade','score_total','url'):
                if col in self.df.columns:
                    self.df = self.df.drop(col,axis=1)
            # En mode prédiction, 'label' peut être absent
            # Si 'label' est fourni (cas test/évaluation),  on le renvoie, sinon None
            if 'label' in p.columns:
                y = self.mlb.transform(p['label'].tolist())
                X = p.drop(['label'], axis=1)
            else:
                y = None
                X = p
            return X, y

    def _validate_data_size(self, X, y):
        """Valide que le dataset est suffisamment grand pour l'entraînement"""
        X,y = np.asarray(X),np.asarray(y)
        n_samples = len(X)
        n_classes = len(self.classes)
        min_samples = n_classes * 5  # Au moins 5 échantillons par classe
        if n_samples < min_samples:
            raise ValueError(
                f"Dataset trop petit : {n_samples} échantillons pour {n_classes} classes. "
                f"Minimum requis : {min_samples} échantillons (5 par classe)."
            )
        return True

    def fit(self, data, smote=False, _all_=True):
        try:
            X, y = self.prepa_data(data, 'fit',smote=smote)
            print("Shapes avant fit:", X.shape, y.shape)
            X_train, y_train = X, y
            self._validate_data_size(X, y)
        except Exception as e:
            print(f"Erreur lors de la préparation des données (FIT): \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None
        # from sklearn.model_selection import StratifiedKFold
        # cv_bin = StratifiedKFold(n_splits=3,random_state=self.random_state,shuffle=True)
        model_stack = ModelStack(X=X_train,y=y_train,n_features=self.n_features,method='multi_label',output='chain',
                                 learning_rate=self.learning_rate,cv=2,random_state=self.random_state)
        stack = model_stack.run(n_iter=5, manual_label=True, n_classes=len(self.classes))
        pip = Pipeline(
            steps=[
                # ('imputer',self.imputer),
                ('scaler',self.scaler),
                ('stack',stack)
            ]
            )
        model_optimize = ModelOptimization(pip,X,y,scoring=self.scoring,save_dir=self.save_dir,cv=2,features_name=self.features_name,random_state=self.random_state)
        for _ in tqdm(range(1),desc='🔄 Entraînement du Pipeline'):
            model_fit,test_x,test_y = model_optimize.run(save_func={"fonction": self.save_model}, _all_=_all_)
        self.model_optimize = model_optimize
        self.model = model_fit
        self.save_model(self.model)
        self.evaluate_model(self.model, test_x, test_y)

    def evaluate_model(self,model,X,y):

        X,y = np.asarray(X),np.asarray(y)
        y_pred = model.predict(X)
        label = 'SC_test'
        metrics = self.model_optimize._compute_detailed_metrics(y,y_pred,prefix='')
        score,report,matrix = self.model_optimize.matrix_and_report(model,X,y,from_='Matrix and Report sur X_test  et y_test ')
        metrics_df = pd.DataFrame([metrics],index=['Test'])

        metrics_df.to_csv(os.path.join(self.model_optimize.save_dir, f'evaluation_detailed_{label}.csv'), index=True)
        print(f'Évaluation détaillée sauvegardée dans {os.path.join(self.model_optimize.save_dir, f"evaluation_detailed_{label}.csv")}')
        print(f"Métriques détaillées : \n {metrics_df}")
        return score, report, matrix,metrics_df

    def predict(self, data):
        try:
            X, y_true = self.prepa_data(data, 'predict')
        except Exception as e:
            print(f" ❌ Erreur lors de la préparation des données (PREDICT): \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None
        if self.model is None:
            print(" ⚠️ Aucun modèle chargé pour la prédiction.")
            return None
        y_pred = np.array(self.model.predict(X))
        y_pred_proba = np.array(self.model.predict_proba(X)).astype(float)
        cols = self.mlb.classes_
        pred_transformed = self.mlb.inverse_transform(y_pred)
        pred_transformed = [list(t) if t else ['safe'] for t in pred_transformed ]
        predict_proba = {i: dict(zip(cols, row)) for i, row in enumerate(y_pred_proba)}
        predict_labels = {i: label for i, label in enumerate(pred_transformed)}
        true_labels = {i: label for i, label in enumerate(self.mlb.inverse_transform(y_true))} if y_true is not None else {}

        return {
            "predict_proba": predict_proba,
            "predict": predict_labels,
            "true_labels": true_labels
        }

if __name__ == '__main__':
    dir_ = "/home/hounsousamuel/PROJET/scanner/ml_model/web_vulns_single_label_50k.pkl"
    dir_ = "/home/hounsousamuel/dataset_test.pkl"
    sc = ScannerIA(model_dir='model_test', model_file='model_scan.pkl', cv=2, learning_rate=0.01, dataset_file='dataset1.pkl',
                   features_name=features_name, n_features=len(features_name), auto_fill_missing=True, save_dir='sam_test')
    df = pd.DataFrame(joblib.load(dir_))
    data, data_ = tts(df,test_size=0.1)
    print(df.columns)
    print(data_.shape,data.shape)
    # input()
    joblib.dump(data_, '/home/hounsousamuel/PROJET/scanner/ml_model/dataset_test_df6.pkl')
    shape = data.shape
    print("Shape original : ",df.shape)
    # while True:
    #     inp = input('Nombre de division : ')
    #     print("shape avec : ", data.shape[0]//int(inp))
    #     inp_ = input('D\'accord ? :').strip().lower()
    #     if inp_ in ('oui','yes'):
    #         break
        # shape[0]//int(inp)
    
    print(data[data == data.isna()])
    sc.fit(data.sample(500), False, _all_=False)
