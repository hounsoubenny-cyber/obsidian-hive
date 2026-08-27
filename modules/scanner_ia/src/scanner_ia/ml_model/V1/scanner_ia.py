
import os, sys, joblib, pandas as pd, numpy as np, tensorflow as tf
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  
sys.path.append("/home/hounsousamuel/PROJET")
from rules.rules1 import RulesManager
from mlsmote import MLSMOTE
from iterstrat.ml_stratifiers import MultilabelStratifiedKFold
#from imblearn.over_sampling import RandomOverSampler
from sklearn.calibration import CalibratedClassifierCV 
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier,HistGradientBoostingClassifier,ExtraTreesRegressor,StackingClassifier
from skopt import BayesSearchCV
from skopt.space import Real, Integer
from sklearn.metrics import classification_report,confusion_matrix
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
from sklearn.preprocessing import RobustScaler,MultiLabelBinarizer
from skmultilearn.problem_transform import ClassifierChain
from sklearn.multiclass import OneVsRestClassifier as MOP
#from sklearn.multioutput import ClassifierChain
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from tqdm import tqdm
from tensorflow.keras.layers import Dense,Dropout,BatchNormalization,Input
from tensorflow.keras.models import Sequential,load_model as lm
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam
from scikeras.wrappers import KerasClassifier
from modeloptimize import ModelOptimization
import traceback

dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),'data')
os.makedirs(dir, exist_ok=True)
rules = RulesManager(rules_file="signatures3.json",password_file="password.txt")
classes = rules.list_vulnerabilities()
features_name = []
rules.js_parser
def get_features_name(X) :
    """ Recuperation des noms des features """
    if isinstance(X,pd.DataFrame) :
        features_name_ = X.columns.tolist()
    elif isinstance(X,np.ndarray) :
        features_name_ = features_name
    return features_name_

class ScannerIA:
    def __init__(self, model_dir='model0',dataset_file='dataset.joblib', model_file='model.joblib', deep_file='deep_model.keras',classes=classes, n_features=20, cv=5, 
                 scoring={}, random_state=42, learning_rate=0.01, save_dir='sam0',min_gain=0.01, min_features_ratio=0.1,features_name=features_name):
        
        self.dataset_file = os.path.join(dir,'datasets',dataset_file) 
        self.model_file = os.path.join(dir,'models', model_dir , model_file)
        self.deep_file = os.path.join(dir,'models', model_dir , deep_file)
    
        self.classes = classes
        self.scoring = scoring or ['f1_samples', 'accuracy', 'precision_samples', 'recall_samples']
        self.random_state = random_state
        self.save_dir = save_dir
        self.min_gain = min_gain
        self.learning_rate = learning_rate
        self.min_features_ratio = min_features_ratio
        self.df = pd.DataFrame({})
        
        os.makedirs(os.path.dirname(self.dataset_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.deep_file), exist_ok=True)
        self.load_dataset(self.dataset_file)
        
        if not self.df.empty and 'label' in self.df.columns:
            self.features_name = get_features_name(self.df.drop(['label'],axis=1))
            self.n_features = self.df.shape[1] - 1
        else:
            self.features_name = features_name
            self.n_features = n_features
            
        self.imputer = IterativeImputer(random_state=self.random_state,estimator=ExtraTreesRegressor(n_estimators=250,n_jobs=-1))
        self.scaler = RobustScaler()
        self.cv = MultilabelStratifiedKFold(n_splits=min(cv,3), shuffle=True, random_state=self.random_state)
        self.smote = MLSMOTE
        self.mlb = MultiLabelBinarizer(classes=self.classes)
        self.mlb.fit([])
        
        self.model = None
        self.bayes = None
        self.mask = None
        self.param_grid = {}
        self.build_param_grid()
        self.build_pipeline(learning_rate)  
        self.load_model(self.model_file,self.deep_file)
        print(f"ScannerIA initialisé avec {self.n_features} features, minimum de features à selectionner : {max(int(self.n_features/4),int(self.n_features*self.min_features_ratio))}, dataset dans {self.dataset_file}, model dans {self.model_file}, model deep dans {self.deep_file}")
        
    def load_dataset(self,filepath) :
        """ Chargement du dataset depuis un fichier """
        if os.path.exists(filepath) :
            try :
                self.df = pd.DataFrame(joblib.load(filepath))
                if 'label' not in self.df.columns :
                    raise ValueError(f"Le dataset doit contenir une colonne 'label'")
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
              
    def save_model(self,model=None,mask=None) :
        """ Sauvegarde du model dans un fichier """
        model = model or self.model
        if model is None :
            print("Aucun model à sauvegarder.")
            return
        try :
            deep = None
            if hasattr(model.named_steps['Stack'].estimators_[-1], 'model_'):
                os.makedirs(os.path.dirname(self.deep_file), exist_ok=True)
                deep = model.named_steps['Stack'].estimators_[-1].model_
            if deep is not None :
                deep.save(self.deep_file)
                print(f" ✅Model deep learning sauvegardé dans {self.deep_file}.")
            model.named_steps['Stack'].estimators_[-1] = None # Remplacer le model keras par None pour la sérialisation
            os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
            joblib.dump({'model': model, 'mask': mask, 'classes': self.mlb.classes_, 'features': self.features_name}, self.model_file)
            print(f" ✅ Model sauvegardé dans {self.model_file}.")
            
        except Exception as e :
            print(f" ❌ Erreur lors de la sauvegarde du model dans {self.model_file} : \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
            
    def load_model(self,model_file,deep_file) :
        """ Chargement du model depuis un fichier """
        if os.path.exists(model_file) :
            try :
                data = joblib.load(model_file)
                if not data :
                    return 
                model = data['model']
                self.mask = data.get('mask', None)
                self.mlb.classes_ = data.get('classes', self.classes)
                self.features_name = data.get('features', features_name)
                if os.path.exists(deep_file) :
                    deep = lm(deep_file)
                    model.named_steps['Stack'].estimators_[-1].model_ = deep
                    print(f" ✅ Model deep learning chargé depuis {deep_file}.")
                self.model = model
                self.bayes = BayesSearchCV(model,search_spaces=self.param_grid,scoring=self.scoring,n_jobs=-1,n_iter=25,cv=self.cv,random_state=self.random_state)       
                print(f" ✅ Model chargé depuis {model_file}.")
                return model
            except Exception as e :
                print(f" ❌ Erreur lors du chargement du model depuis {model_file} : \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
                return None
            
        else :
            print(f" 📁 Aucun model trouvé à {model_file}.")
            return None
        
    def build_deep_model(self, n_features, n_classes,learning_rate=0.001):
        """ Construction d'un model deep learning avec keras """
        model = Sequential()
        model.add(Input(shape=(n_features,)))
        model.add(Dense(128, activation='swish'))
        model.add(BatchNormalization())
        model.add(Dropout(0.3))
        model.add(Dense(64, activation='swish'))
        model.add(BatchNormalization())
        model.add(Dropout(0.3))
        model.add(Dense(32, activation='swish'))
        model.add(BatchNormalization())
        model.add(Dropout(0.3))
        model.add(Dense(1, activation='sigmoid'))
        model.compile(optimizer=Adam(learning_rate=learning_rate), loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def build_pipeline(self, learning_rate):
        """Construction du pipeline avec sklearn.pipeline"""
        
        # CORRECTION: Utiliser OneVsRestClassifier avec un estimateur simple
        # au lieu de StackingClassifier compliqué
        
        rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            class_weight='balanced',
            n_jobs=-1,
            random_state=self.random_state
        )

        xgb = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            objective='binary:logistic',
            learning_rate=learning_rate,
            tree_method='hist',
            n_jobs=-1,
            random_state=self.random_state
        )

        lgbm = LGBMClassifier(
            n_estimators=300,
            num_leaves=40,
            learning_rate=learning_rate,
            verbose=-1,
            max_depth=-1,
            objective="binary",
            n_jobs=-1,
            random_state=self.random_state
        )

        # Utiliser un seul estimateur robuste au lieu de stacking complexe
        base_estimator = lgbm  # LightGBM est excellent pour le multi-label

        # Wrapper pour multi-label
        multi_label_clf = MOP(rf , n_jobs=-1)

        pip = Pipeline(steps=[
            ('Imputer', self.imputer),
            ('Scaler', self.scaler),
            ('Stack', multi_label_clf)
        ])

        self.bayes = BayesSearchCV(
            pip,
            search_spaces=self.param_grid,
            scoring='f1_weighted',
            n_jobs=-1,
            refit='f1_weighted',
            n_iter=10,  # Réduire pour accélérer les tests
            cv=self.cv,
            random_state=self.random_state,
            verbose=1
        )

    def build_param_grid(self):
        """Construction de la grille de parametres pour BayesSearchCV"""
        # CORRECTION: Simplifier la grille de paramètres
        self.param_grid = {
            'Stack__estimator__n_estimators': Integer(200, 500),
            
        }
        
    def prepa_data(self,data,mode):
        if not data:
            raise ValueError('Data vide')
        
        p = pd.DataFrame(data)
        if 'label' not in p.columns and mode == 'fit':
            raise ValueError("La colonne 'label' est requise en mode 'fit'")
        if 'label' in p.columns:
            p['label'] = p['label'].apply(lambda x: x if isinstance(x, list) else [x])
    
        missing_cols = [c for c in self.features_name if c not in p.columns]
        if missing_cols :
            print(f"Colonnes manquantes détectées : \n {missing_cols}.\n Ils seront creer et rempli de 0 pour eviter des bugs si vous le voulez(oui) ou alors une erreur sera levéé")
            inp = input('Votre choix : ') 
            if inp.strip().lower() in ('oui','yes'):           
                for col in missing_cols:
                    p[col] = 0 
            else :
                raise ValueError((f"Colonnes manquantes dans les données: {missing_cols}"))
        p = p[self.features_name + (['label'] if 'label' in p.columns else [])]
        
        if mode == 'fit':
            # Ajout des nouvelles données dans le dataset global
            if self.df.empty:
                self.df = p
            else :
                
                if self.df.equals(p) :  
                    print("⚠️ Les nouvelles données sont déjà présentes dans le dataset. Aucune concaténation effectuée.")
                else:
                    self.df = pd.concat((self.df, p), axis=0, ignore_index=True)
                    #print(self.df)
                    self.df['label'] = self.df['label'].apply(lambda x : ','.join(x))
                    #print(self.df)
                    self.df = self.df.drop_duplicates(ignore_index=True)
                    #print(self.df)
                    self.df['label'] = self.df['label'].apply(lambda x : x.strip().split(','))
                    #print(self.df)
            print(self.df)       
            self.save_dataset(self.dataset_file)
            # Préparer X et y pour l'entraînement
            #print('Y : ',self.df.loc[:,'label'].apply(lambda x: x if isinstance(x, list) else [x]).to_list())
            y = self.mlb.transform(
                self.df['label'].apply(lambda x: x if isinstance(x, list) else [x]).to_list()
            )
            X = self.df.drop(['label'], axis=1)
            
            X_, y_ = self.smote(X, pd.DataFrame(y))
            return X_ , y_.to_numpy()
            
            
        
        elif mode == 'predict':
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
        n_samples = len(X)
        n_classes = len(np.unique(y, axis=0))
        min_samples = n_classes * 5  # Au moins 5 échantillons par classe
        
        if n_samples < min_samples:
            raise ValueError(
                f"Dataset trop petit : {n_samples} échantillons pour {n_classes} classes. "
                f"Minimum requis : {min_samples} échantillons (5 par classe)."
            )
        
        return True
    
    def fit(self, data):
        try:
            X, y = self.prepa_data(data, 'fit') 
            print("Shapes avant fit:", X.shape, y.shape)
            self._validate_data_size(X, y)         
        except Exception as e:
            print(f"Erreur lors de la préparation des données (FIT): \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None
            
        model_optimize = ModelOptimization(self.bayes,X,y,random_state=self.random_state,scoring=self.scoring,save_dir=self.save_dir,min_gain=self.min_gain,
                                          min_features_ratio=self.min_features_ratio,cv=self.cv,features_name=self.features_name)
        for _ in tqdm(range(1),desc='🔄 Entraînement des modèles'):
            bayes,mask,test_x,test_y = model_optimize.run()
        self.bayes = bayes
        self.model = bayes.best_estimator_
        self.mask = mask
        self.save_model(self.model,mask)
        print(f"✅ Meilleurs paramètres : {bayes.best_params_}")
        print(f"✅ Meilleur score CV : {bayes.best_score_}")
        self.evaluate_model(self.model, test_x, test_y)
        model_optimize.evaluate(self.model, test_x, test_y, label='final', mask=mask)
    
    def evaluate_model(self,model,X,y):
        y_pred = model.predict(X)
        score = model.score(X, y)
        report = classification_report(y, y_pred)
        matrix = confusion_matrix(y, y_pred)
        print(f"🎯 Score test : {score}")
        print("📊 Rapport de classification :\n", report)
        print("🧩 Matrice de confusion :\n", matrix)
        return score, report, matrix
    
    def predict(self, data):    
        try:
            X, y_true = self.prepa_data(data, 'predict')
        except Exception as e:
            print(f" ❌ Erreur lors de la préparation des données (PREDICT): \n {type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None
        if self.model is None:
            print(" ⚠️ Aucun modèle chargé pour la prédiction.")
            return None
        if self.mask is not None and X.shape[1] == len(self.mask):
            X = X.loc[:, self.mask] if isinstance(X, pd.DataFrame) else X[:, self.mask]
        
            
        y_pred = np.array(self.model.predict(X))
        y_pred_proba = np.array(self.model.predict_proba(X)).astype(float)
        cols = self.mlb.classes_

        predict_proba = {i: dict(zip(cols, row)) for i, row in enumerate(y_pred_proba)}
        predict_labels = {i: label for i, label in enumerate(self.mlb.inverse_transform(y_pred))}
        true_labels = {i: label for i, label in enumerate(self.mlb.inverse_transform(y_true))} if y_true is not None else {}

        return {
            "predict_proba": predict_proba,
            "predict": predict_labels,
            "true_labels": true_labels
        }
    