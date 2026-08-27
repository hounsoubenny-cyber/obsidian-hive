

from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier,ExtraTreesClassifier,StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold,train_test_split
from skopt import BayesSearchCV
from skopt.space import Real, Integer
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
from sklearn.preprocessing import RobustScaler
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import pandas as pd
from sklearn.datasets import make_classification

X,y = make_classification()
scaler = RobustScaler()
imputer = IterativeImputer()
random_state = 42
learning_rate = 0.01
cv = StratifiedKFold(n_splits=2)
""" Construction du pipeline avec sklearn.pipeline """
rf = RandomForestClassifier(n_estimators=100,max_depth=None,class_weight='balanced',n_jobs=-1,random_state=random_state)
xgb = XGBClassifier(n_estimators=100,max_depth=5,learning_rate=learning_rate,random_state=random_state,n_jobs=-1,tree_method='hist')
lgbm = LGBMClassifier(n_estimators=100,num_leaves=20,learning_rate=learning_rate,n_jobs=-1,verbose=-1,class_weight='balanced',random_state=random_state)
extra = ExtraTreesClassifier(n_estimators=100,n_jobs=-1,max_depth=None,random_state=random_state,class_weight='balanced')
meta = LogisticRegression(max_iter=1500,n_jobs=-1,random_state=random_state,class_weight='balanced')
estimators = [
    ('rf',rf),
    ('xgb',xgb),
    ('lgbm',lgbm),
    ("extra_tree",extra)
]
param_grid = {
            'Stack__rf__n_estimators':Integer(300,700,prior='log-uniform'),

            'Stack__xgb__learning_rate':Real(1e-5,1e-4,prior='log-uniform'),
        }
stacking = StackingClassifier(estimators=estimators,final_estimator=meta,n_jobs=-1,cv=cv)
pip  = Pipeline(steps=[
    ('KNNImputer',imputer),
    ('RobustScaler',scaler),
    ('Stack',stacking)
                ])
scoring = {'accuracy': 'accuracy', 'f1' : 'f1',"recall":"recall","precision":"precision","roc_auc":"roc_auc"}

bayes = BayesSearchCV(pip,search_spaces=param_grid,scoring="recall",n_jobs=-1,n_iter=20,cv=cv,random_state=random_state)

import time
a = time.time()
X_train,X_test,y_train,y_test = train_test_split(X,y,random_state=random_state)
bayes.fit(X=X_train,y=y_train)
mod = bayes.best_estimator_
print('fit terminé en ',time.time()-a," secondes et les meilleurs paramètres sont : ",bayes.best_params_,'\n les meilleus scores : \n',pd.DataFrame(bayes.cv_results_))
y_pred = mod.predict(X_test)
print("Prédictions : ",y_pred)
print("Score : ",mod.score(X_test,y_test))
