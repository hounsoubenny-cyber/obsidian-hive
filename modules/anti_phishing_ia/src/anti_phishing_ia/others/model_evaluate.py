#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Oct 25 20:38:59 2025

@author: hounsousamuel
"""

# Model fitting after trainning

import pandas as pd
from sklearn.model_selection import cross_val_predict, cross_validate, train_test_split as tts, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.datasets import make_classification
from sklearn.ensemble import HistGradientBoostingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
import joblib, os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from anti_phishing.ml_model.modeloptimize import compute_metrics_safe, ModelOptimization
from datetime import datetime
from anti_phishing.ml_model.phishing_ia import PhishingIA, features_name
import matplotlib.pyplot as plt, json

class ModelEvaluate:
    def __init__(self):
        pass

    def load_dataset(self, filename):
        try:
            data = joblib.load(filename)
            data = pd.DataFrame(data)
            return data
        except Exception as e:
            print("Erreur lors du chargement : ", e)

    def validate(self, model, X, y, cv=2):
        cv = StratifiedKFold(shuffle=True, random_state=42, n_splits=cv)
        scoring = ['accuracy','f1', 'recall', 'precision', 'roc_auc']
        filename = "/home/hounsousamuel/PROJET/anti_phishing/ml_model/evaluate"
        os.makedirs(filename, exist_ok=True)
        date = datetime.now().isoformat()
        try:
            print("Cross validate ... ")
            results = cross_validate(estimator=model, cv=cv, n_jobs=-1, return_train_score=True, scoring=scoring, X=X, y=y, verbose=1)
            frame1 = pd.DataFrame(results)
            frame1.loc['mean'] = frame1.mean()
            fileframe1 = os.path.join(filename, f'cross_validate_{date}.')
            frame1.to_csv(fileframe1 + "csv")
            frame1.to_json(fileframe1 + "json")
            print(frame1)
            print()
        except Exception as e:
            print('Erreur lors de la cross_validate : ', e)

        try:
            print('Cross val predict (predict) ... \n')
            predicts = cross_val_predict(model, X=X, y=y, cv=cv, method='predict', n_jobs=-1, verbose=1)
            predicts_proba = cross_val_predict(model, X=X, y=y, cv=cv, method='predict_proba', n_jobs=-1, verbose=1)
            proba_positive = predicts_proba[: ,1]
            metrics = compute_metrics_safe(y_true=y, y_pred=predicts, y_pred_proba=predicts_proba)
            labels = LabelEncoder().fit(['safe', 'phishing']).classes_
            confusion = confusion_matrix(y_true=y, y_pred=predicts)
            print("Confusion matrix : \n", confusion, '\n')
            cm = ConfusionMatrixDisplay(confusion_matrix=confusion, display_labels=labels)
            cm.plot(cmap='Blues')
            plt.title('Confusion matrix')
            cl = classification_report(y_true=y, y_pred=predicts)
            print('Classification report : \n ', cl, '\n')
            frame2 = pd.DataFrame([metrics])
            fileframe2 = os.path.join(filename, f'cross_val_predict_{date}.')
            frame2.to_csv(fileframe2 + "csv")
            frame2.to_json(fileframe2 + "json")
            print()
            print(frame2)
            plt.show(block=True)
        except Exception as e:
            print('Erreur lors de la cross_val_predict_ : ', e)
            import traceback
            print(traceback.format_exc())

if __name__ == '__main__':
    X, y = make_classification(n_features=10,n_samples=10000, random_state=42)
    sc = StandardScaler()
    X = sc.fit_transform(X)
    model = StackingClassifier(
        n_jobs=-1,
        cv=2,
        estimators=[('hgbc', HistGradientBoostingClassifier(max_iter=1000, max_depth=10, class_weight='balanced',
                                                            early_stopping=True, n_iter_no_change=20)),
                    ('tree', DecisionTreeClassifier(max_depth=5, class_weight='balanced'))],
        final_estimator=LogisticRegression(),
        stack_method='predict_proba', passthrough=True
        )

    # 1model.fit(X, y)
    MO = ModelEvaluate()
    # MO.validate(model, X, y, 3)
    # from modeloptimize import ModelOptimization, compute_metrics_safe
    # from sklearn.model_selection import train_test_split as tts
    ph = PhishingIA(features_name=features_name, n_features=len(features_name),cv=3,
                    learning_rate=0.001,dataset_file='dataset.pkl',model_file='model_phish.pkl',
                    auto_fill_missing=True,model_dir_='model10',save_dir='sam11' )
    
    print(len(ph.model.named_steps['stack'].estimators_))
    print(ph.model.named_steps['stack'].estimators_)
    print(ph.model.named_steps['stack'].final_estimator_)
    input()
    
    test_ = joblib.load('/home/hounsousamuel/PROJET/anti_phishing/ml_model/dataset_test_df6.pkl')
    test = test_.to_dict(orient='records')
    if not isinstance(test, list):
        test = [test]
    test = test[:len(test)]
    y = ph.le.fit_transform(test_['label'])
    X = test_.drop(['label','url'],axis=1)
    y_pred = ph.model.predict(X)
    y_proba = ph.model.predict_proba(X)
    mo = ModelOptimization(ph.model, X=[[],[]], y=[], random_state=2)
    mo.matrix_and_report(ph.model, X, y_test=y)
    # X_train, X_val, y_train, y_val = tts(X, y, test_size=0.2)
    # mo.evaluate(ph.model, X_train, y_train, X_val, y_val)
    print(pd.DataFrame(compute_metrics_safe(y,y_pred,y_proba),index=['Test']))
    input()
    MO.validate(model, X, y, 3)
    # test.insert(0, 'http://cutt/5dv')
    for r in test:
        if not isinstance(r, list):
            r = [r]
        print(json.dumps(ph.predict(r),indent=2,ensure_ascii=False))
        input()
    print(json.dumps(ph.predict(test),indent=2,ensure_ascii=False))
    input()
