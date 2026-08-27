#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 15 07:19:03 2026

@author: hounsousamuel
"""

import os
from scanner_ia.scanner_utils.warnings_manager import suppres_warnings
suppres_warnings()
import joblib
import pandas as pd
import numpy as np
import traceback
from scanner_ia.scanner_utils.logger import get_logger
from typing import Tuple
from scanner_ia.ml_model.mlsmote import MLSMOTE

# Configuration des logs
datamanager_logger = get_logger()

pd.set_option("display.max_rows", 200)
pd.set_option("display.max_columns", 200)

_DEFAULT_TARGET_FUNC = lambda x: [x] if isinstance(x, (str, int, float)) else x

_LOAD_FUNC = {
    "csv": pd.read_csv,
    "xlsx": pd.read_excel,
    "json": pd.read_json,
    "pkl": pd.read_pickle,
    "joblib": joblib.load,
    "default": pd.read_pickle
    }
class DataManager:
    
    @staticmethod
    def load_dataset(path:str, output:str = "df") -> pd.DataFrame | np.ndarray:
        try:
            if os.path.exists(path):
                ext = os.path.splitext(path)[-1]
                load_func = _LOAD_FUNC.get(ext, _LOAD_FUNC["default"])
                data = load_func(path)
                if output == "df":
                    data = pd.DataFrame(data)
                else:
                    data = np.array(data)
                datamanager_logger.success(f"Dataset chargé avec succès depuis {path} avec pour shape={data.shape}")
                return data
            else:
                datamanager_logger.warning(f"'{path}' inexistant !")
        except Exception as e:
            datamanager_logger.error(f"Erreur lors du chargement du dataset : {str(e)}")
            datamanager_logger.error(f"Traceback : \n {traceback.format_exc()}")
            return pd.DataFrame() if output == "df" else np.array([])
        
    @staticmethod
    def save_dataset(data:pd.DataFrame|np.ndarray, path:str) -> bool:
        try:
            base = os.path.splitext(path)[0]
            data = pd.DataFrame(data)
            pd.to_pickle(data.to_dict(orient="records"), base + ".pkl")
            data.to_csv(base + ".csv", index=False)
            datamanager_logger.success(f"""Données sauvegardé en pkl(dict) et en csv dans {base + ".pkl"} et {base + ".csv"}""")
            return True
        except Exception as e:
            datamanager_logger.error(f"Erreur lors de la sauvegarde des données : {str(e)}")
            datamanager_logger.error(f"Traceback : \n {traceback.format_exc()}")
            return False
    
    def add_data(self, base_data:list[dict]|pd.DataFrame, data:list[dict]|pd.DataFrame, path:str, subset:list[str] = None) -> pd.DataFrame:
        subset = subset or []
        if base_data is None or pd.DataFrame(base_data).empty:
            base_data = data
            self.save_dataset(base_data, path)
            return base_data
        else:
            base_data = pd.DataFrame(base_data)
            data = pd.DataFrame(data)
            union = pd.DataFrame(pd.concat([base_data, data], axis=0))  # Ajouter des lignes
            try:
                union = union.drop_duplicates(inplace=False, keep="last", ignore_index=True, subset=subset if subset else None)
            except KeyError:
                union = union.drop_duplicates(inplace=False, keep="last", ignore_index=True, subset=None)
            self.save_dataset(union, path)
            datamanager_logger.info(
                f"Base data shape = {base_data.shape}\n"
                f"Data shape = {data.shape}\n"
                f"Union data shape = {union.shape}\n"
                f"Subset = {subset}\n"
                )
            datamanager_logger.success("Opération termné avec succès")
            return union
        
    def prepare_data(
        self, 
        data:list[dict]|pd.DataFrame, 
        cols:list[str],
        cols_to_drop:list[str], 
        target:str, 
        target_func:callable = _DEFAULT_TARGET_FUNC,
        restrain_to_cols:bool = False,
        apply_smote:bool = False,
    ) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray|None]:
        """
        

        Parameters
        ----------
        data : list[dict]|pd.DataFrame
            DESCRIPTION.
        cols : list[str]
            DESCRIPTION.
        cols_to_drop : list[str]
            DESCRIPTION.
        target : str
            DESCRIPTION.
        target_func : callable, optional
            DESCRIPTION. The default is _DEFAULT_TARGET_FUNC(lambda x: [x] if isinstance(x, (str, int, float)) else x).

        Returns
        -------
        data : TYPE
            DESCRIPTION.
        X : TYPE
            DESCRIPTION.
        y : TYPE
            DESCRIPTION.

        """
        data = pd.DataFrame(data)
        new_cols = [col for col in cols if col not in data.columns]
        for col in new_cols:
            data.loc[:, col] = 0
        
        if restrain_to_cols:
            data = data.loc[:, cols]
        y = pd.DataFrame()
        X = pd.DataFrame()
        if target in data.columns:
            y = data.loc[:, target]
            X = data.drop(target, axis=1, inplace=False)
        else:
            X = data
        target_func = target_func if target_func else lambda x: x
        y = y.apply(target_func).to_numpy()
        if cols_to_drop:
            X.drop(cols_to_drop, axis=1, inplace=True, errors="ignore")
        X = X.to_numpy()
        if apply_smote:
            X, y = MLSMOTE(k_neighbors=8)(X, y)
        datamanager_logger.info("Traitement des données terminé !")
        return data, X, y
        
if __name__ == "__main__":
    df1 = pd.DataFrame(np.arange(12).reshape(3, 4),
                   columns=['A', 'B', 'C', 'D'])
    
    df2 = pd.DataFrame(np.arange(15).reshape(3, 5),
                   columns=['A', 'B', 'C', 'D', "I"])
    dmanager = DataManager()
    dmanager.save_dataset(df1, path="./test")
    df1 = dmanager.load_dataset("./test.pkl", "df")
    print(dmanager.prepare_data(df1, cols=df2.columns, cols_to_drop=["A"], target="D", restrain_to_cols=True))
    print(dmanager.add_data(df1, df2, path="./merge", subset=""))
        
                
        
            
                
            