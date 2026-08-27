#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 18 07:21:13 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ============================================
# SUPPRESSION TOTALE DE TOUS LES WARNINGS
# ============================================

import os
import sys
import warnings
import logging

def suppres_warnings():
    # Configuration pour supprimer TOUS les avertissements
    os.environ["PYTHONWARNINGS"] = "ignore"
    
    # Supprimer tous les warnings Python
    warnings.filterwarnings("ignore")
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", category=FutureWarning)
    warnings.filterwarnings("ignore", category=UserWarning)
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    warnings.filterwarnings("ignore", category=ResourceWarning)
    warnings.filterwarnings("ignore", category=ImportWarning)
    warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
    
    # Supprimer les warnings spécifiques à scikit-learn
    warnings.filterwarnings("ignore", module="sklearn")
    warnings.filterwarnings("ignore", message=".*F-score is ill-defined.*")
    warnings.filterwarnings("ignore", message=".*Jaccard is ill-defined.*")
    warnings.filterwarnings("ignore", message=".*ConvergenceWarning.*")
    warnings.filterwarnings("ignore", message=".*UndefinedMetricWarning.*")
    warnings.filterwarnings("ignore", message=".*Stochastic Optimizer.*")
    warnings.filterwarnings("ignore", message=".*Maximum iterations.*")
    warnings.filterwarnings("ignore", message=".*Label .* is present in all training examples.*")
    
    # Supprimer les warnings de PyTorch
    os.environ["TORCH_CPP_LOG_LEVEL"] = "ERROR"
    os.environ["TORCH_DISTRIBUTED_DEBUG"] = "OFF"
    os.environ["TORCH_SHOW_CPP_STACKTRACES"] = "0"
    warnings.filterwarnings("ignore", module="torch")
    
    # Supprimer les warnings de TensorFlow
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
    os.environ["TF_CPP_VLOG_LEVEL"] = "0"
    
    # Supprimer les warnings de XGBoost
    os.environ["XGBOOST_LOG_LEVEL"] = "error"
    os.environ["XGBOOST_SILENT"] = "1"
    
    # Supprimer les warnings de LightGBM
    os.environ["LIGHTGBM_LOG_LEVEL"] = "error"
    os.environ["LIGHTGBM_SILENT"] = "1"
    
    # Supprimer les warnings de Joblib
    os.environ["JOBLIB_LOG_LEVEL"] = "ERROR"
    os.environ["JOBLIB_MULTIPROCESSING"] = "0"
    
    # Supprimer les warnings de NumPy
    os.environ["NUMPY_EXPERIMENTAL_ARRAY_FUNCTION"] = "0"
    warnings.filterwarnings("ignore", message=".*numpy.dtype size changed.*")
    warnings.filterwarnings("ignore", message=".*numpy.ufunc size changed.*")
    
    # Supprimer les warnings de Pandas
    os.environ["PANDAS_WARNINGS"] = "ignore"
    warnings.filterwarnings("ignore", module="pandas")
    warnings.filterwarnings("ignore", message=".*DataFrame is highly fragmented.*")
    
    # Supprimer les warnings de Matplotlib
    os.environ["MPLBACKEND"] = "Agg"
    warnings.filterwarnings("ignore", module="matplotlib")
    logging.getLogger("matplotlib").setLevel(logging.ERROR)
    logging.getLogger("matplotlib.font_manager").disabled = True
    
    # Supprimer les warnings d'Optuna
    warnings.filterwarnings("ignore", module="optuna")
    os.environ["OPTUNA_LOG_LEVEL"] = "ERROR"
    
    # Supprimer les logs de toutes les bibliothèques
    for logger_name in [
        "sklearn", "matplotlib", "optuna", "joblib", "numpy", "pandas",
        "urllib3", "requests", "PIL", "tensorflow", "xgboost", "lightgbm",
        "torch", "torchvision", "transformers", "datasets", "huggingface",
        "numexpr", "boto3", "botocore", "s3transfer", "s3fs", "fsspec",
        "asyncio", "aiohttp", "chardet", "charset_normalizer", "idna",
        "certifi", "urllib3.connectionpool", "PIL.PngImagePlugin", "PIL.TiffImagePlugin"
    ]:
        logging.getLogger(logger_name).setLevel(logging.ERROR)
        logging.getLogger(logger_name).disabled = True
        logger = logging.getLogger(logger_name)
        logger.handlers = []
        logger.propagate = False
    
    # Désactiver complètement le système de logging
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger().setLevel(logging.ERROR)
    logging.getLogger().disabled = False  # Ne pas désactiver complètement pour garder tes logs
    
    # Supprimer les warnings système
    sys.stderr = open(os.devnull, 'w') if not sys.stdout.isatty() else sys.stderr
    sys.warnoptions = []
    warnings.simplefilter("ignore")
    