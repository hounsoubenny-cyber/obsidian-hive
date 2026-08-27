#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 22 06:53:14 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import joblib
import json
import atexit
from datetime import datetime
from simulateur_attaque_ia.simulateur_utils.logger import get_logger

logger = get_logger()
BASEDIR = os.path.dirname(os.path.abspath(os.path.abspath(__file__)))
LOGDIR = os.path.join(BASEDIR, 'data', 'attack_logs')
os.makedirs(BASEDIR, exist_ok=True)
os.makedirs(LOGDIR, exist_ok=True)

class Base:
    __slots__ = (
        "config", "logs", "start_time", "end_time", "pkl_filename",
        "json_filename"
    )
    def __init__(self, name:str|list, **kwargs):
        self.config = kwargs
        self.logs = []
        self.start_time = time.time()
        self.end_time = time.time()
        name = name if isinstance(name, str) else "_".join(name)
        self.pkl_filename = os.path.join(LOGDIR, name + '.pkl')
        self.json_filename = os.path.join(LOGDIR, name + '.json')
        self.load()
        self.save_atexit()

    def log(self, message, log:bool = False):
        """Ajouter log interne"""
        if log:
            logger.print(message)
        self.logs.append({
            'timestamp': time.ctime(),
            'message': message
        })

    def save(self):
        try:
            joblib.dump(self.logs, self.pkl_filename, compress=5)
            logger.print('Fichier sauvegarder dans : ', self.pkl_filename)
            try:
                with open(self.json_filename, 'w', encoding='utf-8') as f:
                    json.dump(self.logs, f, indent=4, ensure_ascii=False)
                logger.print('Fichier sauvegarder au format json dans : ', self.json_filename)
            except Exception as e:
                logger.print("Erreur de sauvegarde au format json :", str(e))
            return True
        
        except Exception as e:
            logger.print("Erreur lord de la sauvegarde du fichier historique : ", e)
            return False

    def load(self):
        try:
            data = joblib.load(self.pkl_filename)
            self.logs = data or []
            logger.print("Succès du chargelent du fichier historique !")
            return True
        
        except FileNotFoundError:
            pass
        
        except Exception as e:
            logger.print("Erreur lord du chargement du fichier historique : ", e)
            return False

    def save_atexit(self):
        def _save():
            self.save()
            logger.print('Fin sauvegarde !')
        atexit.register(_save)
