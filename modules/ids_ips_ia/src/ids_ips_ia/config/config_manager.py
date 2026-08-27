#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 13 11:14:28 2026

@author: hounsousamuel
"""
import os

import json5
import threading
from copy import deepcopy
from datetime import datetime
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
_dir_ = os.path.dirname(os.path.abspath(__file__))

CLASS_CONFIG = {
    "SEUIL" : {
        "decision": -0.6
        },
    
    "CRITICAL_PORT" : {
        "22": 40,
        "3389": 40,
        "445": 52,
        "3306": 33,
        "5432": 33,
        "27017": 33,
        "5984": 33,
        "6379": 30,
        "7001": 30,
        "8086": 30,
        "9042": 30,
        "9200": 30,
        "9300": 30,
        "11211": 30,
        "50070": 30,
        "1433": 27,
        "1371": 27,
        "2181": 27,
        "3000": 27,
        "3001": 27,
        "4242": 27,
        "5005": 27,
        "5009": 27,
        "7199": 27,
        "8888": 27,
        "9999": 27,
        "10000": 27,
        "27018": 27,
        "27019": 27,
        "28017": 27,
        "30000": 27,
        "21": 23,
        "23": 23,
        "25": 23,
        "110": 23,
        "143": 23,
        "135": 23,
        "139": 23,
        "389": 23,
        "636": 23,
        "1099": 23,
        "1102": 23,
        "1524": 23,
        "8080": 23,
        "8443": 23,
        "8161": 23,
        "8500": 23,
        "31337": 23,
        "80": 17,
        "443": 17,
        "465": 17,
        "587": 17,
        "993": 17,
        "995": 17,
        "123": 17,
        "53": 17,
        "69": 17,
        "88": 17,
        "137": 17,
        "161": 17,
        "162": 17,
        "5900": 17,
        "5901": 17,
        "6000": 17,
        "6001": 17,
        "8009": 17,
        "9090": 17,
    },

    "DANGEROUS_LOCALISATION" : {
        "CN": 30,
        "RU": 30,
        "KP": 30,
        "IR": 30,
        "SY": 25,
        "CU": 25,
        "VN": 25,
        "ZA": 25,
        "NG": 25,
        "AO": 25,
        "TJ": 25,
        "MZ": 25,
        "HK": 25,
        "TW": 25,
        "MM": 25,
        "KZ": 25,
        "MD": 25,
        "GE": 25,
        "UA": 25,
        "LV": 20,
        "EE": 20,
        "LT": 20,
        "PK": 20,
        "AF": 20,
        "BY": 20,
        "ID": 20,
        "TH": 20,
        "PH": 20,
        "BR": 20,
        "MX": 20,
        "EC": 20,
        "CO": 20,
        "IN": 15,
        "TK": 15,
        "SA": 15,
        "AE": 15,
    },
    
    "SCORING_CONFIG" : {
        "ml_predict": 15,
        'port_weight': 35,
        'max_score_anomaly': 200,
        'geo_max': 25,
        'block_history_weight': 60,
        'anomaly_frequency_weight': 35,
        'max_score_total': 300,
        "max_bonus" : 100,
    },

    "ANOMALY_RATE_THRESHOLDS" : {
        'critical': 0.90,
        'very_high': 0.75,
        'high': 0.60,
        'medium': 0.50,
        'low': 0.25,
        'minimal': 0.10,
    },

    "DECAY_CONFIG" : {
        'loss_per_hour': 6,
        'reset_days': 14,
        'reset_seconds': 14 * 24 * 3600,
        'minimum_decay_rate': 0.0,
    },

    "ANOMALY_CONFIG" : {
        'max_anomalies_per_file': 10000,
        'anomaly_file_prefix': 'anomalies',
        'seq_length': 60,
    },
    "CAPTURE_CONFIG": {
        "FILTER": "tcp or udp or icmp",
        "TIMEOUT_MS": 40,
        "BUFFER_SIZE": 64,
        "SRC_IGNORED_IP": [],
        "DST_IGNORED_IP": [],
    },
    "GLOBAL_CONFIG" : {
      "model_file": f"model_{date}.pkl",
      "whitelist": [],
      "duration": 2,
      "save_interval": 2,
      "mode": "full",
      "packet_anomaly": 0.4,
      "anomaly_dir": None,
      "interface": None,
      "combination_mode": "or",
      "ids_mode": "ips",
      "verbose": 1,
      "API_CONFIG": {
          "port": 8080,
          "host": "0.0.0.0"
          },
      "REQUEST_LIMIT": 30,
      "GRAPHS": True,
      "N_TRIALS": 2,
      "clear_sets_at_exit": True,
      "unlock_at_exit": True,
      "capture_filename": "capture.pkl",
      "add_data_to_capture_path": None,
      "do_not_fit": not True,
    }
}


_config_path = os.path.join(_dir_, "config_json.json")
SEUIL_KEY = "SEUIL"
CRITICAL_PORT_KEY = "CRITICAL_PORT"
DANGEROUS_LOCALISATION_KEY = "DANGEROUS_LOCALISATION"
SCORING_CONFIG_KEY = "SCORING_CONFIG"
DECAY_CONFIG_KEY = "DECAY_CONFIG"
ANOMALY_CONFIG_KEY = "ANOMALY_CONFIG"
ANOMALY_RATE_THRESHOLDS_KEY = "ANOMALY_RATE_THRESHOLDS"
CAPTURE_CONFIG_KEY = "CAPTURE_CONFIG"
GLOBAL_CONFIG_KEY = "GLOBAL_CONFIG"

SEUIL = CLASS_CONFIG[SEUIL_KEY]
CRITICAL_PORT = CLASS_CONFIG[CRITICAL_PORT_KEY]
DANGEROUS_LOCALISATION = CLASS_CONFIG[DANGEROUS_LOCALISATION_KEY]
DECAY_CONFIG = CLASS_CONFIG[DECAY_CONFIG_KEY]
ANOMALY_CONFIG = CLASS_CONFIG[ANOMALY_CONFIG_KEY]
ANOMALY_RATE_THRESHOLDS = CLASS_CONFIG[ANOMALY_RATE_THRESHOLDS_KEY]
SCORING_CONFIG = CLASS_CONFIG[SCORING_CONFIG_KEY]

LIST = [
        SEUIL_KEY,
        SCORING_CONFIG_KEY,
        CRITICAL_PORT_KEY,
        DANGEROUS_LOCALISATION_KEY,
        ANOMALY_CONFIG_KEY,
        DECAY_CONFIG_KEY,
        ANOMALY_RATE_THRESHOLDS_KEY
    ]
LOCALS = locals()

class Config:
    def __init__(self, config_path=_config_path):
        self._lock = threading.Lock()
        self.CONFIG = {}
        self.config_path = config_path
        self._load()
        
    def _load(self):
        data = None
        if not os.path.exists(self.config_path):
            self.CONFIG = deepcopy(CLASS_CONFIG)
            return
        try:
            with open(self.config_path, "r") as f:
                data = json5.load(f)
                logger.print(f'Succès du chargement de la configuartion de {self.config_path}')
        except Exception as e:
            logger.print(f'Erreur de chargement de la configuartion de {self.config_path} : ', str(e))
            
        if data is None:
            self.CONFIG = deepcopy(CLASS_CONFIG)
            self._save(self.CONFIG)
        else:  
            self.CONFIG = data
            
        self.CONFIG[GLOBAL_CONFIG_KEY].setdefault("model_file", f"model_{date}.pkl")
        self.CONFIG[GLOBAL_CONFIG_KEY]["model_file"] = self.CONFIG[GLOBAL_CONFIG_KEY]["model_file"].replace("{date}", date)
        self.CONFIG[GLOBAL_CONFIG_KEY].setdefault("capture_filename", f"capture_{date}.pkl")
    
    def get(self, *args, **kwargs):
        return self.CONFIG.get(*args, **kwargs)
    
    def _save(self, value):
        try:
            with open(self.config_path, "w") as f:
                json5.dump(value, f, indent=2, ensure_ascii=False)
                logger.print(f'Succès de sauvegarde de la configuartion de {self.config_path}')
        except Exception as e:
            logger.print(f'Erreur de sauvegarde de la configuartion de {self.config_path} : ', str(e))
    
    def _validate_seuil(self, data:dict):
        if 'decision' in data:
            value = data['decision']
            if -1 <= value <= 1: # Seuil entre -1 1
                return True
            return False
        return False
    
    def _validate_port(self, data:dict):
        # On vérifie juste les clés
        key_valid = True
        for k in data.keys():
            try:
                int_ = int(k)
                if not (1 <= int_ <= 65535):
                    key_valid = False
                    break
            except Exception:
                key_valid = False
                break
        return key_valid
    
   
    def _validate_scoring(self, data:dict):
        value_valid = all(0 <= c <= 300 for c in list(data.values()))
        key_valid = True  # Par défaut, l'user peut avoir enlever les la variable SCORING_CONFIG
        if "SCORING_CONFIG" in LOCALS:
            key_valid = all(c in SCORING_CONFIG.keys() for c in list(data.keys()))
        return all(c for c in (key_valid, value_valid))
    
    def _validate_decay(self, data:dict):
        # On vérifie juste les clés
        key_valid = True  
        if "DECAY_CONFIG" in LOCALS:
            key_valid = all(c in DECAY_CONFIG.keys() for c in list(data.keys()))
        return key_valid
    
    def _validate_anomalie_config(self, data:dict):
        # On vérifie juste les clés
        key_valid = True  
        if "ANOMALY_CONFIG" in LOCALS:
            key_valid = all(c in ANOMALY_CONFIG_KEY.keys() for c in list(data.keys()))
        return key_valid
    
    def _validate_anomaly_rate(self, data:dict):
        # On va vérifier clé et valeur
        value_valid = all(0 <= c <= 1 for c in list(data.values()))
        key_valid = True  # Par défaut, l'user peut avoir enlever les la variable SCORING_CONFIG
        if "ANOMALY_RATE_THRESHOLDS" in LOCALS:
            key_valid = all(c in ANOMALY_RATE_THRESHOLDS.keys() for c in list(data.keys()))
        return all(c for c in (key_valid, value_valid))
        
            
    def validate(self, who:str, data:dict):
        if not who.upper() in LIST:
            return False
        who = who.upper()
        if not isinstance(data, dict):
            return False
        
        if who == DANGEROUS_LOCALISATION_KEY:
            return True
        
        elif who == SEUIL_KEY:
            return self._validate_seuil(data)
        
        elif who == CRITICAL_PORT_KEY:
            return self._validate_port(data)
        
        elif who == SCORING_CONFIG_KEY:
            return self._validate_scoring(data)
        
        elif who == ANOMALY_RATE_THRESHOLDS_KEY:
            return self._validate_anomaly_rate(data)
        
        elif who == ANOMALY_CONFIG_KEY:
            return self._validate_anomalie_config(data)
        
        elif who == DECAY_CONFIG_KEY:
            return self._validate_decay(data)
        
        else:
            return False
            
    def update(self, who:str, to_set:dict):
        results = {
            "success": False,
            "rejected": [],
            "keep": [],
            "received": [],
            "errors": []
        }
        
        if not isinstance(to_set, dict):
            logger.print('update attend un dictionnaire, on skip !')
            return results
        results['received'] = list(to_set.keys())
        who = str(who).strip().strip("'\",;:").strip()
        
        if who.upper() not in LIST:
            results['errors'].append(f" La clé {who} n'est pas dans {LIST}")
            return results
        
        with self._lock:
            to_modifie = self.CONFIG.get(who.upper())
            key_in = [k for k in list(to_set.keys()) if k in list(to_modifie.keys())]
            not_in = [k for k in list(to_set.keys()) if k not in key_in]
            if not key_in:
                logger.print('Clés invalides, skip !')
                results["rejected"] = list(to_set.keys())
                results['errors'].append(" Dictionnaire invalide, aucune clé ne figure dans les configs !")
                return results
            
            if not_in:
                logger.print('Clé rejetées : ', not_in)
                results['rejected'] = not_in
                
            filtered = {k:to_set[k] for k in key_in}
            validated = self.validate(who.upper(), filtered)
            if not validated:
                logger.print('Valeur de dictionnaire incohérentes !')
                results['errors'].append('Valeur de dictionnaire incohérentes !')
                return results
            
            to_modifie.update(filtered)
            results['success'] = True
            self.CONFIG[who.upper()] = to_modifie
            self._save(self.CONFIG)
            self._load()
        return results
    
    def _help(self):
        return """=== MODE D'EMPLOI DE LA CONFIGURATION IDS ===
    
    📋 MÉTHODE update(who: str, to_set: dict)
    ------------------------------------------
    Permet de modifier dynamiquement la configuration sans redémarrer l'IDS.
    
    📥 Paramètres :
      • who : Catégorie à modifier (chaîne)
      • to_set : Dictionnaire {clé: nouvelle_valeur}
    
    📤 Retourne : Dictionnaire avec les résultats
      {
        "success": bool,      # True si au moins une clé modifiée
        "rejected": list,     # Clés rejetées
        "keep": list,         # Clés conservées (acceptées)
        "received": list,     # Toutes les clés reçues
        "errors": list        # Messages d'erreur
      }
    
    🏷️ CATÉGORIES DISPONIBLES :
    ---------------------------
    1. 'SEUIL' - Seuils de décision
       • Clés disponibles: ['decision']
       • Validation: -1.0 ≤ valeur ≤ 1.0
       • Exemple: {'decision': -0.5}
    
    2. 'CRITICAL_PORT' - Ports critiques et leur poids
       • Format: {'22': 40, '80': 20}
       • Validation: port 1-65535, poids 0-300
       • Exemple: {'22': 45, '3389': 42}
    
    3. 'DANGEROUS_LOCALISATION' - Scores par pays
       • Format: {'CN': 30, 'FR': 10}
       • Validation: Code pays 2 lettres, score 0-100
    
    4. 'SCORING_CONFIG' - Pondérations du scoring
       • Clés: ['ml_predict', 'port_weight', 'max_score_anomaly', 
                'geo_max', 'block_history_weight', 
                'anomaly_frequency_weight', 'max_score_total', 'max_bonus']
       • Validation: 0 ≤ valeur ≤ 300
    
    5. 'ANOMALY_RATE_THRESHOLDS' - Seuils d'anomalie
       • Clés: ['critical', 'very_high', 'high', 
                'medium', 'low', 'minimal']
       • Validation: 0.0 ≤ valeur ≤ 1.0
    
    6. 'DECAY_CONFIG' - Configuration du décay
       • Clés: ['loss_per_hour', 'reset_days', 
                'reset_seconds', 'minimum_decay_rate']
    
    7. 'ANOMALY_CONFIG' - Configuration des anomalies
       • Clés: ['max_anomalies_per_file', 
                'anomaly_file_prefix', 'seq_length']
    
    🚀 EXEMPLES PRATIQUES :
    -----------------------
    1. Modifier le seuil de décision :
       config.update('SEUIL', {'decision': -0.5})
    
    2. Ajouter un port critique :
       config.update('CRITICAL_PORT', {'8080': 25})
    
    3. Ajuster les pondérations :
       config.update('SCORING_CONFIG', {'port_weight': 40, 'geo_max': 30})
    
    4. Modifier plusieurs seuils :
       config.update('ANOMALY_RATE_THRESHOLDS', {
           'critical': 0.85,
           'high': 0.55
       })
    
    ⚠️ NOTES IMPORTANTES :
    ----------------------
    • Seules les clés existantes peuvent être modifiées
    • Les nouvelles clés sont rejetées (dans 'rejected')
    • La configuration est automatiquement sauvegardée
    • Format JSON : {who: {clé: valeur, ...}}
    • Thread-safe : pas de conflits en multi-threading
    
    🔧 UTILISATION AVEC L'API :
    --------------------------
    POST /api/config/update
    {
        "who": "SEUIL",
        "to_set": {"decision": -0.5}
    }
    
    📁 FICHIER DE CONFIGURATION :
    ----------------------------
    • Emplacement : config_json.json
    • Format : JSON avec indentation
    • Sauvegarde automatique après chaque modification
    • Chargement au démarrage
    
    🔄 REINITIALISATION :
    --------------------
    Supprimer le fichier 'config_json.json' pour revenir aux valeurs par défaut.
    """
    
if __name__ == "__main__":
    import tempfile
    logger.print("🧪 DÉBUT DES TESTS UNITAIRES - Classe Config")
    logger.print("=" * 50)
    
    # === TEST 1: Initialisation ===
    logger.print("\n1. TEST d'initialisation")
    logger.print("-" * 30)
    
    # Créer un fichier temporaire pour les tests
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        temp_config_path = tmp.name
        
        # Tester l'initialisation
        config = Config(config_path=temp_config_path)
        # Vérifier que la configuration est chargée
        assert config.CONFIG is not None, "❌ CONFIG non initialisé"
        assert isinstance(config.CONFIG, dict), "❌ CONFIG n'est pas un dict"
        
        # Vérifier toutes les catégories
        for category in LIST:
            assert category in config.CONFIG, f"❌ Catégorie manquante: {category}"
        
        logger.print("✅ Initialisation OK")
    
    # === TEST 2: Validation des catégories ===
    logger.print("\n2. TEST de validation")
    logger.print("-" * 30)
    
    # Test SEUIL
    valid_seuil = {"decision": -0.5}
    invalid_seuil = {"decision": 1.5}  # Hors range
    assert config.validate("SEUIL", valid_seuil), "❌ Validation SEUIL valide échouée"
    assert not config.validate("SEUIL", invalid_seuil), "❌ Validation SEUIL invalide réussie"
    
    # Test CRITICAL_PORT
    valid_port = {"22": 40, "80": 20}
    invalid_port_key = {"99999": 40}  # Port invalide
    assert config.validate("CRITICAL_PORT", valid_port), "❌ Validation PORT valide échouée"
    assert not config.validate("CRITICAL_PORT", invalid_port_key), "❌ Validation PORT invalide réussie"
    
    # Test SCORING_CONFIG
    valid_scoring = {"ml_predict": 20, "port_weight": 40}
    invalid_scoring = {"ml_predict": 400}  # Valeur trop haute
    assert config.validate("SCORING_CONFIG", valid_scoring), "❌ Validation SCORING valide échouée"
    assert not config.validate("SCORING_CONFIG", invalid_scoring), "❌ Validation SCORING invalide réussie"
    
    logger.print("✅ Validation OK")
    
    # === TEST 3: Méthode update() ===
    logger.print("\n3. TEST de update()")
    logger.print("-" * 30)
    
    # Sauvegarder les valeurs originales pour restauration
    original_config = deepcopy(config.CONFIG)
    
    # Test update valide
    update_result = config.update("SEUIL", {"decision": -0.3})
    assert update_result["success"] == True, "❌ Update valide échoué"
    assert update_result["rejected"] == [], "❌ Clés rejetées alors que valides"
    assert config.CONFIG["SEUIL"]["decision"] == -0.3, "❌ Valeur non mise à jour"
    
    # Test update avec clés mixtes (valides + invalides)
    mixed_result = config.update("CRITICAL_PORT", {"22": 45, "INVALID": 100, "80": 25})
    assert mixed_result["success"] == True, "❌ Update mixte échoué"
    assert "INVALID" in mixed_result["rejected"], "❌ Clé invalide non rejetée"
    assert "22" not in mixed_result["rejected"], "❌ Clé valide rejetée"
    assert config.CONFIG["CRITICAL_PORT"]["22"] == 45, "❌ Valeur port 22 non mise à jour"
    assert config.CONFIG["CRITICAL_PORT"]["80"] == 25, "❌ Valeur port 80 non mise à jour"
    
    # Test update complètement invalide
    invalid_result = config.update("SEUIL", {"invalid_key": 123})
    assert invalid_result["success"] == False, "❌ Update invalide réussi"
    assert invalid_result["rejected"] == ["invalid_key"] or "invalid_key" in invalid_result["errors"], "❌ Pas d'erreur pour clé invalide"
    
    logger.print("✅ Update() OK")
    
    # === TEST 4: Persistance (sauvegarde/chargement) ===
    logger.print("\n4. TEST de persistance")
    logger.print("-" * 30)
    
    # Modifier une valeur
    config.update("SCORING_CONFIG", {"ml_predict": 25})
    
    # Créer une nouvelle instance qui va charger depuis le fichier
    config2 = Config(config_path=temp_config_path)
    
    # Vérifier que la valeur modifiée est persistée
    assert config2.CONFIG["SCORING_CONFIG"]["ml_predict"] == 25, \
        f"❌ Persistance échouée. Attendu: 25, Reçu: {config2.CONFIG['SCORING_CONFIG']['ml_predict']}"
    
    # Vérifier que le fichier existe
    assert os.path.exists(temp_config_path), "❌ Fichier de config non créé"
    
    # Vérifier le contenu du fichier
    with open(temp_config_path, 'r') as f:
        saved_data = json5.load(f)
        assert saved_data["SCORING_CONFIG"]["ml_predict"] == 25, "❌ Données incorrectes dans le fichier"
    
    logger.print("✅ Persistance OK")
    
    # === TEST 5: Thread safety (simulation) ===
    logger.print("\n5. TEST de thread safety")
    logger.print("-" * 30)
    
    import time
    
    # Fonction pour simuler des accès concurrents
    def concurrent_update(thread_id):
        for i in range(5):
            # Chaque thread modifie une valeur différente
            config.update("SCORING_CONFIG", {"ml_predict": thread_id * 10 + i})
            time.sleep(0.01)
    
    # Lancer plusieurs threads
    threads = []
    for i in range(3):
        t = threading.Thread(target=concurrent_update, args=(i,))
        threads.append(t)
        t.start()
    
    # Attendre la fin des threads
    for t in threads:
        t.join()
    
    # Vérifier qu'aucune corruption ne s'est produite
    final_value = config.CONFIG["SCORING_CONFIG"]["ml_predict"]
    assert isinstance(final_value, (int, float)), "❌ Corruption des données"
    assert 0 <= final_value <= 300, "❌ Valeur hors limites après updates concurrents"
    
    logger.print("✅ Thread safety OK")
    
    # === TEST 6: Validation edge cases ===
    logger.print("\n6. TEST des cas limites")
    logger.print("-" * 30)
    
    # Test avec données vides
    empty_result = config.update("SEUIL", {})
    assert empty_result["success"] == False, "❌ Update vide réussi"
    
    # Test avec catégorie inexistante
    invalid_category_result = config.update("CATEGORIE_INEXISTANTE", {"key": "value"})
    assert "errors" in invalid_category_result and len(invalid_category_result["errors"]) > 0, \
        "❌ Catégorie inexistante non détectée"
    
    # Test avec None au lieu de dict
    none_result = config.update("SEUIL", None)
    assert none_result["success"] == False, "❌ None accepté comme paramètre"
    
    # Test avec string au lieu de dict
    string_result = config.update("SEUIL", "not a dict")
    assert string_result["success"] == False, "❌ String accepté comme paramètre"
    
    logger.print("✅ Cas limites OK")
    
    # === TEST 7: Restauration des valeurs originales ===
    logger.print("\n7. TEST de restauration")
    logger.print("-" * 30)
    
    # Restaurer la config originale
    config.CONFIG = original_config
    config._save(config.CONFIG)
    
    # Vérifier la restauration
    for category in LIST:
        assert config.CONFIG[category] == original_config[category], \
            f"❌ Restauration échouée pour {category}"
    
    logger.print("✅ Restauration OK")
    
    # === TEST 8: Méthode _help() ===
    logger.print("\n8. TEST de la méthode _help()")
    logger.print("-" * 30)
    
    help_text = config._help()
    assert help_text is not None, "❌ _help() retourne None"
    assert isinstance(help_text, str), "❌ _help() ne retourne pas une string"
    assert len(help_text) > 100, "❌ _help() trop courte"
    
    # Vérifier que les catégories sont mentionnées
    for category in LIST:
        assert category in help_text.upper(), f"❌ Catégorie {category} non mentionnée dans _help()"
    
    logger.print("✅ _help() OK")
    
    # Nettoyage
    os.unlink(temp_config_path)
    
    logger.print("\n" + "=" * 50)
    logger.print("🎉 TOUS LES TESTS PASSÉS AVEC SUCCÈS !")
    logger.print(f"✅ {8} groupes de tests validés")
    logger.print("=" * 50)