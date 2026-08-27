#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 01:07:39 2026

@author: hounsousamuel
"""

import os
from typing import List, Any, Dict
from pydantic import BaseModel

class ValidateServicesResponse(BaseModel):
    valid:    bool
    errors:   List[str] = []
    warnings: List[str] = []


def validate_services_dict(data: Any) -> ValidateServicesResponse:
    """
    Analyse un dictionnaire et vérifie s'il respecte le format standard 
    des exports de processus et services générés par ServiceManager.
    
    Retourne une instance de ValidateServicesResponse.
    """
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Vérification du format racine (doit être un dictionnaire)
    if not isinstance(data, dict):
        errors.append("Le document racine doit être un dictionnaire (JSON Object).")
        return ValidateServicesResponse(valid=False, errors=errors, warnings=warnings)

    if not data:
        warnings.append("Le dictionnaire de services est vide.")
        return ValidateServicesResponse(valid=True, errors=errors, warnings=warnings)

    # 2. Analyse détaillée de chaque entrée de processus (clé = PID)
    for key, proc_entry in data.items():
        # Validation du PID (clé du dictionnaire)
        try:
            pid = int(key)
            if pid <= 0:
                errors.append(f"Le PID '{key}' doit être un entier positif supérieur à 0.")
        except (ValueError, TypeError):
            errors.append(f"La clé '{key}' n'est pas un PID valide (doit être un entier ou une chaîne numérique).")
            continue

        # Validation de l'entrée du processus (doit être un dictionnaire)
        if not isinstance(proc_entry, dict):
            errors.append(f"L'entrée associée au PID {key} doit être un dictionnaire.")
            continue

        # --- Vérification des champs obligatoires ---

        # Validation de 'name'
        if "name" not in proc_entry:
            errors.append(f"PID {key} : Le champ obligatoire 'name' est manquant.")
        elif not isinstance(proc_entry["name"], str):
            errors.append(f"PID {key} : Le champ 'name' doit être une chaîne de caractères (string).")
        elif not proc_entry["name"].strip():
            warnings.append(f"PID {key} : Le nom du processus ('name') est vide.")

        # Validation de 'cmdline'
        if "cmdline" not in proc_entry:
            errors.append(f"PID {key} : Le champ obligatoire 'cmdline' est manquant.")
        elif not isinstance(proc_entry["cmdline"], list):
            errors.append(f"PID {key} : Le champ 'cmdline' doit être une liste de chaînes.")
        else:
            for idx, arg in enumerate(proc_entry["cmdline"]):
                if not isinstance(arg, str):
                    errors.append(f"PID {key} : L'argument d'index {idx} de 'cmdline' doit être une chaîne de caractères.")

        # --- Vérification des champs optionnels mais structurés ---

        # Validation des 'ports' d'écoute réseau
        if "ports" in proc_entry:
            if not isinstance(proc_entry["ports"], list):
                errors.append(f"PID {key} : Le champ 'ports' doit être une liste d'entiers.")
            else:
                for idx, port in enumerate(proc_entry["ports"]):
                    # Validation et conversion souple si le port est représenté sous forme de chaîne numérique
                    if not isinstance(port, int):
                        try:
                            port_val = int(port)
                            if not (1 <= port_val <= 65535):
                                errors.append(f"PID {key} : Le port '{port}' d'index {idx} doit être compris entre 1 et 65535.")
                        except (ValueError, TypeError):
                            errors.append(f"PID {key} : Le port d'index {idx} n'est pas un entier valide : '{port}'.")
                    elif not (1 <= port <= 65535):
                        errors.append(f"PID {key} : Le port {port} d'index {idx} doit être compris entre 1 et 65535.")
        else:
            warnings.append(f"PID {key} : Le champ 'ports' est absent de l'entrée du processus.")

        # Validation du dictionnaire de variables d'environnement 'environ'
        if "environ" in proc_entry:
            if not isinstance(proc_entry["environ"], dict):
                errors.append(f"PID {key} : Le champ 'environ' doit être un dictionnaire.")
            elif not proc_entry["environ"]:
                warnings.append(f"PID {key} : Le dictionnaire de variables d'environnement 'environ' est vide.")
        else:
            warnings.append(f"PID {key} : Le champ 'environ' est absent de l'entrée du processus.")

        # Validation des champs d'exécution ('exe', 'cwd', 'user')
        for field in ["exe", "cwd", "user"]:
            if field in proc_entry:
                val = proc_entry[field]
                if val is not None and not isinstance(val, str):
                    errors.append(f"PID {key} : Le champ '{field}' doit être une chaîne de caractères (string) ou nul.")
            else:
                warnings.append(f"PID {key} : Le champ facultatif '{field}' est manquant.")

    # Validation globale
    valid = len(errors) == 0
    return ValidateServicesResponse(valid=valid, errors=errors, warnings=warnings)

if __name__ == "__main__":
    # 1. Un dictionnaire de services valide
    valid_services = {
        "1250": {
            "name": "nginx",
            "cmdline": ["/usr/sbin/nginx", "-g", "daemon off;"],
            "exe": "/usr/sbin/nginx",
            "cwd": "/var/www",
            "user": "www-data",
            "environ": {"PATH": "/usr/bin:/bin"},
            "ports": [80, 443]
        }
    }
    
    # 2. Un dictionnaire de services invalide (erreur de type sur les ports, name manquant)
    invalid_services = {
        "invalid_pid": {
            "cmdline": "/usr/bin/python3"  # Devrait être une liste
        },
        "1251": {
            "name": "mysql",
            "cmdline": ["mysqld"],
            "ports": [999999]  # Port invalide (> 65535)
        }
    }

    # Validation du cas valide
    res_valide = validate_services_dict(valid_services)
    print("Test Valide :")
    print(f"  - Est valide : {res_valide.valid}")
    print(f"  - Avertissements : {res_valide.warnings}")
    print(f"  - Erreurs : {res_valide.errors}\n")

    # Validation du cas invalide
    res_invalide = validate_services_dict(invalid_services)
    print("Test Invalide :")
    print(f"  - Est valide : {res_invalide.valid}")
    print(f"  - Erreurs : {res_invalide.errors}")
    print(f"  - Avertissements : {res_invalide.warnings}")