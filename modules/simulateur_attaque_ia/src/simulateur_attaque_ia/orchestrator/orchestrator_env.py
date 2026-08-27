#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:09:09 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from dotenv import load_dotenv
load_dotenv()

from simulateur_attaque_ia.simulateur_utils.cryto_utils import hashpw
from simulateur_attaque_ia.simulateur_utils.env_utils import validate_password, getenv_required
from simulateur_attaque_ia.simulateur_utils.cryto_utils import checksalt

USERNAME = getenv_required(
    'SIMATK_ADMIN_USERNAME',
    help_text="Nom d'utilisateur pour l'authentification admin"
)

PASSWORD = getenv_required(
    'SIMATK_ADMIN_PASSWORD', 
    help_text="Mot de passe fort (min 8 caractères) pour l'admin"
)
validate_password(PASSWORD)
JWT_KEY = getenv_required(
    "SIMATK_JWT_SECRET",
    help_text="Clé secrète JWT (utilisez: openssl rand -hex 32)"
)

def get_data():
    return {
        "jwt_key": JWT_KEY,
        "username": hashpw(USERNAME.encode()),
        "password": hashpw(PASSWORD.encode())
    }
