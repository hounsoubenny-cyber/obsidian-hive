#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 18 02:26:45 2025

@author: hounsousamuel
"""


import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from modules_utils.env_utils import getenv_required, validate_password
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

USERNAME = getenv_required(
    'IDS_ADMIN_USERNAME',
    help_text="Nom d'utilisateur pour l'authentification admin"
)

PASSWORD = getenv_required(
    'IDS_ADMIN_PASSWORD', 
    help_text="Mot de passe fort (min 8 caractères) pour l'admin"
)
# logger.print(PASSWORD)
validate_password(PASSWORD)
JWT_KEY = getenv_required(
    "IDS_JWT_SECRET",
    help_text="Clé secrète JWT (utilisez: openssl rand -hex 32)"
)
# logger.print(JWT_KEY)