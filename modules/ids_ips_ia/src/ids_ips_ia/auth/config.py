#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 18 02:26:45 2025

@author: hounsousamuel
"""

from ids_ips_ia.ids_ips_utils.logger import get_logger
from modules_utils.env_utils import getenv_required, validate_password

logger = get_logger()

USERNAME = getenv_required(
    'IDS_ADMIN_USERNAME',
    help_text="Nom d'utilisateur pour l'authentification admin"
)

PASSWORD = getenv_required(
    'IDS_ADMIN_PASSWORD', 
    help_text="Mot de passe fort (min 8 caractères) pour l'admin"
)
validate_password(PASSWORD)

JWT_KEY = getenv_required(
    "IDS_JWT_SECRET",
    help_text="Clé secrète JWT (utilisez: openssl rand -hex 32)"
)
