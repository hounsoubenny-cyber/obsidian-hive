#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:20:09 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from dotenv import load_dotenv, find_dotenv

from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from modules_utils.env_utils import getenv_required, validate_password
logger = get_logger()

x = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))