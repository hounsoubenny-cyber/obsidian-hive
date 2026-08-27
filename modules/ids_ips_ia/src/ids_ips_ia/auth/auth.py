#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 17 20:57:18 2025

@author: hounsousamuel
"""
import os, sys
import secrets, bcrypt
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from dotenv import load_dotenv
load_dotenv(verbose=True)

from ids_ips_ia.auth.config import USERNAME, PASSWORD, JWT_KEY
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

if not PASSWORD:
    import getpass
    PASSWORD = getpass.getpass("Définir mot de passe admin : ")
    
def hash_password(password):
    """Hachage direct avec bcrypt (sans passlib)"""
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password
    
    # Générer le sel et hacher
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    return hashed.decode('utf-8')

def verify_password(plain_password:str, hashed_password:str):
    """Vérification directe avec bcrypt"""
    if isinstance(plain_password, str):
        password_bytes = plain_password.encode('utf-8')
    else:
        password_bytes = plain_password
    
    if isinstance(hashed_password, str):
        hashed_bytes = hashed_password.encode('utf-8')
    else:
        hashed_bytes = hashed_password
    
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def auth():
    # key = secrets.token_hex(32)  
    hashed_password = hash_password(PASSWORD)
    
    DATA = {
            'username': USERNAME,
            "password": PASSWORD,
            "secret_key": JWT_KEY,
            "hash_password": hashed_password,
            "is_exec": True
           }
    
    return DATA
    
if __name__ == '__main__':
    pw = 'admin'
    hash_ = hash_password(pw)
    logger.print(verify_password(pw, hash_))
    logger.print(auth())

# curl -X POST  "http://0.0.0.0:8080/api/login" -d '{"username":"admin", "password":"admin"}' -H "Content-Type: application/json"  




