#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 08:44:55 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import base64
import getpass
import bcrypt
from cryptography.fernet import Fernet

class FernetManager:
    def __init__(self, password:str, salt:str|bytes|None = None):
        if salt:
            if isinstance(salt, str):
                salt = salt.encode()
            else:
                salt = salt
        else:
            salt = self._gen_salt()
            print('Voici votre salt, veuillez à NE JAMAIS LE PERDRE !\n', salt)
        
        self.salt = salt
        self._key = self._gen_key(str(password), salt)
        self.fernet = Fernet(self._key)
    
    @staticmethod
    def _gen_salt():
        return bcrypt.gensalt()
    
    def _gen_key(self, password:str, salt):
        key = base64.urlsafe_b64encode(
            bcrypt.kdf(
                password.encode(), salt, desired_key_bytes=32, rounds=100
                )
            )
        return key
    
    def _update_fernet(self, key):
        self.fernet = Fernet(key)
        
    def encrypt(self, data:str|bytes):
        if isinstance(data, str):
            data = data.encode()
            
        if isinstance(data, (int, float)):
            data = str(data).encode()
            
        return self.fernet.encrypt(data)
    
    def decrypt(self, data:bytes|str):
        if isinstance(data, str):
            data = data.encode()
            
        if isinstance(data, (int, float)):
            data = str(data).encode()
            
        return self.fernet.decrypt(data)
    
    def encrypt_file(self, filename:str, output:str, is_bytes_file:bool = False):
        if not os.path.exists(filename):
            print("Fichier inexistant !")
            return
        
        write_mode = "wb" if not is_bytes_file else "w"
        read_mode = "rb" if not is_bytes_file else "r"
        
        try:
            content = None
            with open(filename, read_mode) as f:
                content = f.read()
                
            if not content:
                print("Fichier vide !")
                return False
            
            encrypted = self.encrypt(content)
            with open(output, write_mode) as f:
                f.write(encrypted)
                
            print("Fichier chiffré dans", output)
            return True
        except Exception as e:
            print('Erreur lors du cryptage de ', filename, " erreur : ", str(e))
            return False
            
            
    def decrypt_file(self, filename:str, output:str, is_bytes_file:bool = False):
        if not os.path.exists(filename):
            print("Fichier inexistant !")
            return
        
        write_mode = "wb" if not is_bytes_file else "w"
        read_mode = "rb" if not is_bytes_file else "r"
        
        try:
            content = None
            with open(filename, read_mode) as f:
                content = f.read()
                
            if not content:
                print("Fichier vide !")
                return 
            
            
            encrypted = self.decrypt(content)
            with open(output, write_mode) as f:
                f.write(encrypted)
            print("Fichier déchiffré dans", output)
            return True
        except Exception as e:
            print('Erreur lors du cryptage de ', filename, " erreur : ", str(e))
            return False          
            
def hashpw(password:str):
    if isinstance(password, str):
        password = password.encode()
    
    return bcrypt.hashpw(password, bcrypt.gensalt())

def checkpw(password:str, hashed:bytes):
    if isinstance(password, str):
        password = password.encode()

    return bcrypt.checkpw(password=password, hashed_password=hashed)

def checksalt(salt):
    try:
        password = "password".encode()
        bcrypt.hashpw(password, salt)
        return True
    except Exception:
        return False
    