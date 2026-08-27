#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 17:37:41 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..",))))

from dotenv import load_dotenv
from jose import jwt
from fastapi import Request, Header, status, HTTPException
from datetime import datetime, timedelta
from modules_utils.cryto_utils import hashpw, checkpw
from modules_utils.env_utils import getenv_required, validate_password

def get_loop():
    return "uvloop" if sys.platform != "win32" else "asyncio"

class AuthManager:
    def __init__(
        self, 
        exp: int,
        not_before: int | float,
        user_env_key: str,
        passwd_env_key: str,
        secret_key_env_key: str,
        algorithm: str = "HS256",
    ):
        load_dotenv()
        self.algorithm = algorithm
        self.exp = float(exp)
        self.not_before = float(not_before)
        self.user_env_key = str(user_env_key)
        self.passwd_env_key = str(passwd_env_key)
        self.secret_key_env_key = str(secret_key_env_key)
        self.secret_key = None
        self.user = None
        self.passwd = None
    
    def _get_username(self):
        if self.user:
            return self.user
        
        self.user = hashpw(
             getenv_required(
                 self.user_env_key,
                 help_text="Nom d'utilisateur pour l'authentification admin",
                 exit_=False
             )   
        )
        return self.user
    
    def _get_password(self):
        if self.passwd:
            return self.passwd
        passwd = getenv_required(
            self.passwd_env_key,
            help_text="Mot de passe fort (min 8 caractères) pour l'admin",
            exit_=False
        )   
        validate_password(passwd)
        self.passwd = hashpw(
             password=passwd
        )
        return self.passwd
    
    def _get_secret_key(self):
        if self.secret_key:
            return self.secret_key
        self.secret_key = getenv_required(
            self.secret_key_env_key,
            help_text="Clé secrète JWT (utilisez: openssl rand -hex 32)",
            exit_=False
        )   
        return self.secret_key
    
    def verify_env_utils(self):
        self._get_username()
        self._get_password()
        self._get_secret_key()
        if self.user is None:
            raise ValueError("Erreur lors de la validation, username est None")
        
        if self.passwd is None:
            raise ValueError("Erreur lors de la validation, passwd est None")
            
    def verify_username(self, username: str):
        if checkpw(username, self.user):
            return True
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalide username"
        )
    
    def verify_password(self, password: str):
        if checkpw(password, self.passwd):
            return True
        
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalide password"
        )
    
    def verify_token(
        self,
        request: Request,
        authorization: str = Header(...),
    ):
        try:
            try:
                scheme, token = authorization.split()
                if scheme.lower() != "bearer":
                    raise HTTPException(401, "Schéma d'authentification invalide")
            except ValueError:
                raise HTTPException(401, "Format du header Authorization invalide")

            decoded = jwt.decode(
                token, self._get_secret_key(),
                algorithms=[self.algorithm], 
            )
            return decoded["sub"]
        
        except HTTPException:
            raise 
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOKEN_EXPIRED",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        except jwt.JWTError as e:
            print('Erreur jwt: ', type(e).__name__, ": ", str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invlide",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        except Exception as e:
            print('Erreur : ', type(e).__name__, ": ", str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Erreur générale !",
                headers={"WWW-Authenticate": "Bearer"}
                )
    
    def verify_token_params(
        self,
        token: str,
    ):
        try:
            decoded = jwt.decode(
                token, self._get_secret_key(),
                algorithms=[self.algorithm], 
            )
            return decoded["sub"]
        
        except HTTPException:
            raise 
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOKEN_EXPIRED",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        except jwt.JWTError as e:
            print('Erreur jwt: ', type(e).__name__, ": ", str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invlide",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        except Exception as e:
            print('Erreur : ', type(e).__name__, ": ", str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Erreur générale !",
                headers={"WWW-Authenticate": "Bearer"}
                )
            
    def verify_token_without_exp_verify(
        self,
        token: str
    ):
        try:
            decoded = jwt.decode(
                token, self._get_secret_key(),
                algorithms=[self.algorithm], 
                options={
                'verify_exp': False,
                }
            )
            return decoded["sub"]
        
        except HTTPException:
            raise 
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOKEN_EXPIRED",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        except jwt.JWTError as e:
            print('Erreur jwt: ', type(e).__name__, ": ", str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invlide",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        except Exception as e:
            print('Erreur : ', type(e).__name__, ": ", str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Erreur générale !",
                headers={"WWW-Authenticate": "Bearer"}
                )
            
    def create_token(self, data:dict):
        try:
            iat = datetime.utcnow()
            jwt_data = {
                "sub": data["username"],
                "iat": iat,
                "exp": iat + timedelta(minutes=self.exp),
                "nbf": iat + timedelta(seconds=self.not_before)
                }
            token = jwt.encode(jwt_data, key=self._get_secret_key(), algorithm=self.algorithm)
            return token
        except Exception as e:
            print("Erreur dans la création du token jwt :", str(e))



    

