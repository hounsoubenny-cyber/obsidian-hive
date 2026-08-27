#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContextGuard Python SDK

Ce module fournit un SDK asynchrone pour interagir avec l'API ContextGuard.
Il permet de :
    - S'authentifier et gérer les tokens JWT
    - Analyser des prompts pour détecter des injections, jailbreaks ou exfiltrations
    - Rafraîchir automatiquement les tokens expirés
    - Vérifier l'état de santé d'un utilisateur

Auteur : HOUNSOU Samuel
Version : 1.0.0
"""

import os
import sys
import asyncio
import aiohttp
import nest_asyncio
from urllib.parse import urljoin

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from contextguard.core.utils import verify_salt
from fastapi import HTTPException, status

nest_asyncio.apply()

# Configuration des URLs de l'API
_API_URL = "http://localhost:8000"
_ANALYSE_PATH = "/api/analyse"
_CONNECT_PATH = "/api/login"
_REFRESH_PATH = "/api/refresh_token"
_HEALTH_PATH = "/api/health"
_SALT_PATH = "/api/salt"

_CONNECT_URL = urljoin(_API_URL, _CONNECT_PATH)
_ANALYSE_URL = urljoin(_API_URL, _ANALYSE_PATH)
_REFRESH_URL = urljoin(_API_URL, _REFRESH_PATH)
_HEALTH_URL = urljoin(_API_URL, _HEALTH_PATH)
_SALT_URL = urljoin(_API_URL, _SALT_PATH)

_CONNECT_TIMEOUT = 10


class ContextGuardSDK:
    """
    SDK pour interagir avec l'API ContextGuard.
    
    Cette classe fournit des méthodes asynchrones et synchrones pour :
        - Créer un compte ou se connecter
        - Analyser des prompts
        - Gérer les tokens JWT (rafraîchissement automatique)
        - Obtenir des informations de santé
    
    Toutes les méthodes asynchrones sont préfixées par '_async'.
    Les méthodes synchrones correspondantes appellent asyncio.run().
    
    Exemples
    --------
    >>> sdk = ContextGuardSDK()
    >>> 
    >>> # Connexion asynchrone
    >>> async with aiohttp.ClientSession() as session:
    ...     result = await sdk.connect_async("user", "pass", "salt", session=session)
    ...     token = result["result"]["token"]
    >>>
    >>> # Analyse d'un prompt
    >>> result = await sdk.secure_prompt_async(
    ...     username="user",
    ...     password="pass", 
    ...     salt="salt",
    ...     token=token,
    ...     prompts=["Hello world"],
    ...     session=session
    ... )
    """
    
    __author__ = "HOUNSOU Samuel"
    __version__ = "1.0.0"
    
    # ==================== CONNEXION / AUTHENTIFICATION ====================
    
    async def connect_async(
        self,
        username: str,
        password: str,
        salt: str,
        connect: bool = True,
        session: aiohttp.ClientSession = None,
        timeout: int | float = _CONNECT_TIMEOUT
    ) -> dict:
        """
        Authentifie un utilisateur ou crée un nouveau compte.
        
        Parameters
        ----------
        username : str
            Nom d'utilisateur.
        password : str
            Mot de passe en clair.
        salt : str
            Sel de chiffrement (doit être valide).
        connect : bool, optional
            - True : Se connecter (l'utilisateur doit exister)
            - False : Tenter de créer un nouveau compte
            Par défaut True.
        session : aiohttp.ClientSession
            Session HTTP à utiliser (obligatoire).
        timeout : int | float, optional
            Timeout en secondes pour la requête. Par défaut 10.
        
        Returns
        -------
        dict
            {
                "errors": list[str],      # Messages d'erreur
                "status_code": int,       # Code HTTP de la réponse
                "success": bool,          # True si opération réussie
                "result": {
                    "state": str,         # "new user" ou "old user"
                    "success": bool,      # Succès de l'opération
                    "reason": str,        # Raison en cas d'échec
                    "salt": str,          # Sel utilisé
                    "token": str          # Token JWT
                }
            }
        
        Examples
        --------
        >>> async with aiohttp.ClientSession() as session:
        ...     # Créer un nouveau compte
        ...     result = await sdk.connect_async("alice", "secret", salt, connect=False, session=session)
        ...     # Se connecter
        ...     result = await sdk.connect_async("alice", "secret", salt, connect=True, session=session)
        """
        result = {
            "errors": [],
            "status_code": None,
            "result": {},
            "success": False
        }
        
        if not all([username, password, salt, session]):
            result["errors"].append("Paramètres manquants : username, password, salt et session sont requis")
            return result
        
        if not verify_salt(salt):
            result["errors"].append("Salt invalide")
            return result
            
        try:
            json_data = {
                "username": username,
                "password": password,
                "salt": salt,
                "connect": connect
            }
            
            async with session.post(
                url=_CONNECT_URL,
                json=json_data,
                timeout=aiohttp.ClientTimeout(total=float(timeout))
            ) as response:
                result["status_code"] = response.status
                
                if not response.ok:
                    result["errors"].append(f"HTTP {response.status}")
                    return result
                
                request_response = await response.json()
                result["result"] = request_response
                result["success"] = request_response.get("success", False)
            return result
        
        except asyncio.TimeoutError:
            result["errors"].append(f"Timeout après {timeout} secondes")
            return result
        except aiohttp.ClientError as e:
            result["errors"].append(f"Erreur réseau : {str(e)}")
            return result
        except Exception as e:
            result["errors"].append(f"Erreur inattendue : {str(e)}")
            return result
    
    def connect(self, *args, **kwargs) -> dict:
        """
        Version synchrone de connect_async().
        
        See Also
        --------
        connect_async : Version asynchrone avec documentation détaillée
        """
        return asyncio.run(self.connect_async(*args, **kwargs))
    
    # ==================== REFRESH TOKEN ====================
    
    async def refresh_token(
        self,
        username: str,
        token: str,
        salt: str,
        session: aiohttp.ClientSession,
        timeout: int | float = 10
    ) -> str | None:
        """
        Rafraîchit un token JWT expiré.
        
        Cette méthode est généralement appelée automatiquement par secure_prompt_async()
        lorsque le token est expiré.
        
        Parameters
        ----------
        username : str
            Nom d'utilisateur.
        token : str
            Token JWT expiré.
        salt : str
            Sel utilisé lors de la création du token.
        session : aiohttp.ClientSession
            Session HTTP à utiliser.
        timeout : int | float, optional
            Timeout en secondes. Par défaut 10.
        
        Returns
        -------
        str | None
            Nouveau token JWT, ou None si le rafraîchissement a échoué.
        """
        try:
            async with session.post(
                url=_REFRESH_URL,
                json={
                    "username": username,
                    "token": token,
                    "salt": salt
                },
                timeout=aiohttp.ClientTimeout(total=float(timeout))
            ) as response:
                if not response.ok:
                    return None
                request_result = await response.json()
                return request_result.get("token")
        except Exception:
            return None
    
    # ==================== ANALYSE DE PROMPTS ====================
    
    async def secure_prompt_async(
        self,
        username: str,
        password: str,
        salt: str,
        token: str,
        prompts: list[str] | str,
        session: aiohttp.ClientSession,
        timeout: int | float = 60,
        threasholds: list[float] | float = 0.5
    ) -> dict:
        """
        Analyse un ou plusieurs prompts pour détecter des comportements malveillants.
        
        Les prompts sont classifiés dans les catégories suivantes :
            - "safe" : Prompt normal, sans risque
            - "injection" : Tentative d'injection SQL/commande
            - "jailbreak" : Tentative de contournement des restrictions
            - "exfiltration" : Tentative d'exfiltration de données
        
        Si le token est expiré (401 TOKEN_EXPIRED), la méthode tente automatiquement
        de le rafraîchir et réessaie une fois.
        
        Parameters
        ----------
        username : str
            Nom d'utilisateur.
        password : str
            Mot de passe.
        salt : str
            Sel de chiffrement.
        token : str
            Token JWT valide (ou expiré, sera rafraîchi auto).
        prompts : list[str] | str
            Prompt(s) à analyser. Si une seule chaîne, sera convertie en liste.
        session : aiohttp.ClientSession
            Session HTTP à utiliser.
        timeout : int | float, optional
            Timeout en secondes. Par défaut 60.
        threasholds : list[float] | float, optional
            Seuil(s) de décision (entre 0 et 1).
            Si un seul nombre, sera appliqué à tous les prompts.
            Par défaut 0.5.
        
        Returns
        -------
        dict
            {
                "errors": list[str],          # Messages d'erreur
                "token": str,                 # Token utilisé (peut être nouveau)
                "salt": str,                  # Sel utilisé
                "result": {
                    "result": {
                        "prompt": {
                            "threashold": float,    # Seuil appliqué
                            "label": str,          # "safe", "injection", etc.
                            "prob": float          # Probabilité (0-1)
                        },
                        ...
                    },
                    "history_update_with_success": bool
                }
            }
        
        Examples
        --------
        >>> async with aiohttp.ClientSession() as session:
        ...     # Analyser un seul prompt
        ...     result = await sdk.secure_prompt_async(
        ...         username="alice",
        ...         password="secret",
        ...         salt=salt,
        ...         token=token,
        ...         prompts="Hello world",
        ...         session=session
        ...     )
        ...     
        ...     # Analyser plusieurs prompts avec le même seuil
        ...     result = await sdk.secure_prompt_async(
        ...         ...,
        ...         prompts=["prompt1", "prompt2"],
        ...         threasholds=0.7,
        ...         ...
        ...     )
        ...     
        ...     # Analyser avec des seuils différents par prompt
        ...     result = await sdk.secure_prompt_async(
        ...         ...,
        ...         prompts=["p1", "p2", "p3"],
        ...         threasholds=[0.5, 0.7, 0.9],
        ...         ...
        ...     )
        """
        result = {
            "errors": [],
            "token": token,
            "salt": salt,
            "result": {}
        }
        
        if not session:
            result["errors"].append("Session HTTP requise")
            return result
        
        if not verify_salt(salt):
            result["errors"].append("Salt invalide")
            return result
        
        if isinstance(prompts, str):
            prompts = [prompts]
        
        if isinstance(threasholds, (int, float)):
            threasholds = [threasholds] * len(prompts)
        
        if len(threasholds) != len(prompts):
            result["errors"].append(
                f"Nombre de seuils ({len(threasholds)}) différent "
                f"du nombre de prompts ({len(prompts)})"
            )
            return result
        
        for i in range(len(threasholds)):
            if not 0 <= threasholds[i] <= 1:
                threasholds[i] = 0.5
        
        try:
            analyse_json = {
                "threasholds": threasholds,
                "token": token,
                "username": username,
                "password": password,
                "salt": salt,
                "prompts": prompts,
                "verify_connect": False
            }
            
            async with session.post(
                url=_ANALYSE_URL,
                json=analyse_json,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=float(timeout))
            ) as response:
                
                if response.ok:
                    request_result = await response.json()
                    result["result"] = request_result
                    return result
                
                error_data = await response.json()
                
                # Gestion automatique du token expiré
                if response.status == 401 and error_data.get("detail") == "TOKEN_EXPIRED":
                    new_token = await self.refresh_token(
                        username=username,
                        token=token,
                        salt=salt,
                        session=session
                    )
                    if not new_token:
                        result["errors"].append(
                            "Échec du rafraîchissement du token. Veuillez vous reconnecter."
                        )
                        return result
                    
                    # Réessayer avec le nouveau token
                    return await self.secure_prompt_async(
                        username=username,
                        password=password,
                        salt=salt,
                        token=new_token,
                        prompts=prompts,
                        session=session,
                        timeout=timeout,
                        threasholds=threasholds
                    )
                
                result["errors"].append(f"Erreur API : {error_data.get('detail', 'Erreur inconnue')}")
                return result
                
        except asyncio.TimeoutError:
            result["errors"].append(f"Timeout après {timeout} secondes")
            return result
        except aiohttp.ClientError as e:
            result["errors"].append(f"Erreur réseau : {str(e)}")
            return result
        except Exception as e:
            result["errors"].append(f"Erreur inattendue : {str(e)}")
            return result
    
    def secure_prompt(self, *args, **kwargs) -> dict:
        """
        Version synchrone de secure_prompt_async().
        
        See Also
        --------
        secure_prompt_async : Version asynchrone avec documentation détaillée
        """
        return asyncio.run(self.secure_prompt_async(*args, **kwargs))
    
    # ==================== SALT ====================
    
    async def get_salt_async(
        self,
        session: aiohttp.ClientSession,
        timeout: int | float = 10
    ) -> dict:
        """
        Récupère un nouveau sel de chiffrement depuis l'API.
        
        Un salt est nécessaire pour :
            - Hacher les mots de passe
            - Générer des tokens JWT
            - Chiffrer/déchiffrer des données avec Fernet
        
        Parameters
        ----------
        session : aiohttp.ClientSession
            Session HTTP à utiliser.
        timeout : int | float, optional
            Timeout en secondes. Par défaut 10.
        
        Returns
        -------
        dict
            {
                "errors": list[str],      # Messages d'erreur
                "status_code": int,       # Code HTTP
                "success": bool,          # True si succès
                "salt": str | None,       # Le sel (base64)
                "datetime": str | None    # Date de génération
            }
        
        Examples
        --------
        >>> async with aiohttp.ClientSession() as session:
        ...     result = await sdk.get_salt_async(session)
        ...     if result["success"]:
        ...         salt = result["salt"]
        ...         print(f"Salt obtenu : {salt}")
        """
        result = {
            "errors": [],
            "status_code": None,
            "success": False,
            "salt": None,
            "datetime": None
        }
        
        try:
            async with session.get(
                url=_SALT_URL,
                timeout=aiohttp.ClientTimeout(total=float(timeout))
            ) as response:
                result["status_code"] = response.status
                
                if not response.ok:
                    result["errors"].append(f"HTTP {response.status}")
                    return result
                
                data = await response.json()
                result["success"] = True
                result["salt"] = data.get("salt")
                result["datetime"] = data.get("datetime")
                return result
                
        except asyncio.TimeoutError:
            result["errors"].append(f"Timeout après {timeout} secondes")
            return result
        except aiohttp.ClientError as e:
            result["errors"].append(f"Erreur réseau : {str(e)}")
            return result
        except Exception as e:
            result["errors"].append(f"Erreur inattendue : {str(e)}")
            return result
    
    def get_salt(self, *args, **kwargs) -> dict:
        """
        Version synchrone de get_salt_async().
        
        See Also
        --------
        get_salt_async : Version asynchrone avec documentation détaillée
        """
        return asyncio.run(self.get_salt_async(*args, **kwargs))
    
    # ==================== HEALTH CHECK ====================
    
    async def health_async(
        self,
        username: str,
        password: str,
        salt: str,
        token: str,
        session: aiohttp.ClientSession,
        timeout: int | float = 10
    ) -> dict:
        """
        Récupère l'état de santé et l'historique d'un utilisateur.
        
        Cette méthode retourne des statistiques sur l'utilisation du compte,
        incluant l'historique des analyses et leur répartition par catégorie.
        
        Parameters
        ----------
        username : str
            Nom d'utilisateur.
        password : str
            Mot de passe.
        salt : str
            Sel de chiffrement.
        token : str
            Token JWT valide.
        session : aiohttp.ClientSession
            Session HTTP à utiliser.
        timeout : int | float, optional
            Timeout en secondes. Par défaut 10.
        
        Returns
        -------
        dict
            {
                "errors": list[str],
                "status_code": int,
                "success": bool,
                "result": {
                    "history": dict,          # {prompt: label, ...}
                    "username": str,
                    "num_analyse": int,       # Nombre total d'analyses
                    "stats": dict             # {label: count, ...}
                }
            }
        
        Examples
        --------
        >>> async with aiohttp.ClientSession() as session:
        ...     health = await sdk.health_async(
        ...         username="alice",
        ...         password="secret",
        ...         salt=salt,
        ...         token=token,
        ...         session=session
        ...     )
        ...     if health["success"]:
        ...         print(f"Nombre d'analyses : {health['result']['num_analyse']}")
        ...         print(f"Répartition : {health['result']['stats']}")
        """
        result = {
            "errors": [],
            "status_code": None,
            "success": False,
            "result": {}
        }
        
        if not session:
            result["errors"].append("Session HTTP requise")
            return result
        
        if not verify_salt(salt):
            result["errors"].append("Salt invalide")
            return result
        
        try:
            json_data = {
                "username": username,
                "password": password,
                "salt": salt,
                "token": token,
                "verify_connect": False
            }
            
            async with session.post(
                url=_HEALTH_URL,
                json=json_data,
                timeout=aiohttp.ClientTimeout(total=float(timeout))
            ) as response:
                result["status_code"] = response.status
                
                if response.ok:
                    request_result = await response.json()
                    result["result"] = request_result
                    result["success"] = True
                    return result
                
                error_data = await response.json()
                
                # Gestion automatique du token expiré
                if response.status == 401 and error_data.get("detail") == "TOKEN_EXPIRED":
                    new_token = await self.refresh_token(
                        username=username,
                        token=token,
                        salt=salt,
                        session=session
                    )
                    if new_token:
                        return await self.health_async(
                            username=username,
                            password=password,
                            salt=salt,
                            token=new_token,
                            session=session,
                            timeout=timeout
                        )
                
                result["errors"].append(f"Erreur API : {error_data.get('detail', 'Erreur inconnue')}")
                return result
                
        except asyncio.TimeoutError:
            result["errors"].append(f"Timeout après {timeout} secondes")
            return result
        except aiohttp.ClientError as e:
            result["errors"].append(f"Erreur réseau : {str(e)}")
            return result
        except Exception as e:
            result["errors"].append(f"Erreur inattendue : {str(e)}")
            return result
    
    def health(self, *args, **kwargs) -> dict:
        """
        Version synchrone de health_async().
        
        See Also
        --------
        health_async : Version asynchrone avec documentation détaillée
        """
        return asyncio.run(self.health_async(*args, **kwargs))


# ==================== EXEMPLE D'UTILISATION ====================

if __name__ == "__main__":
    USERNAME = "test_user"    
    PASSWORD = "password"
    SALT = b'$2b$12$ATMNYOv6TKJpTm7o1GTFYO'.decode()
    PROMPT = "Hello, how are you ?"
    import json
    
    sdk = ContextGuardSDK()
    
    async def test():
        async with aiohttp.ClientSession() as session:
            # Connexion
            c_result = await sdk.connect_async(
                USERNAME, PASSWORD, SALT,
                connect=False,
                session=session
            )
            
            if c_result["errors"] or not c_result["success"]:
                if "Username is not available" in c_result.get("result", {}).get("reason", ""):
                    c_result = await sdk.connect_async(
                        USERNAME, PASSWORD, SALT,
                        connect=True,
                        session=session
                    )
                else:
                    print("Erreur de connexion !")
                    print(c_result)
                    return
            
            print("Connexion réussie !")
            token = c_result["result"]["token"]
            
            # Analyse
            a_result = await sdk.secure_prompt_async(
                username=USERNAME,
                password=PASSWORD,
                salt=SALT,
                token=token,
                prompts=[PROMPT],
                session=session
            )
            
            print("Analyse :", json.dumps(a_result, indent=2))
    
    asyncio.run(test())