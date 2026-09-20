#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 09:16:09 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import base64
import bcrypt
import asyncio
from datetime import datetime
from collections import Counter
from fastapi.responses import JSONResponse
from fastapi import APIRouter, HTTPException, status, Request

from modules_utils.limiter import limiter
from contextguard.api.models import (
    LoginData, AnalyseRequest, RefreshData, Data,
    DeleteAccountData, LogoutData
)
from contextguard.api.state import (
    get_db, get_model, get_onnx,
    verify_username, USERS, SESSION_TTL,
    verify_username_is_avalable,
)
from contextguard.api.utils import (
    USERNAME_NOT_AVAILABLE_REASON,
    USER_NOT_REGISTERED_REASON,
    VERIFY_CONNECT_ERROR
)
from contextguard.model.model_guard import PredictWrapper
from contextguard.api.config import (
    LIMITE as limite, MATCH, ONNX_PATH, USE_ONNX,
    CONTEXTGUARD_JWT_SECRET,
)
from contextguard.contextguard_utils.utils import (
    FernetManager, checkpw, hashpw,
)
from contextguard.contextguard_utils.jwt_utils import create_token


router = APIRouter()


async def _analyse_one(model: PredictWrapper, prompt: str, threshold: float):
    prob, pred = model.predict(prompt, threshold, USE_ONNX, get_onnx(), ONNX_PATH)
    if isinstance(pred, list):
        return prompt, prob[0], MATCH[pred[0]]
    pred = pred[0].item()
    prob = prob[0][pred].item()
    return prompt, prob, MATCH[pred]


# ═══════════════════════════════════════════════════════════
# /login
# ═══════════════════════════════════════════════════════════

@router.post("/login")
@limiter.limit(f"{limite}/minute")
async def login(request: Request, login_data: LoginData):
    try:
        name = login_data.username
        password = login_data.password
        connect = login_data.connect
        db = get_db()

        # ── Création de compte ────────────────────────────
        if not connect:
            if not verify_username_is_avalable(name):
                return JSONResponse({
                    "state": "Unknown",
                    "success": False,
                    "username": name,
                    "reason": USERNAME_NOT_AVAILABLE_REASON,
                    "salt": "",
                    "token": "",
                }, status_code=status.HTTP_200_OK)

            salt = FernetManager._gen_salt().decode()
            password_hash = hashpw(password)

            result = db.add_user(
                username=name,
                password=password_hash,
                salt=salt,
            )
            if not result["success"]:
                raise HTTPException(
                    detail=f"Erreur serveur : {result['error']}",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            USERS.set(name, salt, password_hash, ttl=SESSION_TTL)

            return JSONResponse({
                "state": "new user",
                "username": name,
                "success": True,
                "reason": "",
                "salt": salt,
                "token": create_token(
                    {"username": name},
                    key=CONTEXTGUARD_JWT_SECRET,
                ),
            })

        # ── Connexion ─────────────────────────────────────
        result = db.get_user_by_name(name)
        if result["error"]:
            raise HTTPException(
                detail=f"Erreur serveur : {result['error']}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if not (result["user"] and result["success"]):
            return JSONResponse({
                "state": "Unknown",
                "success": False,
                "reason": USER_NOT_REGISTERED_REASON,
                "salt": "",
                "token": "",
            })

        user = result["user"][0]
        if not checkpw(password, hashed=user.password):
            raise HTTPException(
                detail="Mot de passe incorrect !",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if not user.salt:
            raise HTTPException(
                detail="Salt manquant en base — veuillez recréer le compte.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        USERS.set(name, user.salt, user.password, ttl=SESSION_TTL)

        return JSONResponse({
            "state": "old user",
            "username": name,
            "success": True,
            "reason": "",
            "salt": user.salt,  
            "token": create_token(
                {"username": name},
                key=CONTEXTGUARD_JWT_SECRET,
            ),
        })

    except HTTPException:
        raise
        
    except Exception as e:
        print("Erreur dans la route login :", str(e))
        raise HTTPException(
            detail=f"Erreur dans login : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ═══════════════════════════════════════════════════════════
# /health
# ═══════════════════════════════════════════════════════════

@router.post("/health")
@limiter.limit(f"{limite}/minute")
async def health(request: Request, data: Data):
    try:
        name = data.username
        password = data.password
        token = data.token
        verify_connect = data.verify_connect

        verify_username(name, token, verify_connect=verify_connect)

        entry = USERS.get(name)
        if entry is None:
            raise HTTPException(
                detail=VERIFY_CONNECT_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if not checkpw(password, hashed=entry.password_hash):
            raise HTTPException(
                detail="Mot de passe incorrect !",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Récupère l'historique chiffré
        db = get_db()
        result = db.get_user_by_name(name)
        if not (result["success"] and result["user"]):
            raise HTTPException(
                detail=USER_NOT_REGISTERED_REASON,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        user = result["user"][0]

        fm = FernetManager(password, entry.salt)
        history = {}
        for k, v in (user.history or {}).items():
            if isinstance(v, str) and v:
                v = fm.decrypt(base64.b64decode(v.encode())).decode()
            history[k] = v

        return JSONResponse({
            "history": history,
            "username": name,
            "num_analyse": len(history),
            "stats": dict(Counter(history.values())),
        })

    except HTTPException:
        raise
    except Exception as e:
        print("Erreur dans la route health :", str(e))
        raise HTTPException(
            detail=f"Erreur dans health : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ═══════════════════════════════════════════════════════════
# /analyse
# ═══════════════════════════════════════════════════════════

@router.post("/analyse")
@limiter.limit(f"{limite + 20}/minute")
async def analyse(request: Request, analyse_data: AnalyseRequest):
    try:
        name = analyse_data.username
        password = analyse_data.password
        token = analyse_data.token
        verify_connect = analyse_data.verify_connect

        verify_username(name, token, verify_connect=verify_connect)

        entry = USERS.get(name)
        if entry is None:
            raise HTTPException(
                detail=VERIFY_CONNECT_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if not checkpw(password, hashed=entry.password_hash):
            raise HTTPException(
                detail="Mot de passe incorrect !",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        fm = FernetManager(password, entry.salt)
        model = get_model()

        prompts = analyse_data.prompts
        thresholds = analyse_data.thresholds

        if not isinstance(prompts, list):
            prompts = [prompts]
        if not isinstance(thresholds, list):
            thresholds = [thresholds] * len(prompts)
        thresholds = [th if 0 <= th <= 1 else 0.5 for th in thresholds]

        tasks = [
            asyncio.create_task(_analyse_one(model, prompt, th))
            for prompt, th in zip(prompts, thresholds)
        ]
        gather_result = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        history = {}
        for prompt, th, result in zip(prompts, thresholds, gather_result):
            results[prompt] = {"threshold": th}
            if isinstance(result, Exception):
                results[prompt]["label"] = "error"
                results[prompt]["prob"] = 1.0
            else:
                _, prob, label = result
                results[prompt]["label"] = label
                results[prompt]["prob"] = prob
                history[prompt] = base64.b64encode(fm.encrypt(label)).decode()

        db = get_db()
        db_result = db.update_history_by_name(name, history)

        return JSONResponse({
            "result": results,
            "history_update_with_success": db_result["success"],
        })

    except HTTPException:
        raise
        
    except Exception as e:
        print("Erreur dans la route analyse :", str(e))
        raise HTTPException(
            detail=f"Erreur dans analyse : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ═══════════════════════════════════════════════════════════
# /refresh_token
# ═══════════════════════════════════════════════════════════

@router.post("/refresh_token")
async def _refresh_token(request: Request, data: RefreshData):
    try:
        verify_username(
            name=data.username, token=data.token,
            verify_exp=False, verify_connect=False,
        )
        return {
            "token": create_token(
                {"username": data.username},
                key=CONTEXTGUARD_JWT_SECRET,
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        print("Erreur dans refresh_token :", str(e))
        raise HTTPException(
            detail=f"Erreur dans refresh_token : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

# ═══════════════════════════════════════════════════════════
# /logout
# ═══════════════════════════════════════════════════════════

@router.post("/logout")
@limiter.limit(f"{limite}/minute")
async def logout(request: Request, data: LogoutData):
    """
    Révoque la session serveur d'un utilisateur.

    - Vérifie la signature du JWT (mais pas son expiration — un token
      fraîchement expiré peut quand même être révoqué).
    - Purge l'entrée correspondante dans ``USERS``.

    Idempotent : un logout sur une session déjà purgée renvoie succès.
    """
    try:
        # Vérifie que le token est bien signé pour ce username
        try:
            verify_username(
                name=data.username, token=data.token,
                verify_exp=False, verify_connect=False,
            )
        except HTTPException:
            raise

        # Purge la session
        USERS.delete(data.username)

        return JSONResponse({
            "success": True,
            "username": data.username,
            "message": "Session révoquée.",
        })

    except HTTPException:
        raise
        
    except Exception as e:
        print("Erreur dans logout :", str(e))
        raise HTTPException(
            detail=f"Erreur dans logout : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ═══════════════════════════════════════════════════════════
# /delete_account
# ═══════════════════════════════════════════════════════════

@router.post("/delete_account")
@limiter.limit(f"{limite}/minute")
async def delete_account(request: Request, data: DeleteAccountData):
    """
    Supprime définitivement le compte d'un utilisateur.

    Sécurité :
    - Vérifie la signature du JWT.
    - Vérifie aussi le mot de passe.
    - Purge la session du cache.
    - Supprime la ligne en DB.

    ⚠️  Opération **irréversible**. Toute la donnée (historique inclus)
    est perdue.
    """
    try:
        name = data.username
        password = data.password
        token = data.token

        # 1. Token valide ?
        verify_username(name, token, verify_connect=False)

        # 2. Récupère l'utilisateur en DB
        db = get_db()
        result = db.get_user_by_name(name)
        if result["error"]:
            raise HTTPException(
                detail=f"Erreur serveur : {result['error']}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        if not (result["user"] and result["success"]):
            raise HTTPException(
                detail=USER_NOT_REGISTERED_REASON,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        user = result["user"][0]

        # 3. Vérifie le password
        if not checkpw(password, hashed=user.password):
            raise HTTPException(
                detail="Mot de passe incorrect !",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # 4. Purge la session
        USERS.delete(name)

        # 5. Supprime en DB
        del_result = db.delete_user_by_name(name)
        if not del_result["success"]:
            raise HTTPException(
                detail=f"Erreur suppression : {del_result['error']}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return JSONResponse({
            "success": True,
            "username": name,
            "message": "Compte supprimé.",
        })

    except HTTPException:
        raise
        
    except Exception as e:
        print("Erreur dans delete_account :", str(e))
        raise HTTPException(
            detail=f"Erreur dans delete_account : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
        

@router.get("/salt")
@limiter.limit(f"{limite}/minute")
def _get_salt(request: Request):
    return {
        "salt": bcrypt.gensalt().decode(),
        "datetime": datetime.utcnow()
    }