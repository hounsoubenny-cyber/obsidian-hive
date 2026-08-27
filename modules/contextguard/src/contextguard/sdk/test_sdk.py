#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr  8 16:22:29 2026

@author: hounsousamuel
"""

import os
import sys
import json
import asyncio
import aiohttp
from datetime import datetime

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from contextguard.sdk.contextguard_py_sdk import ContextGuardSDK
SDK = ContextGuardSDK()
connect_async = SDK.connect_async
secure_prompt_async = SDK.secure_prompt_async



def print_separator(char="=", length=60):
    print(char * length)


def print_title(title):
    print_separator()
    print(f"🤖 {title}")
    print_separator()
    print()


def print_section(title, emoji="📌"):
    print(f"\n{emoji} {title}")
    print("-" * 40)


def print_success(message):
    print(f"   ✅ {message}")


def print_error(message):
    print(f"   ❌ {message}")


def print_info(message):
    print(f"   ℹ️ {message}")


def print_warning(message):
    print(f"   ⚠️ {message}")


async def test_sdk():
    """Fonction de test principale"""
    
    # Configuration
    USERNAME = "test_user"
    PASSWORD = "password"
    SALT = b'$2b$12$ATMNYOv6TKJpTm7o1GTFYO'.decode()
    TEST_PROMPTS = [
        "Hello, how are you ?",
    ]
    
    # En-tête
    print_title("CONTEXTGUARD SDK - TEST SUITE")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    async with aiohttp.ClientSession() as session:
        
        # ==================== ÉTAPE 1 : CONNEXION ====================
        print_section("AUTHENTIFICATION", "🔐")
        
        # D'abord essayer avec connect=False
        c_result = await connect_async(
            USERNAME, PASSWORD, SALT,
            connect=False,
            session=session
        )
        
        # Si l'utilisateur n'existe pas, on le crée avec connect=True
        if c_result.get("errors") or not c_result.get("success", False):
            reason = c_result.get("result", {}).get("reason", "")
            if "Username is not available" in reason:
                print_info("Utilisateur inexistant, création en cours...")
                c_result = await connect_async(
                    USERNAME, PASSWORD, SALT,
                    connect=True,
                    session=session
                )
            else:
                print_error(f"Échec : {c_result.get('errors', ['Unknown error'])[0]}")
                return
        
        if not c_result.get("success", False):
            print_error("Échec de l'authentification")
            return
        
        print_success(f"Connecté en tant que : {USERNAME}")
        print(f"   🔑 Token : {c_result['result']['token'][:50]}...")
        print(f"   🧂 Salt : {c_result['result']['salt']}")
        print(f"   📌 État : {c_result['result'].get('state', 'unknown')}")
        
        token = c_result["result"]["token"]
        
        # ==================== ÉTAPE 2 : ANALYSE ====================
        print_section("ANALYSE DES PROMPTS", "🔍")
        
        a_result = await secure_prompt_async(
            username=USERNAME,
            password=PASSWORD,
            salt=SALT,
            token=token,
            threasholds=[0.5],
            prompts=TEST_PROMPTS,
            timeout=40,
            session=session
        )
        
        if a_result.get("errors"):
            print_error(f"Erreur : {a_result['errors']}")
            return
        
        # Affichage des résultats
        results = a_result.get("result", {}).get("result", {})
        for prompt, data in results.items():
            label = data.get("label", "unknown")
            prob = data.get("prob", 0)
            threshold = data.get("threshold", 0.5)
            
            emoji = "🔴" if label == "injection" else "🟢" if label == "safe" else "🟡"
            
            print(f"\n   📝 Prompt : \"{prompt}\"")
            print(f"      {emoji} Label    : {label.upper()}")
            print(f"      📊 Probabilité : {prob:.2%}")
            print(f"      🎯 Seuil      : {threshold:.2%}")
        
        # ==================== ÉTAPE 3 : TEST REFRESH TOKEN ====================
        print_section("REFRESH TOKEN", "🔄")
        await asyncio.sleep(4)
        refresh_result = await secure_prompt_async(
            username=USERNAME,
            password=PASSWORD,
            salt=SALT,
            token=token,
            threasholds=[0.5],
            prompts=["Test après expiration"],
            timeout=40,
            session=session
        )
        
        if refresh_result.get("errors"):
            print_warning(f"Refresh échoué : {refresh_result['errors']}")
        else:
            new_token = refresh_result.get("token")
            if new_token and new_token != token:
                print_success("Token rafraîchi avec succès")
                print(f"   🔑 Nouveau token : {new_token[:50]}...")
            else:
                print_success("Token toujours valide")
        
        # ==================== CONCLUSION ====================
        print()
        print_separator()
        print("✅ TESTS RÉUSSIS")
        print_separator()


def run_test():
    asyncio.run(test_sdk())


if __name__ == "__main__":
    run_test()