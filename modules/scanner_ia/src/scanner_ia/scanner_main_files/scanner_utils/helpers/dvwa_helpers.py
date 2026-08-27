#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Helper d'authentification pour DVWA
Basé sur le crawler qui fonctionne
"""



import aiohttp
from bs4 import BeautifulSoup
import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
from scanner_ia.scanner_utils.logger import get_logger

logger = get_logger()

async def dvwa_ensure_db(session: aiohttp.ClientSession, base_url: str) -> None:
    """
    Vérifie si DVWA a besoin d'un setup.php, et le fait automatiquement si besoin.
    """
    setup_url = f"{base_url.rstrip('/')}/setup.php"

    async with session.get(setup_url) as resp:
        html = await resp.text()

    if "Create / Reset Database" not in html:
        return  # déjà setup, rien à faire

    soup = BeautifulSoup(html, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    user_token = token_input["value"] if token_input else ""

    data = {"create_db": "Create / Reset Database", "user_token": user_token}

    async with session.post(setup_url, data=data) as resp:
        result_html = await resp.text()
        if "setup was successful" in result_html.lower() or resp.status == 200:
            logger.success("✅ DVWA: Base de données créée/réinitialisée")
        else:
            raise Exception("DVWA: Échec de la création de la BDD")


async def dvwa_login(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "password",
) -> bool:
    """
    Authentification DVWA
    """
    login_url = f"{base_url.rstrip('/')}/login.php"

    async with session.get(login_url) as resp:
        html = await resp.text()
        soup = BeautifulSoup(html, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        user_token = token_input["value"] if token_input else ""

    login_data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": user_token,
    }

    async with session.post(login_url, data=login_data) as resp:
        html = await resp.text()
        final_url = str(resp.url)
        # print(html, final_url)
        if "Login failed" not in html and 'index.php' in final_url:
            logger.success("✅ DVWA: Connecté avec succès")
            return True
        else:
            raise Exception("DVWA: Échec de connexion")


async def dvwa_set_security_level(
    session: aiohttp.ClientSession, base_url: str, level: str = "low"
) -> bool:
    """
    Règle le niveau de sécurité DVWA
    """
    security_url = f"{base_url.rstrip('/')}/security.php"

    async with session.get(security_url) as resp:
        html = await resp.text()
        soup = BeautifulSoup(html, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        user_token = token_input["value"] if token_input else ""

    data = {"security": level, "seclev_submit": "Submit", "user_token": user_token}

    async with session.post(security_url, data=data) as resp:
        pass

    logger.success(f"✅ DVWA: Niveau de sécurité = {level}")
    return True


async def dvwa_full_setup(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    security_level: str = "low",
) -> bool:
    """
    Configuration complète DVWA
    """
    logger.info(f"🔐 DVWA: Authentification sur {base_url}")
    
    await dvwa_ensure_db(session, base_url)   
    await dvwa_login(session, base_url, username, password)
    await dvwa_set_security_level(session, base_url, security_level)
    # print(f"  Cookies Dans session auth: {list(session.cookie_jar)}")
    logger.success("✅ DVWA: Configuration terminée")
    return True


# Test
if __name__ == "__main__":
    import asyncio
    import aiohttp

    URL = "http://localhost:8081"

    async def main():
        logger.info("🚀 Test du helper DVWA")
        async with aiohttp.ClientSession() as session:
            await dvwa_full_setup(session, URL, "admin", "password", "low")
            # Tester l'accès
            async with session.get(f"{URL}/vulnerabilities/sqli/") as resp:
                html = await resp.text()
                if "SQL Injection" in html:
                    logger.success("✅ Accès réussi à la page SQLi")
                else:
                    logger.error("❌ Accès échoué")
    
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.run(main())
