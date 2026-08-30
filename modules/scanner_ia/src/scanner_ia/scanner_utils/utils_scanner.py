#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  5 16:59:52 2026

@author: hounsousamuel
"""

import asyncio
import aiohttp
import math
from collections import Counter
from nest_asyncio import apply

async def is_url_reachable(url: str, timeout: int = 5) -> bool:
    """
    Vérifie rapidement si une URL est atteignable

    Args:
        url: URL à tester
        timeout: Timeout en secondes (défaut: 5)

    Returns:
        bool: True si atteignable, False sinon
    """
    if not url:
        return False

    # Normalisation rapide
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.get(url, allow_redirects=True) as response:
                return response.status < 500  # 200-499 = OK (sauf 500+)
    except Exception:
        return False


async def quick_check(urls: list, timeout: int = 3) -> dict:
    """
    Vérifie rapidement plusieurs URLs

    Args:
        urls: Liste d'URLs à tester
        timeout: Timeout par URL

    Returns:
        dict: {url: bool}
    """
    tasks = [is_url_reachable(url, timeout) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return {url: isinstance(res, bool) and res for url, res in zip(urls, results)}


def calculate_entropy(string):
    """Calcule l'entropie de Shannon (mesure du désordre)"""
    if not string:
        return 0

    counter = Counter(string)
    length = len(string)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())

    return entropy


if __name__ == "__main__":
    # Test rapide
    apply()
    async def test():
        urls = [
            "https://google.com",
            "https://example.com",
            "https://url-qui-nexiste-pas.com",
            "http://localhost:8080",
            "http://localhost:5050/users/ssti-custom_template_field_form"
        ]

        print("🔍 Test de reachabilité:")
        for url in urls:
            result = await is_url_reachable(url)
            status = "✅" if result else "❌"
            print(f"  {status} {url}")

        print("\n📊 Test multiple:")
        results = await quick_check(urls)
        for url, ok in results.items():
            print(f"  {'✅' if ok else '❌'} {url}")

    asyncio.run(test())
