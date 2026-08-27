#!/usr/bin/env python3
"""
Benchmark — ShieldAI Crawler vs Playwright Crawler sur SPA.

Usage:
    1. Lance la SPA : python spa_server/spa_server.py
    2. Lance ce benchmark : python benchmark.py
"""

import asyncio
import aiohttp
import time
import sys
import os
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
# ── Import Playwright crawler ─────────────────────────────────────────────────
from scanner_ia.BENCHMARK_CRAWLER.playwright_crawler import PlaywrightCrawler
from scanner_ia.core.fetcher import PlaywrightPool

# ── Import ShieldAI crawler ───────────────────────────────────────────────────
# Adapte ce chemin selon ton projet

try:
    from scanner_ia.core.crawler import Crawler as ShieldAICrawler
    SHIELDAI_AVAILABLE = True
except ImportError:
    SHIELDAI_AVAILABLE = False
    print("⚠️  ShieldAI crawler non trouvé — on teste uniquement Playwright")

TARGET = "http://localhost:5000"

# Toutes les routes que la SPA expose
EXPECTED_ROUTES = {
    "http://localhost:5000",
    "http://localhost:5000/login",
    "http://localhost:5000/dashboard",
    "http://localhost:5000/profile",
    "http://localhost:5000/admin",
    "http://localhost:5000/settings",
    "http://localhost:5000/admin/users",
    "http://localhost:5000/admin/reports",
    "http://localhost:5000/admin/config",
    "http://localhost:5000/api/users",
    "http://localhost:5000/api/stats",
}


def normalize(urls: set) -> set:
    """Normalise les URLs pour comparaison."""
    result = set()
    for url in urls:
        url = url.rstrip("/").split("?")[0].split("#")[0]
        result.add(url)
    return result


def print_comparison(
    shieldai_urls: set,
    playwright_urls: set,
    shieldai_time: float,
    playwright_time: float,
):
    expected = normalize(EXPECTED_ROUTES)
    sa_norm  = normalize(shieldai_urls)
    pw_norm  = normalize(playwright_urls)

    sa_found    = sa_norm & expected
    pw_found    = pw_norm & expected
    sa_missed   = expected - sa_norm
    pw_missed   = expected - pw_norm
    sa_extra    = sa_norm  - expected
    pw_extra    = pw_norm  - expected

    print("\n" + "=" * 70)
    print("📊  BENCHMARK — ShieldAI Crawler vs Playwright Crawler")
    print("=" * 70)

    print(f"\n{'Route':<45} {'ShieldAI':^10} {'Playwright':^10}")
    print("-" * 70)
    for route in sorted(expected):
        sa  = "✅" if route in sa_norm else "❌"
        pw  = "✅" if route in pw_norm else "❌"
        print(f"{route:<45} {sa:^10} {pw:^10}")

    print("\n" + "-" * 70)
    print(f"{'Routes trouvées / attendues':<45} "
          f"{f'{len(sa_found)}/{len(expected)}':^10} "
          f"{f'{len(pw_found)}/{len(expected)}':^10}")

    print(f"{'Taux de détection':<45} "
          f"{f'{len(sa_found)/len(expected)*100:.0f}%':^10} "
          f"{f'{len(pw_found)/len(expected)*100:.0f}%':^10}")

    print(f"{'Temps':<45} "
          f"{f'{shieldai_time:.2f}s':^10} "
          f"{f'{playwright_time:.2f}s':^10}")

    if sa_missed:
        print(f"\n❌ Manqués par ShieldAI ({len(sa_missed)}) :")
        for r in sorted(sa_missed):
            print(f"   → {r}")

    if pw_missed:
        print(f"\n❌ Manqués par Playwright ({len(pw_missed)}) :")
        for r in sorted(pw_missed):
            print(f"   → {r}")

    if sa_extra:
        print(f"\n➕ Trouvés en plus par ShieldAI ({len(sa_extra)}) :")
        for r in sorted(sa_extra):
            print(f"   → {r}")

    print("\n" + "=" * 70)
    print("🏆  VERDICT")
    print("=" * 70)

    if len(sa_found) > len(pw_found):
        print("ShieldAI gagne sur la détection !")
    elif len(pw_found) > len(sa_found):
        gap = len(sa_missed)
        print(f"Playwright gagne — ShieldAI rate {gap} route(s) JS dynamiques.")
        if gap > 0:
            print("→ Solution : intégrer Playwright comme Ajax Spider dans ShieldAI.")
    else:
        print("Égalité sur la détection.")

    if shieldai_time < playwright_time:
        print(f"ShieldAI est {playwright_time/shieldai_time:.1f}x plus rapide.")
    else:
        print(f"Playwright est {shieldai_time/playwright_time:.1f}x plus rapide.")


async def run_shieldai(session: aiohttp.ClientSession) -> tuple[set, float]:
    try:
        """Lance le crawler ShieldAI et retourne les URLs + temps."""
        crawler = ShieldAICrawler(session=session, MAX_DEEPTH=3, MAX_PAGES=50, DEBUG=False, JOIN_TIMEOUT = 400)
        start   = time.time()
        result  = await crawler.crawl(TARGET, use_playwright=True)
        elapsed = time.time() - start
    
        urls = set()
        for worker in result.result:
            # print(worker.html_links, worker.other_links, worker.url)
            urls.add(worker.url)
            urls.update(worker.html_links)
        
        return urls, elapsed
    finally:
        await PlaywrightPool.close()


async def run_playwright() -> tuple[set, float]:
    """Lance le crawler Playwright et retourne les URLs + temps."""
    crawler = PlaywrightCrawler(TARGET, max_pages=50)
    start   = time.time()
    result  = await crawler.crawl()
    elapsed = time.time() - start
    return set(result["visited"]) | set(result["found_urls"]), elapsed


async def main():
    print(f"🎯 Cible : {TARGET}")
    print("Vérifie que la SPA tourne sur http://localhost:5000\n")

    # Vérifier que la SPA répond
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(TARGET, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status != 200:
                    print(f"❌ SPA non accessible (status {r.status})")
                    return
    except Exception:
        print("❌ SPA non accessible — lance d'abord : python spa_server/spa_server.py")
        return

    print("✅ SPA accessible\n")

    # ── ShieldAI ─────────────────────────────────────────────────────────────
    shieldai_urls, shieldai_time = set(), 0.0
    if SHIELDAI_AVAILABLE:
        print("🔍 Lancement ShieldAI crawler...")
        async with aiohttp.ClientSession() as session:
            shieldai_urls, shieldai_time = await run_shieldai(session)
        print(f"   → {len(shieldai_urls)} URLs trouvées en {shieldai_time:.2f}s")
    else:
        print("⚠️  ShieldAI non disponible — résultats vides")

    # ── Playwright ───────────────────────────────────────────────────────────
    print("\n🎭 Lancement Playwright crawler...")
    playwright_urls, playwright_time = await run_playwright()
    print(f"   → {len(playwright_urls)} URLs trouvées en {playwright_time:.2f}s")

    # ── Comparaison ──────────────────────────────────────────────────────────
    print_comparison(shieldai_urls, playwright_urls, shieldai_time, playwright_time)


if __name__ == "__main__":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    asyncio.run(main())
