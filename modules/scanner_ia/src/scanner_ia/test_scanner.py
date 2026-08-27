#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 15 23:39:46 2026

@author: hounsousamuel

Fonction de test rapide pour ScannerIA
Usage: python test_scan.py
"""

import os, sys
import nest_asyncio

nest_asyncio.apply()
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

from scanner_ia.main_scanner import Scanner, MODEL_DIR

# Tentative d'import Rich pour l'affichage amélioré
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None
scanner = None

def test_scan(
    url: str,
    active: bool = True,
    debug: bool = False,
    limit_payloads: int = 10,
    helpers: list = None, 
    raise_on_helper_error=True,
    model_dir: str = MODEL_DIR,
    use_ml=True
):
    """
    Test rapide du scanner sur une URL
    
    Args:
        url: URL cible (ex: http://localhost:8080)
        active: Activer le scan actif (fuzzer)
        debug: Mode debug (logs détaillés)
        limit_payloads: Limite de payloads par vulnérabilité
    """
    global scanner
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold cyan]🔬 TEST SCANNER[/bold cyan]\n"
            f"URL: {url}\n"
            f"Scan actif: {'✅ OUI' if active else '❌ NON'}\n"
            f"Debug: {'✅ OUI' if debug else '❌ NON'}",
            title="HiveMind Scout",
            border_style="cyan"
        ))
    else:
        print("\n" + "=" * 70)
        print(f"🔬 TEST SCANNER - {url}")
        print("=" * 70)
        print(f"Mode scan actif : {'✅ OUI' if active else '❌ NON'}")
        print(f"Mode debug      : {'✅ OUI' if debug else '❌ NON'}")
        print("-" * 70)
    
    # Configuration
    CONFIG_PATH = "shieldai_scanner.config.json5"
    helpers = helpers or []
    import scanner_ia.main_scanner as ms
    ms._ML_AVAILABLE = use_ml
    
    if not os.path.exists(CONFIG_PATH):
        if RICH_AVAILABLE:
            console.print(f"[red]❌ Fichier de config introuvable : {CONFIG_PATH}[/red]")
        else:
            print(f"❌ Fichier de config introuvable : {CONFIG_PATH}")
        return None
    
    try:
        # Initialisation
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("🔧 Initialisation du scanner...", total=None)
                scanner = Scanner(
                    config_path=CONFIG_PATH,
                    active_scan=active,
                    use_cache=False,
                    debug=debug,
                    semaphore=10,
                    limit_payloads=limit_payloads,
                    use_semantic=False,
                    model_dir=model_dir or MODEL_DIR
                )
                progress.update(task, completed=True)
        else:
            print("\n🔧 Initialisation du scanner...")
            scanner = Scanner(
                config_path=CONFIG_PATH,
                active_scan=active,
                use_cache=True,
                debug=debug,
                semaphore=10,
                limit_payloads=limit_payloads,
                use_semantic=False,
                model_dir=model_dir or MODEL_DIR
            )
        # return scanner
        
        if RICH_AVAILABLE:
            console.print("[green]✅ Scanner initialisé[/green]")
            console.print(f"[bold yellow]🚀 Lancement du scan sur {url}...[/bold yellow]")
            console.print("[dim]⏳ Cela peut prendre quelques secondes...[/dim]\n")
        else:
            print("✅ Scanner initialisé")
            print(f"\n🚀 Lancement du scan sur {url}...")
            print("⏳ Cela peut prendre quelques secondes...\n")
        
        # Lancement du scan
        result = scanner.scan_sync(
            url=url,
            fetch=True,
            limit_vuln_for_fuzzer=None if active else None,
            time_between_for_fuzzer=0.01,
            allowed_domains=None,
            dynamic_timeout_for_fuzzer=False,
            threshold=0.5,
            use_cache=False,
            put_result_in_cache=True,
            helpers=helpers,
            raise_on_helper_error=raise_on_helper_error
        )
        
        # =========================================================
        # AFFICHAGE DES RÉSULTATS
        # =========================================================
        
        if result is None:
            if RICH_AVAILABLE:
                console.print("[red]❌ Aucun résultat[/red]")
            else:
                print("❌ Aucun résultat")
            return None
        
        phases = getattr(result, 'phases_result', {})
        timings = getattr(result, 'timings', {})
        
        if RICH_AVAILABLE:
            # Tableau des timings
            time_table = Table(title="⏱️ Temps par phase", style="cyan")
            time_table.add_column("Phase", style="bold")
            time_table.add_column("Durée", justify="right")
            for phase, t in sorted(timings.items(), key=lambda x: -x[1]):
                time_table.add_row(phase, f"{t:.2f}s")
            console.print(time_table)
        else:
            print(f"\n⏱️ Temps total : {result.elapsed:.2f}s")
            for phase, t in timings.items():
                print(f"   ├─ {phase:<35} : {t:.2f}s")
        
        # Pages crawlées
        analyzer = phases.get("analyzer_helper(crawl_and_parse)")
        if analyzer:
            n_pages = len(getattr(analyzer, 'elements', {}))
            if RICH_AVAILABLE:
                console.print(f"\n[bold]🕷️ Pages crawlées :[/bold] {n_pages}")
                if n_pages > 0:
                    urls = list(getattr(analyzer, 'elements', {}).keys())[:5]
                    for u in urls:
                        console.print(f"   └─ [dim]{u[:80]}...[/dim]")
            else:
                print(f"\n🕷️ Pages crawlées : {n_pages}")
                if n_pages > 0:
                    urls = list(getattr(analyzer, 'elements', {}).keys())[:5]
                    for u in urls:
                        print(f"   └─ {u[:80]}...")
        
        # Vulnérabilités fuzzer
        fuzzer = phases.get("fuzzer")
        if fuzzer:
            stats = getattr(fuzzer, 'stats', {})
            total_tests = stats.get('total_tests', 0)
            total_vulns = stats.get('total_vulns', 0)
            vuln_count = stats.get('vuln_count', {})
            
            if RICH_AVAILABLE:
                console.print(f"\n[bold]⚡ FUZZER :[/bold] {total_tests} tests, {total_vulns} vulnérabilités")
                if vuln_count:
                    vuln_table = Table(title="Vulnérabilités détectées", style="red")
                    vuln_table.add_column("Type", style="bold")
                    vuln_table.add_column("Occurrences", justify="right")
                    for vuln, count in sorted(vuln_count.items(), key=lambda x: -x[1]):
                        vuln_table.add_row(vuln, str(count))
                    console.print(vuln_table)
            else:
                print(f"\n⚡ FUZZER : {total_tests} tests, {total_vulns} vulnérabilités")
                if vuln_count:
                    print("   Vulnérabilités détectées :")
                    for vuln, count in sorted(vuln_count.items(), key=lambda x: -x[1]):
                        print(f"   ├─ {vuln:<25} : {count}")
        
        # Prédictions ML
        ml = phases.get("scanner_ia_preds", {})
        proba = ml.get("proba", {})
        if proba:
            if RICH_AVAILABLE:
                console.print(f"\n[bold]🤖 PRÉDICTIONS ML[/bold] ({len(proba)} pages)")
                for url, probs in list(proba.items())[:3]:
                    safe_prob = probs.get("SAFE", 0)
                    status = "🟢 SAFE" if safe_prob > 0.5 else "🔴 VULNÉRABLE"
                    console.print(f"\n[bold cyan]{url[:60]}...[/bold cyan]")
                    console.print(f"   Statut : {status} (SAFE={safe_prob:.3f})")
                    top3 = sorted([(k, v) for k, v in probs.items() if k != "SAFE"], key=lambda x: -x[1])[:3]
                    if top3:
                        for vuln, prob in top3:
                            bar = "█" * int(prob * 20)
                            console.print(f"      {vuln:<20} {bar} {prob:.3f}")
            else:
                print(f"\n🤖 PRÉDICTIONS ML ({len(proba)} pages)")
                for url, probs in list(proba.items())[:3]:
                    safe_prob = probs.get("SAFE", 0)
                    status = "🟢 SAFE" if safe_prob > 0.5 else "🔴 VULNÉRABLE"
                    print(f"\n   {url[:60]}...")
                    print(f"   Statut : {status} (SAFE={safe_prob:.3f})")
                    top3 = sorted([(k, v) for k, v in probs.items() if k != "SAFE"], key=lambda x: -x[1])[:3]
                    if top3:
                        print("   Top vulnérabilités :")
                        for vuln, prob in top3:
                            print(f"      └─ {vuln:<20} : {prob:.3f}")
        
        # Rapports
        report = phases.get("report_generation", {})
        if report:
            if RICH_AVAILABLE:
                console.print(f"\n[bold green]📄 RAPPORTS générés dans result_scan/[/bold green]")
            else:
                print(f"\n📄 RAPPORTS générés dans result_scan/")
        
        # Bannière de fin
        if RICH_AVAILABLE:
            console.print(Panel(
                f"[bold green]✅ SCAN TERMINÉ[/bold green]\n"
                f"Temps total : {result.elapsed:.2f}s",
                border_style="green"
            ))
        else:
            print("\n" + "=" * 70)
            print(f"✅ SCAN TERMINÉ - {result.elapsed:.2f}s")
            print("=" * 70)
        
        return result
        
    except FileNotFoundError as e:
        if RICH_AVAILABLE:
            console.print(f"[red]❌ Erreur: {e}[/red]")
        else:
            print(f"❌ Erreur: {e}")
    except ConnectionError as e:
        if RICH_AVAILABLE:
            console.print(f"[red]❌ URL inaccessible: {e}[/red]")
        else:
            print(f"❌ URL inaccessible: {e}")
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[red]❌ Erreur inattendue: {e}[/red]")
        else:
            print(f"❌ Erreur inattendue: {e}")
        if debug:
            import traceback
            traceback.print_exc()
    
    return None


# =========================================================
# POINT D'ENTRÉE
# =========================================================
if __name__ == "__main__":
    from scanner_ia.scanner_utils.helpers import dvwa_full_setup
    # ===== CONFIGURATION ICI =====
    URL = "http://localhost:8090"      # ← Change ici l'URL à scanner
    ACTIVE = True                       # ← True = scan actif, False = passif
    DEBUG = True                       # ← True = logs détaillés
    LIMIT_PAYLOADS = None                 # ← Limite de payloads (None = illimité)
    # ==============================
    helpers = [
        [dvwa_full_setup, (URL, "admin", "password", "low")]
    ]
    
    r = test_scan(
        url=URL,
        active=ACTIVE,
        debug=DEBUG,
        limit_payloads=LIMIT_PAYLOADS,
        model_dir="model_scanner_chain_mvp",
        use_ml=True,
        # helpers=helpers, 
        # raise_on_helper_error=True
    )
    if r is not None:
        import joblib
        joblib.dump(r.to_dict(True), "./data1.pkl", compress=9)