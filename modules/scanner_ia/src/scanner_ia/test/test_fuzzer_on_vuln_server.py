#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TEST SHIELDAI V2 - Fuzzer vs Serveur Vulnérable

Lance le serveur vulnérable, puis teste le fuzzer dessus.

Author: Samuel - ShieldAI
Date: 2026-03-12
"""

import os
import sys
import time
import asyncio, aiohttp
import subprocess
from pathlib import Path
from scanner_ia.scanner_utils.helpers import dvwa_full_setup
# Configuration
VULN_SERVER_PORT = 5000
VULN_SERVER_URL = f"http://localhost:{VULN_SERVER_PORT}"

from nest_asyncio import apply
apply()
# Couleurs terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    """Print header avec style"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.ENDC}\n")

def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.ENDC}")

def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}❌ {text}{Colors.ENDC}")

def print_info(text):
    """Print info message"""
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.ENDC}")

def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.ENDC}")

async def test_fuzzer():
    """
    Test le fuzzer sur le serveur vulnérable
    """
    print_header("🔥 TEST SHIELDAI V2 - FUZZER")
    
    # Import du fuzzer
    try:
        from scanner_ia.fuzzer.active_fuzzer import Fuzzer
        print_success("Fuzzer importé")
    except ImportError as e:
        print_error(f"Erreur import fuzzer: {e}")
        return
    
    # URLs à tester
    test_urls = [
        # XSS
        # f"{VULN_SERVER_URL}/xss/reflected?q=test",
        # f"{VULN_SERVER_URL}/xss/stored",
        
        # # SQLi
        # f"{VULN_SERVER_URL}/sqli/search?id=1",
        # f"{VULN_SERVER_URL}/sqli/login",
        
        # # CMDi
        # f"{VULN_SERVER_URL}/cmdi/ping",
        
        # # Directory Traversal
        # f"{VULN_SERVER_URL}/file/read?path=test.txt",
        
        # # IDOR
        # f"{VULN_SERVER_URL}/user/profile/1",
        
        # # CORS
        # f"{VULN_SERVER_URL}/api/data",
        
        # # Info Disclosure
        # f"{VULN_SERVER_URL}/.env",
        # f"{VULN_SERVER_URL}/debug",
        # VULN_SERVER_URL,
        VULN_SERVER_URL #+ "/vulnerabilities/xss_r/"
    ]
    
    print_info(f"Testing {len(test_urls)} URLs\n")
    
    # Créer fuzzer
    fuzzer = Fuzzer(debug=True, session=aiohttp.ClientSession())
    # await dvwa_full_setup(fuzzer.session, VULN_SERVER_URL, "admin", "password", "low")
    # Tester chaque URL
    results = {}
    for url in test_urls:
        print(f"\n{Colors.BOLD}Testing:{Colors.ENDC} {url}")
        print("-" * 70)
        
        try:
            # Lancer le fuzzing
            result = await fuzzer.test(test_urls, use_cache=False)
            
            # Analyser résultats
            if result:
                vulns_found = len(result.stats.get('vulns_url', []))
                total_tests = result.stats.get('total_tests', 0)
                elapsed = result.elapsed

                results[url] = {
                    'vulns_found': vulns_found,
                    'total_tests': total_tests,
                    'elapsed': elapsed
                }
                
                if vulns_found > 0:
                    print_success(f"Vulns found: {vulns_found} | Tests: {total_tests} | Time: {elapsed:.2f}s")
                else:
                    print_warning(f"No vulns | Tests: {total_tests} | Time: {elapsed:.2f}s")
            else:
                print_error("No result returned")
                
        except Exception as e:
            print_error(f"Error testing {url}: {e}")
            results[url] = {'error': str(e)}
    
    # Résumé final
    print_header("📊 RÉSULTATS FINAUX")
    
    total_vulns = sum(r.get('vulns_found', 0) for r in results.values())
    total_tests = sum(r.get('total_tests', 0) for r in results.values())
    total_time = sum(r.get('elapsed', 0) for r in results.values())
    
    print(f"\n{Colors.BOLD}Global Stats:{Colors.ENDC}")
    print(f"  • URLs tested: {len(test_urls)}")
    print(f"  • Vulnerabilities found: {Colors.GREEN}{total_vulns}{Colors.ENDC}")
    print(f"  • Total tests run: {total_tests}")
    print(f"  • Total time: {total_time:.2f}s")
    print(f"  • Avg per URL: {total_time/len(test_urls):.2f}s")
    
    print(f"\n{Colors.BOLD}Detailed Results:{Colors.ENDC}")
    for url, result in results.items():
        if 'error' in result:
            print(f"  {Colors.RED}✗{Colors.ENDC} {url}")
            print(f"    Error: {result['error']}")
        else:
            vulns = result.get('vulns_found', 0)
            if vulns > 0:
                print(f"  {Colors.GREEN}✓{Colors.ENDC} {url}")
                print(f"    Vulns: {vulns} | Tests: {result['total_tests']} | Time: {result['elapsed']:.2f}s")
            else:
                print(f"  {Colors.YELLOW}○{Colors.ENDC} {url}")
                print(f"    No vulns | Tests: {result['total_tests']} | Time: {result['elapsed']:.2f}s")
    
    print()

def main():
    """
    Main function
    """
    print_header("🔥 SHIELDAI V2 - VULN SERVER TEST")
    
    print_warning("Ce test nécessite que le serveur vulnérable soit lancé sur le port 5000")
    print_info("Lance vuln_server.py dans un autre terminal avant de continuer\n")
    
    input(f"{Colors.BOLD}Appuie sur ENTER quand le serveur est prêt...{Colors.ENDC}")
    
    # Vérifier que le serveur est accessible
    import urllib.request
    try:
        urllib.request.urlopen(VULN_SERVER_URL, timeout=2)
        print_success(f"Serveur accessible sur {VULN_SERVER_URL}\n")
    except Exception as e:
        print_error(f"Serveur non accessible: {e}")
        print_error("Lance 'python vuln_server.py' dans un autre terminal")
        return
    
    # Lancer les tests
    try:
        asyncio.run(test_fuzzer())
    except KeyboardInterrupt:
        print_warning("\nTest interrompu par l'utilisateur")
    except Exception as e:
        print_error(f"Erreur durant le test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
