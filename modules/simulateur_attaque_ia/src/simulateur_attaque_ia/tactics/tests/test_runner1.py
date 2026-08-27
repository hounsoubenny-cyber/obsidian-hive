#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 22 08:29:54 2026

@author: hounsousamuel

Test runner ShieldAI V2.

NETWORK_MODE = False → un seul container, tous les tests classiques
NETWORK_MODE = True  → réseau multi-containers, test lateral movement inclus
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from simulateur_utils.logger import get_logger
logger = get_logger()

from tactics.tests.environment import TestEnvironment

# ── Imports tactics ──
from tactics.reconnaissance.port_scan_and_banner_grab  import test_network_service_discover
from tactics.initial_access.ssh_brute_force            import test_ssh
from tactics.initial_access.http_brute_force           import test_http_brute_force
from tactics.initial_access.ftp_brute_force            import test_ftp
from tactics.execution.command_execution               import test_command_exec
from tactics.execution.python_execution                import test_python_exec
from tactics.execution.reverse_shell                   import test_reverse_shell
from tactics.persistence.ssh_key_backdoor              import test_ssh_key_backdoor
from tactics.persistence.cron_backdoor                 import test_cron_backdoor
from tactics.persistence.startup_script                import test_startup_script
from tactics.privilege_escalation.sudo_exploit         import test_sudo_exploit
from tactics.privilege_escalation.suid_binary          import test_suid_exploit
from tactics.defense_evasion.log_cleaner               import test_log_cleaner
from tactics.defense_evasion.timestomp                 import full_test_timestomp
from tactics.credential_access.password_file_dump      import test_password_file_dump
from tactics.credential_access.bash_history_read       import test_bash_history_read
from tactics.credential_access.ssh_key_theft           import test_ssh_key_theft
from tactics.lateral_movement.ssh_lateral_movement     import test_ssh_lateral_movement
from tactics.exfiltration.exfiltration_http            import test_exfiltration_http


# =============================================================================
# CONFIG — change ici
# =============================================================================

IMAGE_NAME = "shieldai_sim_atk:v2" 
CONTAINER_NAME = "shieldai_test"
NETWORK_MODE   = True   # True → réseau multi-containers
N_NODES        = 3       # Nombre de containers en mode réseau
C2_URL         = "http://127.0.0.1:8888/exfil"


# =============================================================================
# Helpers
# =============================================================================

def cat(path, dock, flush=False):
    output, result = dock.exec_command(f"cat {path}")
    logger.print("OUTPUT : \n", output)
    logger.print("EXIT CODE : \n", result.exit_code)
    if flush:
        dock.exec_command(f'bash -c "echo \' \' > {path}"')


def run_all_tests_simple(ip: str, dock):
    """Lance tous les tests sur un seul container."""
    logger.print("\n" + "=" * 60)
    logger.print("🧪 LANCEMENT DE TOUS LES TESTS")
    logger.print("=" * 60)

    # Reconnaissance
    logger.print("\n── Reconnaissance ──")
    test_network_service_discover(ip=ip, port_range=range(8080, 8100))

    # Initial Access
    logger.print("\n── Initial Access ──")
    test_http_brute_force(ip)
    test_ftp(ip)
    test_ssh(ip)

    # Execution
    logger.print("\n── Execution ──")
    test_command_exec(ip)
    test_python_exec(ip)
    test_reverse_shell(ip)

    # Privilege Escalation
    logger.print("\n── Privilege Escalation ──")
    test_sudo_exploit(ip=ip)
    test_suid_exploit(ip=ip)

    # Credential Access
    logger.print("\n── Credential Access ──")
    test_password_file_dump(ip=ip)
    test_bash_history_read(ip=ip)
    steal_result = test_ssh_key_theft(ip=ip)

    # Lateral Movement — avec les clés volées
    logger.print("\n── Lateral Movement ──")
    usable_keys = steal_result.get("results", {}).get("usable_keys", [])
    known_hosts  = steal_result.get("results", {}).get("known_hosts", [])
    if usable_keys and known_hosts:
        test_ssh_lateral_movement(usable_keys=usable_keys, known_hosts=known_hosts)
    else:
        logger.print("  ⚠️ Pas de clés/hosts pour lateral movement")

    # Exfiltration
    logger.print("\n── Exfiltration ──")
    test_exfiltration_http(target_ip=ip, c2_url=C2_URL)

    # Defense Evasion
    logger.print("\n── Defense Evasion ──")
    full_test_timestomp(ip=ip)
    test_log_cleaner(ip=ip)

    # Persistence
    logger.print("\n── Persistence ──")
    test_cron_backdoor(dock)
    test_ssh_key_backdoor(ip=ip)
    result, startup = test_startup_script(ip=ip)

    logger.print("\n" + "=" * 60)
    logger.print("✅ TOUS LES TESTS TERMINÉS")
    logger.print("=" * 60)


def run_network_tests(nodes):
    """Lance les tests en mode réseau — focus lateral movement."""
    entry = nodes[0]
    ip    = entry["ip"]
    dock  = entry["dock"]

    logger.print("\n" + "=" * 60)
    logger.print(f"🌐 TESTS RÉSEAU — Point d'entrée : {ip}")
    logger.print("=" * 60)

    # Tests classiques sur le point d'entrée
    logger.print("\n── Reconnaissance ──")
    test_network_service_discover(ip=ip, port_range=range(1, 100))

    logger.print("\n── Initial Access ──")
    test_ssh(ip)

    logger.print("\n── Execution ──")
    test_command_exec(ip)

    logger.print("\n── Privilege Escalation ──")
    test_sudo_exploit(ip=ip)
    test_suid_exploit(ip=ip)

    logger.print("\n── Credential Access ──")
    test_password_file_dump(ip=ip)
    test_bash_history_read(ip=ip)
    steal_result = test_ssh_key_theft(ip=ip)

    # Lateral Movement — clés volées + known_hosts du réseau
    logger.print("\n── Lateral Movement ──")
    usable_keys = steal_result.get("results", {}).get("usable_keys", [])
    known_hosts  = steal_result.get("results", {}).get("known_hosts", [])

    # Fallback : utiliser les known_hosts injectés par l'environnement
    if not known_hosts:
        known_hosts = entry.get("known_hosts", [])
        logger.print(f"  ℹ️ Fallback known_hosts depuis l'environnement : {known_hosts}")

    # Fallback : utiliser la clé générée par l'environnement
    if not usable_keys and entry.get("public_key"):
        # logger.print("  ℹ️ Fallback : récupération clé privée depuis container...")
        # output, _ = dock.exec_command("bash -c 'cat /root/.ssh/id_rsa 2>/dev/null' ")
        # key_content = output.strip()
        # if key_content and "PRIVATE" in key_content:
        #     usable_keys = [{"content": key_content, "type": "RSA", "usable": True}]
        pass

    if usable_keys and known_hosts:
        test_ssh_lateral_movement(
            usable_keys=usable_keys,
            known_hosts=known_hosts,
        )
    else:
        logger.print("  ⚠️ Pas de clés/hosts disponibles pour lateral movement")

    # Exfiltration
    logger.print("\n── Exfiltration ──")
    test_exfiltration_http(target_ip=ip, c2_url=C2_URL)

    # Defense Evasion
    logger.print("\n── Defense Evasion ──")
    test_log_cleaner(ip=ip)
    full_test_timestomp(ip=ip)

    # Persistence
    logger.print("\n── Persistence ──")
    test_cron_backdoor(dock)
    test_ssh_key_backdoor(ip=ip)

    logger.print("\n" + "=" * 60)
    logger.print("✅ TESTS RÉSEAU TERMINÉS")
    logger.print("=" * 60)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":

    if NETWORK_MODE:
        # ── Mode réseau ──
        env = TestEnvironment(
            image_name=IMAGE_NAME,
            network=True,
            n_nodes=N_NODES,
        )
        try:
            nodes = env.setup()
            env.print_topology()
            logger.print(f"\n🎯 Point d'entrée : {nodes[0]['ip']} (root:toor)")
            run_network_tests(nodes)

        except KeyboardInterrupt:
            logger.print("\n⚠️ Interruption manuelle")

        except Exception as e:
            logger.print(f"❌ Erreur : {e}")
            import traceback
            traceback.print_exc()

        finally:
            env.teardown()

    else:
        # ── Mode simple ──
        env = TestEnvironment(
            image_name=IMAGE_NAME,
            container_name=CONTAINER_NAME,
        )
        try:
            ip = env.setup()
            logger.print(f"\n🎯 IP cible prête : {ip}")
            env.get_open_ports()
            run_all_tests_simple(ip=ip, dock=env.dock)

        except KeyboardInterrupt:
            logger.print("\n⚠️ Interruption manuelle")

        except Exception as e:
            logger.print(f"❌ Erreur : {e}")
            import traceback
            traceback.print_exc()

        finally:
            env.teardown()