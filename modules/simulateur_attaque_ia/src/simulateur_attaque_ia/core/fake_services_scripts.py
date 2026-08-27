#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug  4 03:53:37 2026

@author: hounsousamuel
"""


import io
import random

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# =============================================================================
# FAKE_HTTP_SCRIPT — serveur générique multi-protocole (HTTP/FTP/SMTP/MySQL/...)
# =============================================================================

FAKE_HTTP_SCRIPT = r'''import socket
import sys
import threading

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", port))
except Exception as e:
    print(f"Erreur bind port {port}: {e}", flush=True)
    sys.exit(1)
s.listen(5)
print(f"Listening on port {port}", flush=True)

def handle_ssh(conn):
    conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")

def handle_http(conn):
    try:
        conn.recv(4096)
    except Exception:
        pass
    body = b"<html><body>Hello</body></html>\r\n"
    conn.send(
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n" + body
    )

def handle_ftp(conn):
    conn.send(b"220 FTP Server (vsftpd 3.0.5) ready.\r\n")
    try:
        data = conn.recv(1024)
        if b"USER" in data:
            conn.send(b"331 Password required.\r\n")
            data = conn.recv(1024)
            if b"PASS" in data:
                conn.send(b"530 Login incorrect.\r\n")
    except Exception:
        pass

def handle_smtp(conn):
    conn.send(b"220 mail.example.com ESMTP Postfix\r\n")

def handle_mysql(conn):
    conn.send(b"\x4a\x00\x00\x00\x0a8.0.20\x00")

def handle_redis(conn):
    conn.send(b"+REDIS_VERSION:6.0.9\r\n")

def handle_postgres(conn):
    conn.send(b"E\x00\x00\x00\x25SFATAL\x00C28000\x00Mpassword authentication failed\x00\x00")

def handle_custom(conn, p):
    conn.send(f"Custom Service v1.0 on port {p}\r\n".encode())

PORT_SERVICES = {
    80: handle_http, 443: handle_http, 8080: handle_http,
    8081: handle_http, 8443: handle_http, 9090: handle_http,
    21: handle_ftp, 2121: handle_ftp,
    25: handle_smtp, 587: handle_smtp,
    3306: handle_mysql, 6379: handle_redis, 5432: handle_postgres,
}

def serve():
    while True:
        try:
            conn, addr = s.accept()
            try:
                handler = PORT_SERVICES.get(port)
                if handler:
                    handler(conn)
                else:
                    handle_custom(conn, port)
            except Exception as e:
                print(f"Erreur handler: {e}", flush=True)
            finally:
                conn.close()
        except Exception as e:
            print(f"Erreur accept: {e}", flush=True)

serve()
'''


# =============================================================================
# FAKE_SSH_SCRIPT — serveur SSH factice basé sur paramiko
# =============================================================================

FAKE_SSH_SCRIPT = r'''
import socket
import sys
import io
import paramiko
import threading
import subprocess
import os
import time
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, credentials):
        self.credentials = credentials
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        if username in self.credentials and self.credentials[username] == password:
            print(f"OK Auth password OK: {username}", flush=True)
            return paramiko.AUTH_SUCCESSFUL
        print(f"FAIL Auth password FAIL: {username}", flush=True)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        try:
            auth_keys_path = "/root/.ssh/authorized_keys"
            if not os.path.exists(auth_keys_path):
                print("FAIL authorized_keys introuvable", flush=True)
                return paramiko.AUTH_FAILED
            with open(auth_keys_path, "r") as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                try:
                    key_data = base64.b64decode(parts[1])
                    # Essayer tous les types de clés — ordre important
                    for key_class in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                        try:
                            stored_key = key_class(data=key_data)
                            if stored_key == key:
                                print(f"OK Auth publickey OK: {username} ({key_class.__name__})", flush=True)
                                return paramiko.AUTH_SUCCESSFUL
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception as e:
            print(f"WARN Erreur check_auth_publickey: {e}", flush=True)
        print(f"FAIL Auth publickey FAIL: {username}", flush=True)
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        def run():
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True, timeout=600, cwd="/"
                )
                if result.stdout:
                    channel.send(result.stdout.encode("utf-8", errors="ignore"))
                if result.stderr:
                    channel.send_stderr(result.stderr.encode("utf-8", errors="ignore"))
                channel.send_exit_status(result.returncode)
            except subprocess.TimeoutExpired:
                channel.send(b"Command timed out\n")
                channel.send_exit_status(124)
            except Exception as e:
                channel.send(f"Error: {str(e)}\n".encode())
                channel.send_exit_status(1)
            finally:
                self.event.set()
                try:
                    channel.close()
                except Exception:
                    pass
        threading.Thread(target=run, daemon=True).start()
        return True

    def get_allowed_auths(self, username):
        return "password,publickey"

def handle_client(client_sock, addr, host_key, credentials):
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        server = FakeSSHServer(credentials)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            print(f"FAIL SSHException: {e}", flush=True)
        channel = transport.accept(30)
        if channel is None:
            return
        server.event.wait(600)
    except Exception as e:
        print(f"FAIL Erreur client {addr}: {e}", flush=True)
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass

def start_ssh_server(port=22):
    credentials = {
        "root": "toor",
        "testuser": "password",
        "admin": "admin123",
        "user": "user123"
    }

    # Bind + listen AVANT la génération de clé : le port répond dès ici,
    # même si la génération qui suit prend du temps. Le backlog du socket
    # met en attente les connexions entrantes jusqu'au premier accept().
    # (Avant : la clé RSA 2048 était générée en premier, ce qui pouvait
    # prendre de quelques ms à plusieurs secondes selon l'entropie
    # disponible dans le container -> fenêtre où un scan tombait sur un
    # port encore fermé -> détection intermittente.)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except Exception as e:
        print(f"FAIL Erreur bind port {port}: {e}", flush=True)
        return
    sock.listen(500)
    print(f"OK FakeSSH listening on port {port}", flush=True)

    # Ed25519 : bannière SSH crédible. La clé hôte est injectée ci-dessous
    # via un token, remplacé une fois pour toutes au chargement du module
    # (cf. plus bas dans ce fichier) — aucune génération de clé n'a lieu
    # ici au runtime, dans le container.
    _pem = """__SSH_HOST_KEY_PEM__"""
    host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(_pem))

    while True:
        try:
            client, addr = sock.accept()
            threading.Thread(
                target=handle_client,
                args=(client, addr, host_key, credentials),
                daemon=True
            ).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"FAIL Erreur accept: {e}", flush=True)

if __name__ == "__main__":
    _port = int(sys.argv[1]) if len(sys.argv) > 1 else 22
    start_ssh_server(_port)
'''

_SSH_HOST_KEY_POOL_SIZE = 5

_ssh_host_key_pool = [
    Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    for _ in range(_SSH_HOST_KEY_POOL_SIZE)
]

_ssh_host_key_pem = random.choice(_ssh_host_key_pool)

FAKE_SSH_SCRIPT = FAKE_SSH_SCRIPT.replace(
   "__SSH_HOST_KEY_PEM__",
   _ssh_host_key_pem
)


# =============================================================================
# FAKE_FTP_SCRIPT — serveur FTP factice
# =============================================================================

FAKE_FTP_SCRIPT = r'''
import socket
import sys
import threading
import subprocess
import os

USERS = {"testuser": "password", "root": "toor", "admin": "admin123"}
current_user = {}

def execute_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        return output if output else "Command executed successfully.\n"
    except Exception:
        return "Error.\n"

def handle_ftp_client(conn, addr):
    try:
        conn.send(b"220 FTP Server ready.\r\n")
        username = None
        authenticated = False
        while True:
            try:
                data = conn.recv(4096).decode("utf-8", errors="ignore").strip()
                if not data:
                    break
                cmd_parts = data.split()
                if not cmd_parts:
                    continue
                cmd = cmd_parts[0].upper()
                arg = " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
                if cmd == "USER":
                    username = arg
                    conn.send(b"331 Password required.\r\n")
                elif cmd == "PASS":
                    if username and USERS.get(username) == arg:
                        authenticated = True
                        conn.send(b"230 User logged in.\r\n")
                    else:
                        conn.send(b"530 Login incorrect.\r\n")
                elif cmd == "QUIT":
                    conn.send(b"221 Goodbye.\r\n")
                    break
                elif cmd == "SYST":
                    conn.send(b"215 UNIX Type: L8\r\n")
                elif cmd == "PWD":
                    conn.send(b'257 "/" is current directory.\r\n')
                elif cmd == "NOOP":
                    conn.send(b"200 OK.\r\n")
                else:
                    conn.send(b"502 Command not implemented.\r\n")
            except Exception:
                break
    except Exception as e:
        print(f"Erreur client FTP: {e}")
    finally:
        conn.close()

def start_ftp_server(port=21):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except Exception as e:
        print(f"FAIL Erreur bind FTP port {port}: {e}")
        return
    sock.listen(50)
    print(f"OK Fake FTP listening on port {port}")
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_ftp_client, args=(conn, addr), daemon=True).start()
        except Exception:
            break

if __name__ == "__main__":
    _port = int(sys.argv[1]) if len(sys.argv) > 1 else 21
    start_ftp_server(_port)
'''


# =============================================================================
# SSH_SETUP_SCRIPT — configuration OpenSSH réel (mode réseau multi-nodes)
# =============================================================================

SSH_SETUP_SCRIPT = r"""#!/bin/bash
command -v sshd &>/dev/null || {
    apt-get update -qq && apt-get install -y -qq openssh-server 2>/dev/null || \
    yum install -y openssh-server 2>/dev/null || true
}
mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh

[ -f /etc/ssh/ssh_host_rsa_key ]     || ssh-keygen -t rsa     -f /etc/ssh/ssh_host_rsa_key     -N "" -q
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
[ -f /etc/ssh/ssh_host_ecdsa_key ]   || ssh-keygen -t ecdsa   -f /etc/ssh/ssh_host_ecdsa_key   -N "" -q

cat > /etc/ssh/sshd_config << 'SSHD_EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
UsePAM no
X11Forwarding no
PrintMotd no
StrictModes no
SSHD_EOF

echo "root:toor" | chpasswd 2>/dev/null || true
echo "testuser:password" | chpasswd 2>/dev/null || useradd -m testuser && echo "testuser:password" | chpasswd 2>/dev/null || true

pkill sshd 2>/dev/null || true
sleep 0.3
nohup /usr/sbin/sshd -D > /var/log/sshd.log 2>&1 &
echo "OK OpenSSH démarré"
"""


# =============================================================================
# KEYGEN_SCRIPT — génération de clé RSA propre (mode réseau)
# =============================================================================

KEYGEN_SCRIPT = r"""#!/bin/bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Supprimer les clés canary/malformées existantes
rm -f /root/.ssh/id_rsa /root/.ssh/id_rsa.pub
rm -f /root/.ssh/id_ed25519 /root/.ssh/id_ed25519.pub
rm -f /root/.ssh/id_ecdsa /root/.ssh/id_ecdsa.pub
rm -f /root/.ssh/authorized_keys

# Générer une vraie clé RSA 2048 propre
ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" -q 2>/dev/null

# Retourner la clé publique
cat /root/.ssh/id_rsa.pub
"""


# =============================================================================
# Registre des services par défaut disponibles pour deploy_default_services
# =============================================================================
# Chaque entrée : script à déployer + ports par défaut si l'appelant n'en
# précise pas explicitement. Le script doit accepter le port en argv[1].

# "script" : déjà rendu et prêt à l'emploi pour les 3 types — pour "ssh",
# la clé hôte est déjà injectée dans FAKE_SSH_SCRIPT (cf. section dédiée
# plus haut), aucun traitement supplémentaire requis à l'appel.
DEFAULT_SERVICE_REGISTRY: dict[str, dict] = {
    "http": {"script": FAKE_HTTP_SCRIPT, "ports": [80, 8080]},
    "ssh":  {"script": FAKE_SSH_SCRIPT,  "ports": [22]},
    "ftp":  {"script": FAKE_FTP_SCRIPT,  "ports": [21]},
}