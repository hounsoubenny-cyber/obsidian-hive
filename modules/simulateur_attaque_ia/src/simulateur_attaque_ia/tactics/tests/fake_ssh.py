#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 22 08:27:41 2026

@author: hounsousamuel
"""

# fake_ssh_server.py
import socket
import paramiko
import threading

class FakeSSHServer(paramiko.ServerInterface):
    """Serveur SSH minimal pour tests"""

    def __init__(self, valid_credentials):
        self.valid_credentials = valid_credentials  # Dict: {'user': 'pass'}

    def check_auth_password(self, username, password):
        """Vérifie credentials"""
        if username in self.valid_credentials:
            if self.valid_credentials[username] == password:
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'


def start_fake_ssh_server(host='0.0.0.0', port=2222, credentials=None):
    """Lance serveur SSH fake"""

    if credentials is None:
        credentials = {'testuser': 'password', 'root': 'toor'}

    # Générer clé RSA
    host_key = paramiko.RSAKey.generate(2048)

    # Socket serveur
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    print(f"🚀 Serveur SSH fake démarré sur {host}:{port}")
    print(f"📝 Credentials valides: {credentials}")

    def handle_client(client_sock):
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(host_key)

            server = FakeSSHServer(credentials)
            transport.start_server(server=server)

            channel = transport.accept(20)
            if channel:
                channel.close()

        except Exception as e:
            print(f"Erreur client: {e}")
        finally:
            try:
                transport.close()
            except Exception:
                pass

    # Accepter connexions
    while True:
        try:
            client, addr = sock.accept()
            print(f"📞 Connexion depuis {addr}")
            thread = threading.Thread(target=handle_client, args=(client,))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            break

    sock.close()


if __name__ == '__main__':
    # Lancer serveur
    start_fake_ssh_server(
        host='0.0.0.0',
        port=2222,
        credentials={
            'testuser': 'password',
            'root': 'toor',
            'admin': 'admin123'
        }
    )
