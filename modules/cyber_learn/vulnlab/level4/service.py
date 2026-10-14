"""
VulnLab - Niveau 4 (Difficile) - Service réseau
Lance avec : python3 service.py
Port TCP : 4444
Essaie : nc 127.0.0.1 4444
"""
import socket
import threading

FLAG = "FLAG{level4_pr0t0c0l_bru7ef0rce_0r_l34k}"

# Comptes "système" du faux service - un est volontairement faible
ACCOUNTS = {
    "guest": "guest",
    "operator": "hunter2",
    "svc_backup": "B@ckup2024!",   # compte de service oublié, souvent utilisé en vrai
}

BANNER = (
    b"=== MiniVaultD v0.9 (experimental) ===\r\n"
    b"Commandes: HELLO | LOGIN <user> <pass> | HELP | QUIT\r\n"
)


def handle_client(conn: socket.socket, addr):
    conn.sendall(BANNER)
    authed_as = None
    try:
        while True:
            conn.sendall(b"> ")
            data = conn.recv(1024)
            if not data:
                break
            line = data.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split(" ")
            cmd = parts[0].upper()

            if cmd == "HELLO":
                conn.sendall(b"Salut. Ce service protege des donnees de sauvegarde.\r\n")
            elif cmd == "HELP":
                conn.sendall(b"LOGIN <user> <pass>\r\n")
            elif cmd == "LOGIN" and len(parts) == 3:
                user, pw = parts[1], parts[2]
                if ACCOUNTS.get(user) == pw:
                    authed_as = user
                    conn.sendall(f"OK, connecte en tant que {user}\r\n".encode())
                    if user == "svc_backup":
                        conn.sendall(f"Acces sauvegarde accorde. {FLAG}\r\n".encode())
                else:
                    conn.sendall(b"ERR identifiants invalides\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"Bye.\r\n")
                break
            else:
                conn.sendall(b"ERR commande inconnue\r\n")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 4444))
    srv.listen(5)
    print("[Level 4] TCP service sur le port 4444")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
