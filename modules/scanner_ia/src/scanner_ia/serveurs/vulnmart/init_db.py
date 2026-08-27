"""
init_db.py — Initialise la base SQLite de VulnMart avec des données de démo.
Contient volontairement des mots de passe faibles / hashés en MD5 pour certains
comptes "legacy" (voir README.md, section Auth).
"""
import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnmart.db")

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    hash_algo TEXT NOT NULL DEFAULT 'md5',
    role TEXT NOT NULL DEFAULT 'user',
    is_admin INTEGER NOT NULL DEFAULT 0,
    ssn TEXT,
    credit_card TEXT,
    avatar TEXT DEFAULT '/static/uploads/default.png',
    reset_token TEXT
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL,
    image_url TEXT,
    stock INTEGER DEFAULT 10
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    shipping_address TEXT,
    card_last4 TEXT,
    status TEXT DEFAULT 'processing'
);

CREATE TABLE reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    username TEXT,
    body TEXT
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT,
    body TEXT
);
"""

def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    users = [
        # username, email, password (plain, will be hashed), algo, role, is_admin, ssn, cc
        ("admin", "admin@vulnmart.test", "admin123", "md5", "admin", 1, "078-05-1120", "4111111111111111"),
        ("alice", "alice@vulnmart.test", "alice2020", "md5", "user", 0, "512-33-8842", "4222222222222"),
        ("bob", "bob@vulnmart.test", "letmein", "md5", "user", 0, "223-44-9981", "4333333333333"),
        ("sam", "sam@vulnmart.test", "P@ssw0rd!", "sha256", "user", 0, "301-22-7765", "4555555555555"),
    ]
    for u in users:
        username, email, pw, algo, role, is_admin, ssn, cc = u
        h = md5(pw) if algo == "md5" else hashlib.sha256(pw.encode()).hexdigest()
        conn.execute(
            "INSERT INTO users (username,email,password_hash,hash_algo,role,is_admin,ssn,credit_card) VALUES (?,?,?,?,?,?,?,?)",
            (username, email, h, algo, role, is_admin, ssn, cc)
        )

    products = [
        ("Casque Audio Pro X1", "Casque sans fil, réduction de bruit active.", 89.99, "https://picsum.photos/seed/headphones/400/300", 25),
        ("Montre Connectée Orbit", "Suivi fitness, GPS, autonomie 7 jours.", 129.50, "https://picsum.photos/seed/watch/400/300", 14),
        ("Sac à dos Urban 24L", "Compartiment laptop 15\", résistant à l'eau.", 45.00, "https://picsum.photos/seed/backpack/400/300", 40),
        ("Clavier Mécanique Nova", "Switches rouges, rétroéclairage RGB.", 74.90, "https://picsum.photos/seed/keyboard/400/300", 18),
        ("Lampe de bureau Halo", "LED variable, port USB-C intégré.", 32.00, "https://picsum.photos/seed/lamp/400/300", 33),
        ("Enceinte Bluetooth Wave", "Étanche IPX7, 12h d'autonomie.", 59.99, "https://picsum.photos/seed/speaker/400/300", 22),
    ]
    for p in products:
        conn.execute("INSERT INTO products (name,description,price,image_url,stock) VALUES (?,?,?,?,?)", p)

    reviews = [
        (1, "alice", "Super qualité sonore, je recommande !"),
        (1, "bob", "Un peu cher mais ça vaut le coup."),
        (2, "sam", "Le GPS met du temps à accrocher au début."),
    ]
    for r in reviews:
        conn.execute("INSERT INTO reviews (product_id,username,body) VALUES (?,?,?)", r)

    orders = [
        (2, 1, 1, "12 rue des Lilas, Cotonou", "1111", "shipped"),
        (2, 3, 2, "12 rue des Lilas, Cotonou", "1111", "processing"),
        (3, 2, 1, "5 avenue du Port, Cotonou", "3333", "delivered"),
    ]
    for o in orders:
        conn.execute("INSERT INTO orders (user_id,product_id,quantity,shipping_address,card_last4,status) VALUES (?,?,?,?,?,?)", o)

    conn.commit()
    conn.close()
    print(f"DB créée : {DB_PATH}")

if __name__ == "__main__":
    main()
