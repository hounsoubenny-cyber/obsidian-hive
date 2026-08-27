#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul  9 00:00:46 2026

@author: hounsousamuel
"""

"""
Fausse route de login — VOLONTAIREMENT VULNÉRABLE (SQLi classique).
Sert uniquement à tester si Alex sait : trouver ce fichier, comprendre
la faille, et proposer un fix correct.
"""

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db():
    return sqlite3.connect("users.db")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # 🚨 VULNÉRABLE : concaténation directe dans la requête SQL
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "ok", "user_id": user[0]})
    return jsonify({"status": "error", "message": "Identifiants invalides"}), 401


if __name__ == "__main__":
    app.run(debug=True)