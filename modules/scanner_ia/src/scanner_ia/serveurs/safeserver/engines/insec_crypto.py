"""InsecCrypto (safe) — hachage salé PBKDF2-HMAC-SHA256, aucun chiffrement maison."""
import hashlib
import os
from .base import Unit, UnitCtx


def make_units(resource):
    def md5_password_storage(ctx: UnitCtx):
        pwd = ctx.value("password123")
        salt = os.urandom(16)
        derived = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 200_000)
        return {"algorithm": "PBKDF2-HMAC-SHA256", "salted": True, "iterations": 200_000,
                "note": f"mot de passe {resource} salé et haché avec un algorithme adapté aux mots de passe"}

    def weak_xor_encryption(ctx: UnitCtx):
        val = ctx.value("secret data")
        return {"algorithm": "not implemented here — use AES-GCM with a random nonce via a vetted library",
                "note": f"aucun chiffrement maison pour {resource} ; utiliser une bibliothèque cryptographique éprouvée"}

    return [
        Unit("InsecCrypto", "md5_unsalted_password", "form", "password", "PBKDF2-HMAC-SHA256 salé", md5_password_storage, "medium"),
        Unit("InsecCrypto", "xor_fixed_key_encryption", "query", "data", "pas de chiffrement maison, recommandation de lib éprouvée", weak_xor_encryption, "medium"),
    ]
