"""InsecCrypto — algorithmes cryptographiques faibles (MD5 sans sel, XOR 'chiffrement')."""
import hashlib
from .base import Unit, UnitCtx


def make_units(resource):
    def md5_password_storage(ctx: UnitCtx):
        pwd = ctx.value("password123")
        hashed = hashlib.md5(pwd.encode()).hexdigest()
        return {"algorithm": "MD5", "salted": False, "stored_hash": hashed,
                "note": f"mot de passe {resource} stocké en MD5 sans sel, cassable via rainbow table"}

    def weak_xor_encryption(ctx: UnitCtx):
        val = ctx.value("secret data")
        key = 0x2A  # clé fixe, triviale
        cipher = bytes([b ^ key for b in val.encode()]).hex()
        return {"algorithm": "XOR single-byte", "fixed_key": True, "ciphertext_hex": cipher,
                "note": f"données {resource} 'chiffrées' avec un XOR à clé fixe unique, cassable instantanément"}

    return [
        Unit("InsecCrypto", "md5_unsalted_password", "form", "password",
             "hash MD5 sans sel pour stocker un mot de passe", md5_password_storage, "medium"),
        Unit("InsecCrypto", "xor_fixed_key_encryption", "query", "data",
             f"chiffrement XOR à clé fixe pour protéger des données {resource}", weak_xor_encryption, "medium"),
    ]
