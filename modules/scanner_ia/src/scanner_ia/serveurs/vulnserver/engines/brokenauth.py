"""BrokenAuth — authentification défaillante (pas de throttle, session prévisible)."""
import hashlib
import time
from .base import Unit, UnitCtx, USERS_TABLE

LOGIN_ATTEMPTS = {}  # jamais nettoyé/bloqué -> volontairement cassé


def make_units(resource):
    def unlimited_login_attempts(ctx: UnitCtx):
        user = ctx.value("admin")
        LOGIN_ATTEMPTS[user] = LOGIN_ATTEMPTS.get(user, 0) + 1
        return {"attempts_so_far": LOGIN_ATTEMPTS[user], "blocked": False,
                "note": "aucune limite de tentatives, brute-force possible à l'infini"}

    def predictable_session_token(ctx: UnitCtx):
        user = ctx.value("admin")
        token = hashlib.md5(f"{user}-{int(time.time()) // 3600}".encode()).hexdigest()
        return {"session_token": token, "note": "token dérivé de username+heure courante, prévisible/rejouable"}

    def guessable_reset_token(ctx: UnitCtx):
        user = ctx.value("admin")
        token = str(abs(hash(user)) % 1000000).zfill(6)
        return {"reset_token": token, "note": "token de reset password sur 6 chiffres prévisibles, sans expiration"}

    return [
        Unit("BrokenAuth", "no_bruteforce_protection", "form", "username",
             f"login {resource} sans limite de tentatives", unlimited_login_attempts),
        Unit("BrokenAuth", "predictable_session_token", "form", "username",
             "token de session dérivé de valeurs prévisibles", predictable_session_token, "medium"),
        Unit("BrokenAuth", "guessable_password_reset", "query", "username",
             "token de réinitialisation de mot de passe devinable", guessable_reset_token, "medium"),
    ]
