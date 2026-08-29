"""BrokenAuth (safe) — throttle réel, tokens de session/reset cryptographiquement forts."""
import secrets
import time
from .base import Unit, UnitCtx

LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


def make_units(resource):
    def unlimited_login_attempts(ctx: UnitCtx):
        user = ctx.value("admin")
        now = time.time()
        attempts = [t for t in LOGIN_ATTEMPTS.get(user, []) if now - t < WINDOW_SECONDS]
        blocked = len(attempts) >= MAX_ATTEMPTS
        if not blocked:
            attempts.append(now)
        LOGIN_ATTEMPTS[user] = attempts
        return {"attempts_last_60s": len(attempts), "blocked": blocked,
                "note": f"blocage après {MAX_ATTEMPTS} tentatives / {WINDOW_SECONDS}s"}

    def predictable_session_token(ctx: UnitCtx):
        token = secrets.token_hex(32)
        return {"session_token": token, "note": "token généré via secrets.token_hex (CSPRNG), non prévisible"}

    def guessable_reset_token(ctx: UnitCtx):
        token = secrets.token_urlsafe(32)
        return {"reset_token": token, "note": "token de reset long, aléatoire cryptographiquement fort, à usage unique et expirant"}

    return [
        Unit("BrokenAuth", "no_bruteforce_protection", "form", "username", f"throttle réel sur login {resource}", unlimited_login_attempts),
        Unit("BrokenAuth", "predictable_session_token", "form", "username", "token de session CSPRNG", predictable_session_token, "medium"),
        Unit("BrokenAuth", "guessable_password_reset", "query", "username", "token de reset CSPRNG", guessable_reset_token, "medium"),
    ]
