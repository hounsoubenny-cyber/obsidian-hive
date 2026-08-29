"""RateLimit (safe) — limite de débit réellement appliquée sur les actions sensibles."""
import time
from .base import Unit, UnitCtx

CALL_LOG = {}
MAX_CALLS = 5
WINDOW = 60


def make_units(resource):
    def login_no_throttle(ctx: UnitCtx):
        user = ctx.value("admin")
        now = time.time()
        recent = [t for t in CALL_LOG.get(user, []) if now - t < WINDOW]
        throttled = len(recent) >= MAX_CALLS
        if not throttled:
            recent.append(now)
        CALL_LOG[user] = recent
        return {"attempts_last_60s": len(recent), "throttled": throttled, "note": f"blocage après {MAX_CALLS} tentatives/{WINDOW}s"}

    def password_reset_no_throttle(ctx: UnitCtx):
        email = ctx.value("user@example.test")
        key = f"reset:{email}"
        now = time.time()
        recent = [t for t in CALL_LOG.get(key, []) if now - t < WINDOW]
        throttled = len(recent) >= MAX_CALLS
        if not throttled:
            recent.append(now)
        CALL_LOG[key] = recent
        return {"reset_requests_last_60s": len(recent), "throttled": throttled}

    return [
        Unit("RateLimit", "login_endpoint_no_throttle", "form", "username", f"throttle réel sur {resource}", login_no_throttle),
        Unit("RateLimit", "password_reset_no_throttle", "query", "email", "throttle réel appliqué", password_reset_no_throttle),
    ]
