"""RateLimit — absence de limitation de débit sur des actions sensibles."""
import time
from .base import Unit, UnitCtx

CALL_LOG = {}


def make_units(resource):
    def login_no_throttle(ctx: UnitCtx):
        user = ctx.value("admin")
        CALL_LOG.setdefault(user, []).append(time.time())
        recent = [t for t in CALL_LOG[user] if time.time() - t < 60]
        return {"attempts_last_60s": len(recent), "throttled": False,
                "note": f"login {resource} : aucun blocage même après de nombreuses tentatives"}

    def password_reset_no_throttle(ctx: UnitCtx):
        email = ctx.value("user@example.test")
        key = f"reset:{email}"
        CALL_LOG.setdefault(key, []).append(time.time())
        recent = [t for t in CALL_LOG[key] if time.time() - t < 60]
        return {"reset_requests_last_60s": len(recent), "throttled": False,
                "note": "endpoint de reset password sans limite de débit, spam/énumération possible"}

    return [
        Unit("RateLimit", "login_endpoint_no_throttle", "form", "username",
             f"endpoint login {resource} sans rate limiting", login_no_throttle),
        Unit("RateLimit", "password_reset_no_throttle", "query", "email",
             "endpoint reset password sans rate limiting", password_reset_no_throttle),
    ]
