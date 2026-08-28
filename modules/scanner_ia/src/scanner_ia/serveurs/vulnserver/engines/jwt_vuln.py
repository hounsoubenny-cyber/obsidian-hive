"""JWT — mauvaise validation de JSON Web Tokens."""
import jwt as pyjwt
from .base import Unit, UnitCtx, JWT_SECRET


def make_units(resource):
    def alg_none_accepted(ctx: UnitCtx):
        token = ctx.value("")
        try:
            # DANGER volontaire : algorithmes autorisés incluent 'none'
            decoded = pyjwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "none"])
            return {"decoded_payload": decoded, "note": f"token accepté sans vérifier la signature (alg=none possible) pour {resource}"}
        except Exception as e:
            return {"error": str(e)}

    def weak_secret_bruteforce(ctx: UnitCtx):
        token = ctx.value("")
        try:
            decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return {"decoded_payload": decoded, "note": "secret HS256 faible et devinable côté serveur"}
        except Exception as e:
            return {"error": str(e), "hint_secret_is_weak": True}

    def no_expiry_check(ctx: UnitCtx):
        token = ctx.value("")
        try:
            decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
            return {"decoded_payload": decoded, "note": f"expiration du token {resource} jamais vérifiée"}
        except Exception as e:
            return {"error": str(e)}

    return [
        Unit("JWT", "alg_none_accepted", "header", "Authorization",
             "algorithme 'none' accepté, signature jamais vérifiée", alg_none_accepted, "hard"),
        Unit("JWT", "weak_hardcoded_secret", "header", "Authorization",
             "secret HS256 faible/hardcodé, brute-forçable", weak_secret_bruteforce, "hard"),
        Unit("JWT", "expiry_never_checked", "cookie", "auth_token",
             f"token {resource} accepté même expiré", no_expiry_check, "medium"),
    ]
