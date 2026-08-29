"""JWT (safe) — signature toujours vérifiée, alg figé côté serveur, expiration contrôlée."""
import jwt as pyjwt
from .base import Unit, UnitCtx, JWT_SECRET


def make_units(resource):
    def alg_none_accepted(ctx: UnitCtx):
        token = ctx.value("")
        try:
            decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # 'none' jamais autorisé
            return {"decoded_payload": decoded, "note": "seul HS256 est autorisé, signature toujours vérifiée"}
        except Exception as e:
            return {"error": str(e), "note": "token rejeté (signature invalide ou algorithme non autorisé)"}

    def weak_secret_bruteforce(ctx: UnitCtx):
        token = ctx.value("")
        try:
            decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return {"decoded_payload": decoded, "note": "secret fort généré aléatoirement, non devinable"}
        except Exception as e:
            return {"error": str(e)}

    def no_expiry_check(ctx: UnitCtx):
        token = ctx.value("")
        try:
            decoded = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # verify_exp actif par défaut
            return {"decoded_payload": decoded, "note": f"expiration du token {resource} vérifiée systématiquement"}
        except pyjwt.ExpiredSignatureError:
            return {"error": "token expiré", "rejected": True}
        except Exception as e:
            return {"error": str(e)}

    return [
        Unit("JWT", "alg_none_accepted", "header", "Authorization", "alg=none jamais autorisé", alg_none_accepted, "hard"),
        Unit("JWT", "weak_hardcoded_secret", "header", "Authorization", "secret fort et aléatoire", weak_secret_bruteforce, "hard"),
        Unit("JWT", "expiry_never_checked", "cookie", "auth_token", "expiration vérifiée systématiquement", no_expiry_check, "medium"),
    ]
