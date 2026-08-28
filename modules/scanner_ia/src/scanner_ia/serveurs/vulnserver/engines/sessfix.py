"""SessFix — Session Fixation : accepte un ID de session fourni par le client."""
from .base import Unit, UnitCtx

ACTIVE_SESSIONS = {}


def make_units(resource):
    def accept_client_sessionid_query(ctx: UnitCtx):
        sid = ctx.value("")
        if sid:
            ACTIVE_SESSIONS[sid] = {"authenticated": False}
            note = "session ID fourni par le client accepté tel quel, pas régénéré au login"
        else:
            sid = "srv-generated-001"
            note = "aucun sessionid fourni, un ID serveur a été généré"
        return {"session_id": sid, "note": note}

    def accept_client_sessionid_cookie(ctx: UnitCtx):
        sid = ctx.value("")
        if sid:
            ACTIVE_SESSIONS[sid] = ACTIVE_SESSIONS.get(sid, {"authenticated": False})
            ACTIVE_SESSIONS[sid]["authenticated"] = True
            note = f"cookie de session pré-existant réutilisé après login sur {resource}, jamais régénéré"
        else:
            sid = "none"
            note = "aucun cookie de session présent"
        return {"session_id": sid, "note": note}

    return [
        Unit("SessFix", "sessionid_accepted_from_query", "query", "sessionid",
             "ID de session fourni par le client accepté avant authentification", accept_client_sessionid_query, "medium"),
        Unit("SessFix", "sessionid_not_regenerated_on_login", "cookie", "sessionid",
             f"cookie de session sur {resource} non régénéré après authentification", accept_client_sessionid_cookie, "medium"),
    ]
