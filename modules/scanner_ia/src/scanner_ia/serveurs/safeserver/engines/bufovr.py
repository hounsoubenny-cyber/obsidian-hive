"""BufOvr (safe) — longueur d'entrée strictement bornée avant toute écriture mémoire."""
from .base import Unit, UnitCtx

MAX_LEN = 64


def make_units(resource):
    def fixed_buffer_query(ctx: UnitCtx):
        val = ctx.value("")
        if len(val) > MAX_LEN:
            return {"accepted": False, "reason": f"entrée > {MAX_LEN} octets rejetée avant traitement"}
        return {"accepted": True, "bytes_len": len(val), "note": f"buffer {resource} : longueur validée avant écriture"}

    def fixed_buffer_header(ctx: UnitCtx):
        val = ctx.value("")
        if len(val) > MAX_LEN:
            return {"accepted": False, "reason": f"header > {MAX_LEN} octets rejeté avant traitement"}
        return {"accepted": True, "bytes_len": len(val)}

    return [
        Unit("BufOvr", "fixed_buffer_ctypes_query", "query", "data", "longueur validée avant toute écriture buffer", fixed_buffer_query, "hard"),
        Unit("BufOvr", "fixed_buffer_ctypes_header", "header", "X-Payload", "longueur de header validée avant traitement", fixed_buffer_header, "hard"),
    ]
