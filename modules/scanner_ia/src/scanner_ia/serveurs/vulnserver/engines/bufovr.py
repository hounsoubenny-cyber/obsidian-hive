"""BufOvr — dépassement de buffer mémoire (démonstration isolée en sous-process).

Un vrai buffer overflow nécessite du code natif. On simule un buffer fixe en
mémoire via ctypes dans un SOUS-PROCESS isolé (multiprocessing) pour que le
crash mémoire ne puisse jamais faire tomber le serveur Flask principal.
"""
import ctypes
import multiprocessing
from .base import Unit, UnitCtx

FIXED_BUFFER_SIZE = 64


def _overflow_worker(data: bytes, q):
    try:
        buf = ctypes.create_string_buffer(FIXED_BUFFER_SIZE)
        # écriture sans vérification de longueur : dépassement si data > buffer
        ctypes.memmove(buf, data, len(data))
        q.put({"crashed": False, "bytes_written": len(data), "buffer_size": FIXED_BUFFER_SIZE})
    except Exception as e:
        q.put({"crashed": False, "error": str(e)})


def _run_isolated(data: bytes):
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_overflow_worker, args=(data, q))
    p.start()
    p.join(timeout=3)
    if p.exitcode is not None and p.exitcode < 0:
        return {"crashed": True, "signal": -p.exitcode, "bytes_written": len(data), "buffer_size": FIXED_BUFFER_SIZE}
    if not q.empty():
        return q.get()
    return {"crashed": True, "note": "process terminé sans résultat (probable corruption mémoire)"}


def make_units(resource):
    def fixed_buffer_query(ctx: UnitCtx):
        val = ctx.value("").encode(errors="ignore")
        result = _run_isolated(val)
        result["note"] = f"buffer fixe {FIXED_BUFFER_SIZE} octets pour {resource}, écriture non bornée (isolé en sous-process pour la démo)"
        return result

    def fixed_buffer_header(ctx: UnitCtx):
        val = ctx.value("").encode(errors="ignore")
        result = _run_isolated(val)
        result["note"] = "valeur de header copiée dans un buffer fixe sans contrôle de longueur"
        return result

    return [
        Unit("BufOvr", "fixed_buffer_ctypes_query", "query", "data",
             "buffer natif de taille fixe, écriture non bornée", fixed_buffer_query, "hard"),
        Unit("BufOvr", "fixed_buffer_ctypes_header", "header", "X-Payload",
             "buffer natif de taille fixe rempli depuis un header", fixed_buffer_header, "hard"),
    ]
