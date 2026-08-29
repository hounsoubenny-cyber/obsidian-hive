"""DirTrav (safe) — chemin normalisé et vérifié contre le dossier de base autorisé."""
import os
from .base import Unit, UnitCtx

BASE_DIR = os.path.realpath("/tmp/safeserver_files")
os.makedirs(BASE_DIR, exist_ok=True)
with open(os.path.join(BASE_DIR, "readme.txt"), "w") as f:
    f.write("fichier public de test")


def _safe_read(name: str):
    candidate = os.path.realpath(os.path.join(BASE_DIR, name))
    if not candidate.startswith(BASE_DIR + os.sep) and candidate != BASE_DIR:
        return None, "chemin en dehors du dossier autorisé, rejeté"
    if not os.path.isfile(candidate):
        return None, "fichier introuvable"
    with open(candidate, "r", errors="ignore") as f:
        return f.read(500), None


def make_units(resource):
    def read_file_query(ctx: UnitCtx):
        name = ctx.value("readme.txt")
        content, err = _safe_read(name)
        return {"content_preview": content, "error": err, "note": "chemin normalisé et validé contre BASE_DIR"}

    def read_file_form(ctx: UnitCtx):
        name = ctx.value(f"{resource}.log")
        content, err = _safe_read(name)
        return {"content_preview": content, "error": err}

    def read_file_path_segment(ctx: UnitCtx):
        name = ctx.value("readme.txt")
        content, err = _safe_read(name)
        return {"content_preview": content, "error": err}

    return [
        Unit("DirTrav", "read_file_query_param", "query", "file", f"chemin validé pour {resource}", read_file_query),
        Unit("DirTrav", "read_file_form_param", "form", "filename", "chemin validé", read_file_form),
        Unit("DirTrav", "read_file_path_segment", "path", "filename", "chemin validé", read_file_path_segment, "medium"),
    ]
