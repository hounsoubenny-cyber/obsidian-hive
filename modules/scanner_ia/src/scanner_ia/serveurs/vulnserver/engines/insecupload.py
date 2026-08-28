"""InsecUpload — upload de fichier sans contrôle d'extension/contenu."""
import base64
import os
from .base import Unit, UnitCtx

UPLOAD_DIR = "/tmp/vulnserver_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
DANGEROUS_EXT = (".php", ".py", ".jsp", ".asp", ".sh")


def make_units(resource):
    def no_ext_check(ctx: UnitCtx):
        body = ctx.raw_json()
        filename = body.get("filename", f"{resource}.txt")
        content_b64 = body.get("content_b64", "")
        path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
        try:
            data = base64.b64decode(content_b64) if content_b64 else b""
        except Exception:
            data = b""
        with open(path, "wb") as f:
            f.write(data[:2048])
        dangerous = filename.lower().endswith(DANGEROUS_EXT)
        return {"saved_path": path, "extension_checked": False, "dangerous_extension_accepted": dangerous}

    def no_content_check(ctx: UnitCtx):
        body = ctx.raw_json()
        filename = body.get("filename", f"{resource}.png")
        content_b64 = body.get("content_b64", "")
        path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
        try:
            data = base64.b64decode(content_b64) if content_b64 else b""
        except Exception:
            data = b""
        with open(path, "wb") as f:
            f.write(data[:2048])
        return {"saved_path": path, "content_type_checked": False,
                "note": "extension autorisée mais contenu jamais vérifié (magic bytes ignorés)"}

    return [
        Unit("InsecUpload", "no_extension_whitelist", "json", "filename",
             f"upload {resource} accepté quelle que soit l'extension (.php/.py inclus)", no_ext_check, "hard"),
        Unit("InsecUpload", "no_content_type_check", "json", "content_b64",
             f"upload {resource} : extension filtrée mais contenu réel jamais inspecté", no_content_check, "medium"),
    ]
