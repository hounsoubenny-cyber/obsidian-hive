"""InsecUpload (safe) — whitelist d'extensions + vérification des magic bytes."""
import base64
import os
from .base import Unit, UnitCtx

UPLOAD_DIR = "/tmp/safeserver_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = (".png", ".jpg", ".jpeg", ".gif", ".txt", ".pdf")
MAGIC_BYTES = {
    ".png": b"\x89PNG",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8",
    ".pdf": b"%PDF",
}


def _safe_name(filename):
    base = os.path.basename(filename)
    return base.replace("..", "")


def make_units(resource):
    def no_ext_check(ctx: UnitCtx):
        body = ctx.raw_json()
        filename = _safe_name(body.get("filename", f"{resource}.txt"))
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXT:
            return {"accepted": False, "reason": "extension non autorisée", "extension_checked": True}
        content_b64 = body.get("content_b64", "")
        try:
            data = base64.b64decode(content_b64) if content_b64 else b""
        except Exception:
            return {"accepted": False, "reason": "contenu base64 invalide"}
        path = os.path.join(UPLOAD_DIR, filename)
        with open(path, "wb") as f:
            f.write(data[:2048])
        return {"accepted": True, "saved_path": path, "extension_checked": True}

    def no_content_check(ctx: UnitCtx):
        body = ctx.raw_json()
        filename = _safe_name(body.get("filename", f"{resource}.png"))
        ext = os.path.splitext(filename)[1].lower()
        content_b64 = body.get("content_b64", "")
        try:
            data = base64.b64decode(content_b64) if content_b64 else b""
        except Exception:
            return {"accepted": False, "reason": "contenu base64 invalide"}
        expected_magic = MAGIC_BYTES.get(ext)
        if expected_magic and not data.startswith(expected_magic):
            return {"accepted": False, "reason": "magic bytes ne correspondent pas à l'extension déclarée"}
        path = os.path.join(UPLOAD_DIR, filename)
        with open(path, "wb") as f:
            f.write(data[:2048])
        return {"accepted": True, "saved_path": path, "content_type_checked": True}

    return [
        Unit("InsecUpload", "no_extension_whitelist", "json", "filename", f"whitelist stricte d'extensions pour {resource}", no_ext_check, "hard"),
        Unit("InsecUpload", "no_content_type_check", "json", "content_b64", "vérification des magic bytes en plus de l'extension", no_content_check, "medium"),
    ]
