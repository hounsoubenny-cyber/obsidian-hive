"""CMDi (safe) — pas de shell, aucune commande système construite depuis l'input."""
from .base import Unit, UnitCtx
import ipaddress


def make_units(resource):
    def ping_host(ctx: UnitCtx):
        host = ctx.value("127.0.0.1")
        try:
            ipaddress.ip_address(host)
            valid = True
        except ValueError:
            valid = False
        return {"host_received": host, "valid_ip_format": valid, "shell_used": False,
                "note": "aucune commande shell exécutée ; l'input est seulement validé comme IP"}

    def file_process(ctx: UnitCtx):
        filename = ctx.value(f"{resource}.txt")
        safe = filename.replace("..", "").replace("/", "").replace(";", "").replace("|", "")
        return {"filename_received": filename, "filename_sanitized": safe, "shell_used": False}

    def archive_name(ctx: UnitCtx):
        name = ctx.value(f"{resource}_export")
        safe = "".join(c for c in name if c.isalnum() or c in "_-")
        return {"archive_name_used": safe, "shell_used": False,
                "note": "nom filtré (alphanumérique + _ -), jamais passé à un shell"}

    return [
        Unit("CMDi", "ping_host_shell_true", "query", "host", "aucun shell, validation stricte", ping_host),
        Unit("CMDi", "filename_echo_shell", "form", "filename", "aucun shell, sanitization", file_process, "medium"),
        Unit("CMDi", "archive_name_shell", "json", "name", "aucun shell, whitelist de caractères", archive_name, "medium"),
    ]
