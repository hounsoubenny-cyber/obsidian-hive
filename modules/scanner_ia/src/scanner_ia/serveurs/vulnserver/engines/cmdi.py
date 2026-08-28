"""CMDi — Command Injection via shell=True / os.popen sur input utilisateur."""
import subprocess
from .base import Unit, UnitCtx


def make_units(resource):
    def ping_host(ctx: UnitCtx):
        host = ctx.value("127.0.0.1")
        cmd = f"ping -c 1 -W 1 {host}"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, timeout=3, text=True)
            return {"cmd_executed": cmd, "stdout": out.stdout[-500:], "stderr": out.stderr[-300:]}
        except Exception as e:
            return {"cmd_executed": cmd, "error": str(e)}

    def file_process(ctx: UnitCtx):
        filename = ctx.value(f"{resource}.txt")
        cmd = f"echo processing {filename}"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, timeout=3, text=True)
            return {"cmd_executed": cmd, "stdout": out.stdout[-500:]}
        except Exception as e:
            return {"cmd_executed": cmd, "error": str(e)}

    def archive_name(ctx: UnitCtx):
        name = ctx.value(f"{resource}_export")
        cmd = f"echo archive:{name}.tar.gz"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, timeout=3, text=True)
            return {"cmd_executed": cmd, "stdout": out.stdout[-500:]}
        except Exception as e:
            return {"cmd_executed": cmd, "error": str(e)}

    return [
        Unit("CMDi", "ping_host_shell_true", "query", "host",
             "hostname passé tel quel à un shell via subprocess(shell=True)", ping_host),
        Unit("CMDi", "filename_echo_shell", "form", "filename",
             "nom de fichier interpolé dans une commande shell", file_process, "medium"),
        Unit("CMDi", "archive_name_shell", "json", "name",
             "nom d'archive interpolé dans une commande shell", archive_name, "medium"),
    ]
