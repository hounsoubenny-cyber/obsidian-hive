"""DirTrav — Path/Directory Traversal via nom de fichier non validé."""
import os
from .base import Unit, UnitCtx

BASE_DIR = "/tmp/vulnserver_files"
os.makedirs(BASE_DIR, exist_ok=True)
with open(os.path.join(BASE_DIR, "readme.txt"), "w") as f:
    f.write("fichier public de test")


def make_units(resource):
    def read_file_query(ctx: UnitCtx):
        name = ctx.value("readme.txt")
        # PAS de normalisation/validation : concaténation directe -> traversal possible
        path = os.path.join(BASE_DIR, name)
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read(500)
            return {"resolved_path": path, "content_preview": content}
        except Exception as e:
            return {"resolved_path": path, "error": str(e)}

    def read_file_form(ctx: UnitCtx):
        name = ctx.value(f"{resource}.log")
        path = BASE_DIR + "/" + name
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read(500)
            return {"resolved_path": path, "content_preview": content}
        except Exception as e:
            return {"resolved_path": path, "error": str(e)}

    def read_file_path_segment(ctx: UnitCtx):
        name = ctx.value("readme.txt")
        path = BASE_DIR + "/" + name
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read(500)
            return {"resolved_path": path, "content_preview": content}
        except Exception as e:
            return {"resolved_path": path, "error": str(e)}

    return [
        Unit("DirTrav", "read_file_query_param", "query", "file", f"lecture fichier {resource} via param query non validé", read_file_query),
        Unit("DirTrav", "read_file_form_param", "form", "filename", f"lecture fichier {resource} via champ form non validé", read_file_form),
        Unit("DirTrav", "read_file_path_segment", "path", "filename", f"lecture fichier {resource} via segment d'URL non validé", read_file_path_segment, "medium"),
    ]
