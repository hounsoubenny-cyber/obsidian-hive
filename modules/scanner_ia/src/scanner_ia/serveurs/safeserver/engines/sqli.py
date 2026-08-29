"""SQLi (safe) — requêtes paramétrées, aucune concaténation d'input dans le SQL."""
import sqlite3
from .base import Unit, UnitCtx, fake_records


def _db(resource):
    con = sqlite3.connect(":memory:")
    con.execute(f"CREATE TABLE {resource} (id INTEGER, name TEXT, owner_id INTEGER, secret TEXT, email TEXT)")
    for r in fake_records(resource):
        con.execute(f"INSERT INTO {resource} VALUES (?,?,?,?,?)",
                    (r["id"], r["name"], r["owner_id"], r["secret"], r["email"]))
    con.commit()
    return con


_SORT_WHITELIST = {"id", "name", "email"}


def make_units(resource):
    def select_where(ctx: UnitCtx):
        val = ctx.value("1")
        con = _db(resource)
        try:
            rid = int(val)
        except ValueError:
            return {"error": "id invalide", "query_executed": "SELECT ... WHERE id = ? (paramétré)"}
        rows = con.execute(f"SELECT id,name,email FROM {resource} WHERE id = ?", (rid,)).fetchall()
        return {"query_executed": f"SELECT id,name,email FROM {resource} WHERE id = ?", "rows": rows}

    def order_by(ctx: UnitCtx):
        val = ctx.value("id")
        col = val if val in _SORT_WHITELIST else "id"  # whitelist stricte, pas de concat
        con = _db(resource)
        rows = con.execute(f"SELECT id,name FROM {resource} ORDER BY {col}").fetchall()
        return {"sort_column_used": col, "rows": rows,
                "note": "colonne de tri validée contre une liste blanche"}

    def like_search(ctx: UnitCtx):
        val = ctx.value("")
        con = _db(resource)
        rows = con.execute(f"SELECT id,name FROM {resource} WHERE name LIKE ?", (f"%{val}%",)).fetchall()
        return {"rows": rows, "note": "requête LIKE paramétrée (placeholder ?)"}

    def login_bypass(ctx: UnitCtx):
        from flask import request as freq
        user = ctx.value("")
        pwd = freq.form.get("password", "")
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
        con.execute("INSERT INTO users VALUES ('admin','S3cr3tAdmin!','admin')")
        rows = con.execute("SELECT * FROM users WHERE username = ? AND password = ?", (user, pwd)).fetchall()
        return {"authenticated": len(rows) > 0, "note": "requête paramétrée, aucun bypass possible"}

    def union_select(ctx: UnitCtx):
        val = ctx.value("1")
        con = _db(resource)
        try:
            rid = int(val)
        except ValueError:
            return {"error": "id invalide"}
        rows = con.execute(f"SELECT id,name FROM {resource} WHERE id = ?", (rid,)).fetchall()
        return {"rows": rows, "note": "requête paramétrée, UNION SELECT inopérant"}

    return [
        Unit("SQLi", "where_id_concat", "query", "id", "requête paramétrée (placeholder ?)", select_where),
        Unit("SQLi", "order_by_concat", "query", "sort", "colonne ORDER BY validée par whitelist", order_by),
        Unit("SQLi", "like_search_concat", "form", "q", "LIKE paramétré", like_search, "medium"),
        Unit("SQLi", "login_bypass", "form", "username", "login paramétré, pas de bypass possible", login_bypass, "medium"),
        Unit("SQLi", "union_select_id", "json", "id", "requête paramétrée, UNION inopérant", union_select, "hard"),
    ]
