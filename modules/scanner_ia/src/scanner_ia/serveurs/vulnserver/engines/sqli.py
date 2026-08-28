"""SQLi — injection SQL classique via concaténation de chaînes."""
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


def make_units(resource):
    def select_where(ctx: UnitCtx):
        val = ctx.value("1")
        con = _db(resource)
        query = f"SELECT id,name,email FROM {resource} WHERE id = {val}"
        try:
            rows = con.execute(query).fetchall()
            return {"query_executed": query, "rows": rows}
        except sqlite3.Error as e:
            return {"query_executed": query, "sql_error": str(e)}

    def order_by(ctx: UnitCtx):
        val = ctx.value("id")
        con = _db(resource)
        query = f"SELECT id,name FROM {resource} ORDER BY {val}"
        try:
            rows = con.execute(query).fetchall()
            return {"query_executed": query, "rows": rows}
        except sqlite3.Error as e:
            return {"query_executed": query, "sql_error": str(e)}

    def like_search(ctx: UnitCtx):
        val = ctx.value("")
        con = _db(resource)
        query = f"SELECT id,name FROM {resource} WHERE name LIKE '%{val}%'"
        try:
            rows = con.execute(query).fetchall()
            return {"query_executed": query, "rows": rows}
        except sqlite3.Error as e:
            return {"query_executed": query, "sql_error": str(e)}

    def login_bypass(ctx: UnitCtx):
        user = ctx.value("")
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
        con.execute("INSERT INTO users VALUES ('admin','S3cr3tAdmin!','admin')")
        query = f"SELECT * FROM users WHERE username = '{user}' AND password = 'wrong'"
        try:
            rows = con.execute(query).fetchall()
            return {"query_executed": query, "authenticated": len(rows) > 0, "rows": rows}
        except sqlite3.Error as e:
            return {"query_executed": query, "sql_error": str(e)}

    def union_select(ctx: UnitCtx):
        val = ctx.value("1")
        con = _db(resource)
        query = f"SELECT id,name FROM {resource} WHERE id = {val}"
        try:
            rows = con.execute(query).fetchall()
            return {"query_executed": query, "rows": rows}
        except sqlite3.Error as e:
            return {"query_executed": query, "sql_error": str(e)}

    return [
        Unit("SQLi", "where_id_concat", "query", "id",
             "id concaténé directement dans une clause WHERE numérique", select_where),
        Unit("SQLi", "order_by_concat", "query", "sort",
             "valeur ORDER BY non paramétrable, injectable", order_by),
        Unit("SQLi", "like_search_concat", "form", "q",
             "recherche LIKE avec concaténation directe", like_search, "medium"),
        Unit("SQLi", "login_bypass", "form", "username",
             "contournement d'authentification via injection dans WHERE", login_bypass, "medium"),
        Unit("SQLi", "union_select_id", "json", "id",
             "id JSON injecté, exploitable en UNION SELECT", union_select, "hard"),
    ]
