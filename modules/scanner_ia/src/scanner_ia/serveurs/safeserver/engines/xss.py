"""XSS (safe) — tout output utilisateur est échappé avant insertion dans le HTML."""
from markupsafe import escape
from .base import Unit, UnitCtx


def make_units(resource):
    def reflected_query(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<div class='result'>Recherche pour {resource}: {escape(val)}</div>"
        return {"html_fragment": html, "note": "valeur échappée via markupsafe.escape()"}

    def reflected_form(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<p>Commentaire sur {resource}: {escape(val)}</p>"
        return {"html_fragment": html, "note": "échappement HTML appliqué"}

    def reflected_json_render(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<span data-{resource}>{escape(val)}</span>"
        return {"html_fragment": html, "note": "valeur JSON échappée avant insertion HTML"}

    def reflected_header_useragent(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<!-- last client for {resource}: {escape(val)} -->"
        return {"html_fragment": html, "note": "header échappé avant insertion dans le HTML"}

    def reflected_attribute_break_out(ctx: UnitCtx):
        val = ctx.value("")
        html = f'<input type="text" value="{escape(val)}" name="{resource}_field">'
        return {"html_fragment": html, "note": "guillemets d'attribut échappés correctement"}

    return [
        Unit("XSS", "reflected_query_div", "query", "q", "sortie échappée (markupsafe)", reflected_query),
        Unit("XSS", "reflected_form_comment", "form", "comment", "sortie échappée", reflected_form),
        Unit("XSS", "reflected_json_span", "json", "value", "sortie échappée", reflected_json_render, "medium"),
        Unit("XSS", "reflected_header_comment", "header", "X-Client-Note", "sortie échappée", reflected_header_useragent, "medium"),
        Unit("XSS", "reflected_attribute_breakout", "query", "val", "attribut HTML échappé correctement", reflected_attribute_break_out, "medium"),
    ]
