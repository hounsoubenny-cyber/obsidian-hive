"""XSS — Cross-Site Scripting réfléchi, input renvoyé sans échappement HTML."""
from markupsafe import Markup
from .base import Unit, UnitCtx


def make_units(resource):
    def reflected_query(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<div class='result'>Recherche pour {resource}: {val}</div>"
        return {"html_fragment": Markup(html).unescape() if False else html, "note": "input renvoyé sans échappement (Markup non appliqué)"}

    def reflected_form(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<p>Commentaire sur {resource}: {val}</p>"
        return {"html_fragment": html, "note": "champ de commentaire renvoyé tel quel dans le HTML"}

    def reflected_json_render(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<span data-{resource}>{val}</span>"
        return {"html_fragment": html, "note": "valeur JSON injectée directement dans un attribut/texte HTML"}

    def reflected_header_useragent(ctx: UnitCtx):
        val = ctx.value("")
        html = f"<!-- last client for {resource}: {val} -->"
        return {"html_fragment": html, "note": "header réfléchi tel quel dans un commentaire HTML visible côté client"}

    def reflected_attribute_break_out(ctx: UnitCtx):
        val = ctx.value("")
        html = f'<input type="text" value="{val}" name="{resource}_field">'
        return {"html_fragment": html, "note": "valeur insérée dans un attribut HTML sans échappement des guillemets"}

    return [
        Unit("XSS", "reflected_query_div", "query", "q", "recherche réfléchie sans échappement", reflected_query),
        Unit("XSS", "reflected_form_comment", "form", "comment", "commentaire réfléchi sans échappement", reflected_form),
        Unit("XSS", "reflected_json_span", "json", "value", "valeur JSON réfléchie dans le HTML", reflected_json_render, "medium"),
        Unit("XSS", "reflected_header_comment", "header", "X-Client-Note", "header réfléchi dans un commentaire HTML", reflected_header_useragent, "medium"),
        Unit("XSS", "reflected_attribute_breakout", "query", "val", "échappement d'attribut HTML non géré", reflected_attribute_break_out, "medium"),
    ]
