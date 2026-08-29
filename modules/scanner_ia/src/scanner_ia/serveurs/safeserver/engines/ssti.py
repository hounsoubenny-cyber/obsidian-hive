"""SSTI (safe) — l'input utilisateur est toujours passé comme DONNÉE, jamais compilé comme template."""
from jinja2 import Environment
from .base import Unit, UnitCtx
from markupsafe import escape

_env = Environment(autoescape=True)
_GREETING_TPL = _env.from_string("Bonjour {{ name }} depuis {{ resource }} !")
_MESSAGE_TPL = _env.from_string("[{{ resource }}] message: {{ message }}")


def make_units(resource):
    def render_name_query(ctx: UnitCtx):
        name = ctx.value("world")
        rendered = _GREETING_TPL.render(name=name, resource=resource)
        return {"rendered": rendered, "note": "le nom est une VARIABLE de template, jamais compilé comme template"}

    def render_template_field_form(ctx: UnitCtx):
        tpl = ctx.value("Bienvenue")
        rendered = escape(tpl)
        return {"rendered": str(rendered), "note": "le contenu client n'est jamais compilé comme template Jinja2, juste échappé et affiché"}

    def render_field_json(ctx: UnitCtx):
        val = ctx.value("hello")
        rendered = _MESSAGE_TPL.render(resource=resource, message=val)
        return {"rendered": rendered, "note": "input inséré comme variable de template, autoescape actif"}

    return [
        Unit("SSTI", "greeting_name_query", "query", "name", "template précompilé, input passé en variable", render_name_query, "hard"),
        Unit("SSTI", "custom_template_field_form", "form", "template", "input jamais compilé comme template", render_template_field_form, "hard"),
        Unit("SSTI", "message_field_json", "json", "message", "template précompilé, autoescape actif", render_field_json, "hard"),
    ]
