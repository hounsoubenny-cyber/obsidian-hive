"""SSTI — Server-Side Template Injection via rendu Jinja2 d'input utilisateur."""
from jinja2 import Environment
from .base import Unit, UnitCtx

_env = Environment()


def make_units(resource):
    def render_name_query(ctx: UnitCtx):
        name = ctx.value("world")
        template = f"Bonjour {name} depuis {resource} !"
        try:
            rendered = _env.from_string(template).render()
            return {"template_used": template, "rendered": rendered}
        except Exception as e:
            return {"template_used": template, "error": str(e)}

    def render_template_field_form(ctx: UnitCtx):
        tpl = ctx.value("Bienvenue {{ 1+1 }}")
        try:
            rendered = _env.from_string(tpl).render(resource=resource)
            return {"template_used": tpl, "rendered": rendered}
        except Exception as e:
            return {"template_used": tpl, "error": str(e)}

    def render_field_json(ctx: UnitCtx):
        val = ctx.value("hello")
        template = f"[{resource}] message: {val}"
        try:
            rendered = _env.from_string(template).render()
            return {"template_used": template, "rendered": rendered}
        except Exception as e:
            return {"template_used": template, "error": str(e)}

    return [
        Unit("SSTI", "greeting_name_query", "query", "name", "nom utilisateur injecté directement dans un template Jinja2", render_name_query, "hard"),
        Unit("SSTI", "custom_template_field_form", "form", "template", f"template {resource} entièrement fourni par le client puis rendu", render_template_field_form, "hard"),
        Unit("SSTI", "message_field_json", "json", "message", f"message {resource} injecté dans un template avant rendu", render_field_json, "hard"),
    ]
