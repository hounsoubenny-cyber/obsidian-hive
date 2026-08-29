"""XXE (safe) — parseur XML avec résolution d'entités externes désactivée."""
from lxml import etree
from .base import Unit, UnitCtx


def _parse_safe(xml_text: str):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
    return etree.fromstring(xml_text.encode(), parser=parser)


def make_units(resource):
    def import_xml_json(ctx: UnitCtx):
        xml_text = ctx.value(f"<{resource}><name>test</name></{resource}>")
        try:
            tree = _parse_safe(xml_text)
            root_text = "".join(tree.itertext())[:500]
            return {"parsed_root_text": root_text, "note": "resolve_entities=False, no_network=True : entités externes bloquées"}
        except Exception as e:
            return {"error": str(e)}

    def import_xml_form(ctx: UnitCtx):
        xml_text = ctx.value(f"<{resource}/>")
        try:
            tree = _parse_safe(xml_text)
            root_text = "".join(tree.itertext())[:500]
            return {"parsed_root_text": root_text, "note": "DTD externe désactivée"}
        except Exception as e:
            return {"error": str(e)}

    return [
        Unit("XXE", "resolve_entities_json_body", "json", "xml", f"parseur XML sécurisé pour {resource}", import_xml_json, "hard"),
        Unit("XXE", "resolve_entities_form_body", "form", "xml", "parseur XML sécurisé", import_xml_form, "hard"),
    ]
