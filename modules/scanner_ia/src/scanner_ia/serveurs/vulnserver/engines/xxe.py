"""XXE — XML External Entity, parseur XML sans résolution d'entités désactivée."""
from lxml import etree
from .base import Unit, UnitCtx


def _parse_unsafe(xml_text: str):
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    tree = etree.fromstring(xml_text.encode(), parser=parser)
    return tree


def make_units(resource):
    def import_xml_json(ctx: UnitCtx):
        xml_text = ctx.value(f"<{resource}><name>test</name></{resource}>")
        try:
            tree = _parse_unsafe(xml_text)
            root_text = "".join(tree.itertext())[:500]
            return {"parsed_root_text": root_text, "note": "resolve_entities=True : entités externes résolues"}
        except Exception as e:
            return {"error": str(e), "note": "resolve_entities=True : entités externes résolues"}

    def import_xml_form(ctx: UnitCtx):
        xml_text = ctx.value(f"<{resource}/>")
        try:
            tree = _parse_unsafe(xml_text)
            root_text = "".join(tree.itertext())[:500]
            return {"parsed_root_text": root_text, "note": "parseur XML sans désactivation des DTD externes"}
        except Exception as e:
            return {"error": str(e), "note": "parseur XML sans désactivation des DTD externes"}

    return [
        Unit("XXE", "resolve_entities_json_body", "json", "xml",
             f"import XML {resource} avec résolution d'entités externes activée", import_xml_json, "hard"),
        Unit("XXE", "resolve_entities_form_body", "form", "xml",
             f"upload XML {resource} sans désactivation des DTD externes", import_xml_form, "hard"),
    ]
