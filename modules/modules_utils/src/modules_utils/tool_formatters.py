"""
Formatters pour sérialiser des résultats de tool calls (dict/list/str/...)
en texte lisible par un LLM, SANS échapper les strings (pas de \\ -> \\\\,
pas de " -> \\").

Principe commun aux 3 versions : au lieu d'échapper les caractères spéciaux
à l'intérieur du texte, on isole chaque bloc de texte brut entre deux
marqueurs UNIQUES générés aléatoirement (comme les boundaries MIME en email,
ou les heredocs bash avec suffixe random). On vérifie que ce marqueur
n'apparaît pas déjà dans le texte ; si collision (proba quasi nulle), on en
régénère un autre. Le texte à l'intérieur n'est JAMAIS modifié.

Aucune des 3 sorties n'est faite pour être re-parsée par une machine
(json.loads, xml.etree, ...) : c'est du texte pour un LLM.
"""

import secrets


def _gen_id(nbytes: int = 4) -> str:
    """Id court aléatoire (hex) pour désambiguïser un marqueur."""
    return secrets.token_hex(nbytes)


def _safe_tag(key) -> str:
    return str(key).strip().replace(" ", "_") or "item"


def _unique_wrapper_tag(base_tag: str, text: str) -> str:
    """
    Génère un nom de balise base_tag-<id> tel que la balise fermante
    </base_tag-<id>> n'apparaisse PAS dans text. Boucle jusqu'à garantie.
    """
    while True:
        candidate = f"{base_tag}-{_gen_id()}"
        if f"</{candidate}>" not in text:
            return candidate


def _unique_delimiter(text: str, prefix: str) -> str:
    """
    Génère un délimiteur de bloc prefix_<id> tel qu'il n'apparaisse pas
    dans text. Boucle jusqu'à garantie.
    """
    while True:
        candidate = f"{prefix}_{_gen_id()}"
        if candidate not in text:
            return candidate


# ---------------------------------------------------------------------------
# VERSION 1 : XML-like
# - Les clés deviennent des balises.
# - Balises "structurelles" (dict/list imbriqués) : nom propre, sans id.
# - Balises "feuilles" (texte brut) : nom + id unique anti-collision.
# ---------------------------------------------------------------------------

def to_xml_like(data, root: str = "tool_result") -> str:
    return "\n".join(_render_xml(root, data, 0))


def _render_xml(tag: str, value, depth: int) -> list[str]:
    indent = "  " * depth
    tag = _safe_tag(tag)

    if isinstance(value, dict):
        lines = [f"{indent}<{tag}>"]
        for k, v in value.items():
            lines.extend(_render_xml(k, v, depth + 1))
        lines.append(f"{indent}</{tag}>")
        return lines

    if isinstance(value, list):
        lines = [f"{indent}<{tag}>"]
        for item in value:
            lines.extend(_render_xml("item", item, depth + 1))
        lines.append(f"{indent}</{tag}>")
        return lines

    if isinstance(value, str):
        open_tag = _unique_wrapper_tag(tag, value)
        if "\n" in value:
            return [f"{indent}<{open_tag}>"] + value.split("\n") + [f"{indent}</{open_tag}>"]
        return [f"{indent}<{open_tag}>{value}</{open_tag}>"]

    # int / float / bool / None -> pas de risque de collision, pas d'id
    return [f"{indent}<{tag}>{value}</{tag}>"]


# ---------------------------------------------------------------------------
# VERSION 2 : JSON-like visuel
# - Garde {, }, [, ] pour la structure (reconnaissable visuellement).
# - AUCUNE quote autour des strings : chaque string est mise dans un bloc
#   délimité par un marqueur unique <<<RAW_xxxx ... RAW_xxxx>>>.
# - Ce n'est PAS du JSON valide (volontairement) : jamais reparsé.
# ---------------------------------------------------------------------------

def to_json_like(data) -> str:
    return "\n".join(_render_json_like(data, 0))


def _render_raw_block(text: str, depth: int, prefix: str = "RAW") -> list[str]:
    indent = "  " * depth
    delim = _unique_delimiter(text, prefix)
    return [f"{indent}<<<{delim}"] + text.split("\n") + [f"{indent}{delim}>>>"]


def _render_json_like(value, depth: int) -> list[str]:
    indent = "  " * depth

    if isinstance(value, dict):
        lines = [f"{indent}{{"]
        for k, v in value.items():
            lines.extend(_render_json_kv(k, v, depth + 1))
        lines.append(f"{indent}}}")
        return lines

    if isinstance(value, list):
        lines = [f"{indent}["]
        for item in value:
            lines.extend(_render_json_like(item, depth + 1))
        lines.append(f"{indent}]")
        return lines

    if isinstance(value, str):
        return _render_raw_block(value, depth)

    return [f"{indent}{value}"]


def _render_json_kv(key, value, depth: int) -> list[str]:
    indent = "  " * depth
    key = _safe_tag(key)

    if isinstance(value, (dict, list)):
        return [f"{indent}{key}:"] + _render_json_like(value, depth + 1)

    if isinstance(value, str):
        return [f"{indent}{key}:"] + _render_raw_block(value, depth + 1)

    return [f"{indent}{key}: {value}"]


# ---------------------------------------------------------------------------
# VERSION 3 : Clé/valeur simple (façon heredoc)
# - Pas de {}/[] : indentation + "- " pour les listes.
# - Blocs de texte brut délimités par un marqueur unique <<<END_xxxx.
# - Plus légère, adaptée aux résultats plutôt plats.
# ---------------------------------------------------------------------------

def to_kv(data) -> str:
    return "\n".join(_render_kv(data, 0))


def _render_kv(data, depth: int) -> list[str]:
    indent = "  " * depth
    lines: list[str] = []

    if isinstance(data, dict):
        for k, v in data.items():
            k = _safe_tag(k)
            if isinstance(v, dict):
                lines.append(f"{indent}{k}:")
                lines.extend(_render_kv(v, depth + 1))
            elif isinstance(v, list):
                lines.append(f"{indent}{k}:")
                lines.extend(_render_kv(v, depth + 1))
            elif isinstance(v, str):
                lines.append(f"{indent}{k}:")
                lines.extend(_render_raw_block(v, depth + 1, prefix="END"))
            else:
                lines.append(f"{indent}{k}: {v}")
        return lines

    if isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{indent}-")
                lines.extend(_render_kv(item, depth + 1))
            elif isinstance(item, str):
                lines.append(f"{indent}-")
                lines.extend(_render_raw_block(item, depth + 1, prefix="END"))
            else:
                lines.append(f"{indent}- {item}")
        return lines

    return [f"{indent}{data}"]
