#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 16 17:55:57 2026

@author: hounsousamuel
"""

"""
ShieldAI - Refactoring payloads_v3.json → v3.1.0
================================================
Usage:
    python3 refactor_payloads_v3.py payloads_v3.json payloads_v3.1.json

Transformation:
    {"payload": "X", "encoding": "none", "type": "t"} x3
    → {"payload": "X", "encodings": ["none", "url", "base64"], "type": "t"}
"""

import json
import sys
from collections import defaultdict


# ─────────────────────────────────────────────
# ÉTAPE 1 — REFACTORISATION DU JSON
# ─────────────────────────────────────────────

def refactor(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    total_original = 0
    total_refactored = 0

    for cat_key, category in data["payloads"].items():
        original_payloads = category["payloads"]
        total_original += len(original_payloads)

        # Group entries by exact payload string (preserve insertion order)
        groups: dict[str, list[dict]] = defaultdict(list)
        order: list[str] = []

        for entry in original_payloads:
            key = entry["payload"]
            if key not in groups:
                order.append(key)
            groups[key].append(entry)

        new_payloads = []
        for key in order:
            entries = groups[key]

            # Take first entry as base (keeps "type", "repeat", etc.)
            base = dict(entries[0])

            # Collect all encodings, deduplicated
            encodings: list[str] = []
            for e in entries:
                enc = e.get("encoding", "none")
                if enc not in encodings:
                    encodings.append(enc)

            # "none" always first
            if "none" in encodings:
                encodings.remove("none")
                encodings = ["none"] + encodings

            base.pop("encoding", None)   # remove old field
            base["encodings"] = encodings

            new_payloads.append(base)

        total_refactored += len(new_payloads)
        category["payloads"] = new_payloads

    # Mise à jour metadata
    data["metadata"]["version"] = "3.1.0"
    data["metadata"]["total_base_payloads"] = total_refactored
    data["metadata"]["total_expanded_payloads"] = total_original

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"✓ Version:            3.0.0 → 3.1.0")
    print(f"✓ Expanded payloads:  {total_original}")
    print(f"✓ Base payloads:      {total_refactored}")
    print(f"✓ Réduction:          -{total_original - total_refactored} entrées supprimées")
    print(f"✓ Fichier écrit:      {output_path}")


# ─────────────────────────────────────────────
# ÉTAPE 2 — _prepare_payloads() ADAPTÉ
# ─────────────────────────────────────────────

def _prepare_payloads(
    category_data: dict,
    marker: str,
) -> list[dict]:
    """
    Génère la liste complète des payloads prêts à l'envoi.

    Pour chaque entrée dans category_data["payloads"], génère une variante
    par encoding listé dans "encodings".

    Args:
        category_data: dict d'une catégorie (ex: data["payloads"]["SQLi"])
        marker:        identifiant unique pour cette session (ex: "A1B2")

    Returns:
        Liste de dicts {"payload": str, "encoding": str, "type": str, ...}
    """
    import base64
    import urllib.parse

    expanded: list[dict] = []

    for entry in category_data.get("payloads", []):
        base_payload: str = entry["payload"].replace("{{MARKER}}", marker)
        encodings: list[str] = entry.get("encodings", ["none"])
        repeat: int = entry.get("repeat", 1)

        for encoding in encodings:
            encoded_payload = _apply_encoding(base_payload, encoding)

            # Répétition (ex: buffer overflow)
            if repeat > 1:
                encoded_payload = encoded_payload * repeat

            variant = {
                "payload":  encoded_payload,
                "encoding": encoding,
                "type":     entry.get("type", "unknown"),
            }
            # Propager les champs additionnels (repeat, note, etc.)
            for k, v in entry.items():
                if k not in ("payload", "encodings", "encoding", "type", "repeat"):
                    variant[k] = v

            expanded.append(variant)

    return expanded


def _apply_encoding(payload: str, encoding: str) -> str:
    """Applique l'encodage demandé au payload."""
    import base64
    import urllib.parse

    match encoding:
        case "none":
            return payload
        case "url":
            return urllib.parse.quote(payload, safe="")
        case "base64":
            return base64.b64encode(payload.encode()).decode()
        case "html":
            import html
            return html.escape(payload)
        case "null_byte":
            return payload + "\x00"
        case _:
            # Encoding inconnu → on laisse tel quel + warning
            print(f"[WARN] Encoding inconnu: {encoding!r} → payload non transformé")
            return payload


# ─────────────────────────────────────────────
# EXEMPLE D'UTILISATION
# ─────────────────────────────────────────────

USAGE_EXAMPLE = '''
# Charger le JSON refactorisé
with open("payloads_v3.1.json") as f:
    payload_db = json.load(f)

# Générer les variantes pour SQLi avec marker "X9K2"
sqli_payloads = _prepare_payloads(
    category_data=payload_db["payloads"]["SQLi"],
    marker="X9K2",
)

for p in sqli_payloads:
    send_request(p["payload"], encoding=p["encoding"], type=p["type"])
'''

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 refactor_payloads_v3.py <input.json> <output.json>")
        sys.exit(1)

    refactor(sys.argv[1], sys.argv[2])