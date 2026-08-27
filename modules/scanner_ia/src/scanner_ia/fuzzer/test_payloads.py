#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 16 18:08:19 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test rapide de _prepare_payloads — à lancer directement :
    python3 test_prepare_payloads.py
"""

import copy, html, base64, random, string
from urllib.parse import quote

# ── Stub minimal du PayloadGenerator ─────────────────────────────────────────

class PayloadGenerator:
    def __init__(self):
        self.debug = True
        self.encoding_mapping = {
            "url":       lambda x: quote(x),
            "html":      lambda x: html.escape(x, quote=True),
            "base64":    lambda x: base64.b64encode(str(x).encode()).decode(),
            "null_byte": lambda x: "%00.".join(str(x).rsplit(".", 1)),
            "default":   lambda x: x,
        }

    def encode(self, text: str, enc_type: str | None = None) -> str:
        if enc_type is None:
            return text
        return self.encoding_mapping.get(enc_type, self.encoding_mapping["default"])(text)

    def _resolve_marker(self, payload_str: str) -> tuple[str, str]:
        marker_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return payload_str.replace("{{MARKER}}", marker_id), marker_id

    def _prepare_payloads(self, raw_payloads: list[dict]) -> list[dict]:
        prepared = []
        for entry in raw_payloads:
            encodings = entry.get("encodings", [entry.get("encoding", "none")])
            for enc in encodings:
                variant = copy.deepcopy(entry)
                resolved, marker_id = self._resolve_marker(variant["payload"])
                variant["_marker_id"] = marker_id
                enc_type = None if enc == "none" else enc
                encoded  = self.encode(resolved, enc_type)
                variant["payload"]  = encoded
                variant["encoding"] = enc
                if "repeat" in variant:
                    try:
                        variant["payload"] = encoded * (variant["repeat"] // 4)
                    except MemoryError:
                        print(f"[MemoryError] repeat={variant['repeat']}")
                variant.pop("encodings", None)
                prepared.append(variant)
        if self.debug:
            print(f"[DEBUG] _prepare_payloads : {len(prepared)} variantes depuis {len(raw_payloads)} entrées")
        return prepared


# ── Helpers d'affichage ───────────────────────────────────────────────────────

SEP  = "─" * 70
SEP2 = "═" * 70

def section(title: str):
    print(f"\n{SEP2}\n  {title}\n{SEP2}")

def show(variants: list[dict], max_payload_len: int = 80):
    for i, v in enumerate(variants):
        p = v["payload"]
        display = p[:max_payload_len] + ("…" if len(p) > max_payload_len else "")
        print(f"  [{i}] enc={v['encoding']:<10} type={v.get('type','?'):<25} marker={v['_marker_id']}")
        print(f"       payload: {display}")


# ── Données de test ───────────────────────────────────────────────────────────

RAW_PAYLOADS = [
    # 1. Cas nominal : 3 encodings
    {
        "payload":   "; echo SHLD{{MARKER}}-$(id)-$(hostname)",
        "encodings": ["none", "url", "base64"],
        "type":      "unix_echo_marker",
    },
    # 2. Repeat (buffer overflow) sur 3 encodings
    {
        "payload":   "SHLD{{MARKER}}",
        "encodings": ["none", "url", "base64"],
        "type":      "overflow_large",
        "repeat":    100,       # → payload × 25
    },
    # 3. 4 encodings (NoSQLi)
    {
        "payload":   '{"$ne": "SHLD{{MARKER}}"}',
        "encodings": ["none", "url", "base64", "html"],
        "type":      "mongodb_ne",
    },
    # 4. null_byte
    {
        "payload":   "../../../../etc/passwd",
        "encodings": ["url", "null_byte"],
        "type":      "url_encoded",
    },
    # 5. Rétro-compat : ancien format string (v3.0)
    {
        "payload":  "' UNION SELECT NULL,version()-- -",
        "encoding": "none",
        "type":     "union_based_old_format",
    },
    # 6. Champs additionnels (note, etc.)
    {
        "payload":   "SHLD{{MARKER}}",
        "encodings": ["none"],
        "type":      "php_hex",
        "note":      "hex encoded sans doubles accolades",
    },
]


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pg = PayloadGenerator()

    # ── Test global ───────────────────────────────────────────────────────────
    section("TEST GLOBAL — toutes les entrées")
    all_variants = pg._prepare_payloads(RAW_PAYLOADS)
    print(f"\n  Total entrées brutes   : {len(RAW_PAYLOADS)}")
    print(f"  Total variantes expand : {len(all_variants)}")
    #  attendu : 3 + 3 + 4 + 2 + 1 + 1 = 14
    expected_total = 14
    status = "✓ OK" if len(all_variants) == expected_total else f"✗ FAIL (attendu {expected_total})"
    print(f"  {status}")

    # ── Détail par cas ────────────────────────────────────────────────────────
    section("CAS 1 — CMDi : 3 encodings")
    r1 = pg._prepare_payloads([RAW_PAYLOADS[0]])
    show(r1)
    assert len(r1) == 3, f"attendu 3, obtenu {len(r1)}"
    assert "{{MARKER}}" not in r1[0]["payload"]
    assert "encodings" not in r1[0]
    print(f"\n  ✓ 3 variantes, marker résolu, champ 'encodings' supprimé")

    section("CAS 2 — BufOvr : repeat=100 sur 3 encodings")
    r2 = pg._prepare_payloads([RAW_PAYLOADS[1]])
    show(r2, max_payload_len=40)
    single_none = f"SHLD{r2[0]['_marker_id']}"
    assert len(r2[0]["payload"]) == len(single_none) * 25, \
        f"longueur attendue {len(single_none)*25}, obtenue {len(r2[0]['payload'])}"
    print(f"\n  ✓ repeat=100 → payload×25 (longueur none: {len(r2[0]['payload'])})")
    print(f"  ✓ variante base64 : {r2[2]['payload'][:40]}…")

    section("CAS 3 — NoSQLi : 4 encodings")
    r3 = pg._prepare_payloads([RAW_PAYLOADS[2]])
    show(r3)
    assert len(r3) == 4
    print(f"\n  ✓ 4 variantes générées")

    section("CAS 4 — DirTrav : url + null_byte")
    r4 = pg._prepare_payloads([RAW_PAYLOADS[3]])
    show(r4)
    assert len(r4) == 2
    assert r4[0]["encoding"] == "url"
    assert r4[1]["encoding"] == "null_byte" and "%00" in r4[1]["payload"]
    print(f"\n  ✓ null_byte inséré : {r4[1]['payload']!r}")

    section("CAS 5 — Rétro-compat ancien format 'encoding' string")
    r5 = pg._prepare_payloads([RAW_PAYLOADS[4]])
    show(r5)
    assert len(r5) == 1 and r5[0]["encoding"] == "none"
    print(f"\n  ✓ 1 variante, encoding='none'")

    section("CAS 6 — Champs additionnels préservés (note)")
    r6 = pg._prepare_payloads([RAW_PAYLOADS[5]])
    show(r6)
    assert r6[0].get("note") == "hex encoded sans doubles accolades"
    print(f"\n  ✓ note = {r6[0]['note']!r}")

    # ── Résumé final ──────────────────────────────────────────────────────────
    print(f"\n{SEP2}")
    print(f"  RÉSULTAT FINAL : TOUS LES CAS PASSÉS ✓")
    print(f"{SEP2}\n")