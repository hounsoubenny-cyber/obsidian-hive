#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flame_offline.py — folded.txt (généré par profile_run.py) -> flamegraph HTML autonome.
Aucune dépendance, aucun accès réseau : ouvre le .html dans ton navigateur.

Usage :
  python3 flame_offline.py profile_out_XXXX/folded.txt                    # -> flame.html à côté
  python3 flame_offline.py folded.txt --thread consumer                   # un seul thread
  python3 flame_offline.py folded.txt --min-pct 0.5 --width 1600          # plus léger / plus large

Lecture : la base = racine (le thread), chaque étage au-dessus = une fonction appelée par celle du
dessous. Plus un rectangle est LARGE, plus il consomme de temps (inclusif). Survole pour voir le
détail, tape un nom dans la barre de recherche (ex : predict_sequence) pour le surligner.
"""
import argparse
import colorsys
import hashlib
from html import escape
from pathlib import Path


def build_tree(path: Path, thread_filter: str):
    root = {"n": "all", "v": 0, "c": {}}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stack, _, cnt = line.rstrip().rpartition(" ")
        if not stack or not cnt.isdigit():
            continue
        frames = stack.split(";")
        if thread_filter and thread_filter.lower() not in frames[0].lower():
            continue
        n = int(cnt)
        root["v"] += n
        node = root
        for f in frames:
            nxt = node["c"].get(f)
            if nxt is None:
                nxt = node["c"][f] = {"n": f, "v": 0, "c": {}}
            nxt["v"] += n
            node = nxt
    return root


def depth(node) -> int:
    return 1 + max((depth(c) for c in node["c"].values()), default=0)


def color(name: str) -> str:
    h = int(hashlib.md5(name.encode()).hexdigest()[:6], 16)
    hue = 0.02 + (h % 1000) / 1000 * 0.11          # rouge -> jaune (palette "flame")
    r, g, b = colorsys.hsv_to_rgb(hue, 0.55 + (h >> 10) % 40 / 100, 0.95)
    return f"rgb({int(r * 255)},{int(g * 255)},{int(b * 255)})"


def render(root, width: int, min_pct: float, row_h: int = 18) -> str:
    total = root["v"]
    levels = depth(root)
    height = levels * row_h + 20
    out, count = [], 0

    def walk(node, x, level):
        nonlocal count
        w = node["v"] / total * width
        if node["v"] / total * 100 < min_pct:
            return
        y = height - (level + 1) * row_h - 4
        pct = 100 * node["v"] / total
        tip = f'{node["n"]} — {node["v"] / 1000:.2f} s ({pct:.1f} %)'
        out.append(
            f'<g class="f" data-n="{escape(node["n"].lower(), quote=True)}">'
            f'<title>{escape(tip)}</title>'
            f'<rect x="{x:.2f}" y="{y}" width="{max(w - 0.5, 0.5):.2f}" height="{row_h - 1}" '
            f'fill="{color(node["n"]) if level else "#cfd8dc"}" rx="2"/>'
        )
        chars = int(w / 6.6)
        if chars >= 4:
            label = node["n"] if len(node["n"]) <= chars else node["n"][:chars - 1] + "…"
            out.append(f'<text x="{x + 3:.2f}" y="{y + row_h - 6}">{escape(label)}</text>')
        out.append("</g>")
        count += 1
        cx = x
        for child in sorted(node["c"].values(), key=lambda c: -c["v"]):
            walk(child, cx, level + 1)
            cx += child["v"] / total * width

    walk(root, 0.0, 0)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'font-family="monospace" font-size="11">{"".join(out)}</svg>'), count


PAGE = """<!doctype html><html lang="fr"><meta charset="utf-8"><title>Flamegraph IDS/IPS</title>
<style>
body{{font-family:system-ui,sans-serif;margin:12px;background:#fafafa;color:#222}}
input{{padding:6px 10px;width:340px;font-size:14px}} .g{{overflow-x:auto;margin-top:10px}}
text{{pointer-events:none;fill:#111}} .f:hover rect{{stroke:#000;stroke-width:1}}
.dim{{opacity:.25}} .hit rect{{stroke:#000;stroke-width:2}}
small{{color:#666}}
</style>
<h3>🔥 Flamegraph — {title}</h3>
<input id="q" placeholder="🔎 rechercher une fonction (ex : predict_sequence)">
<small> &nbsp;{count} blocs · total {total:.1f} s · largeur = temps inclusif</small>
<div class="g">{svg}</div>
<script>
const q=document.getElementById('q'), fs=[...document.querySelectorAll('.f')];
q.addEventListener('input',()=>{{const t=q.value.trim().toLowerCase();
 fs.forEach(f=>{{const m=t&&f.dataset.n.includes(t);
  f.classList.toggle('hit',!!m); f.classList.toggle('dim',!!t&&!m);}});}});
</script></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folded", help="fichier folded.txt")
    ap.add_argument("-o", "--output", default="")
    ap.add_argument("--thread", default="", help="ne garder que les threads dont le nom contient ce texte")
    ap.add_argument("--min-pct", type=float, default=0.2, help="masquer les blocs < X %% du total (défaut 0.2)")
    ap.add_argument("--width", type=int, default=1400)
    a = ap.parse_args()

    src = Path(a.folded)
    root = build_tree(src, a.thread)
    if root["v"] <= 0:
        raise SystemExit("Aucun échantillon (filtre --thread trop strict ou fichier vide ?).")
    svg, count = render(root, a.width, a.min_pct)
    out = Path(a.output) if a.output else src.with_name("flame.html")
    out.write_text(PAGE.format(title=escape(src.parent.name or src.name), count=count,
                               total=root["v"] / 1000, svg=svg), encoding="utf-8")
    print(f"✅ {out}  ({out.stat().st_size / 1024:.0f} Ko, {count} blocs) — ouvre-le dans ton navigateur")


if __name__ == "__main__":
    main()
