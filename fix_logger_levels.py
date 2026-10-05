#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May  7 07:50:10 2026

@author: hounsousamuel
"""

"""
fix_logger_levels.py — remplace `logger.print(...)` par `logger.<niveau>(...)` avec un VRAI niveau.

Principe
  * on lit chaque fichier avec `ast` (jamais de regex sur le code : chaînes, commentaires et f-strings sont sûrs) ;
  * le niveau est déduit du TEXTE LITTÉRAL de l'appel avec EXACTEMENT les regex de ton Logger (_detect_level) :
    SUCCESS avant ERROR avant WARNING avant DEBUG, sinon INFO -> le niveau choisi est celui que `print` aurait calculé
    à l'exécution (pour les f-strings, seule la partie fixe est connue) ;
  * trois heuristiques en plus (désactivables) : emojis (❌ error, ⚠️ warning, ✅ success), appel placé sous un
    `if verbose:` -> debug (sauf error/warning), `verify=False` -> info ;
  * on ne remplace QUE le mot `print` après `logger.` (position exacte via l'AST) : arguments, retours à la ligne,
    commentaires et encodage restent intacts ;
  * un appel SANS texte littéral (`logger.print(traceback.format_exc())`, `logger.print(msg)`) n'est PAS modifié :
    il est listé avec fichier:ligne pour que tu le vérifies toi-même ;
  * `logger.print()` vide (ligne blanche) est laissé tel quel (compté seulement).

Pré-requis : le Logger doit avoir les méthodes « print-like » (logger.py patché : debug/info/success/warning/error
acceptent plusieurs arguments, sep=, et ignorent end=/flush=/file=). Le script le vérifie (--force pour passer outre).

Usage
  python3 fix_logger_levels.py                       # RAPPORT seulement (dry-run) sur modules/ids_ips_ia/src/ids_ips_ia
  python3 fix_logger_levels.py --apply               # applique (puis : git diff)
  python3 fix_logger_levels.py --path <fichier|dossier> --report mon_rapport.txt
  python3 fix_logger_levels.py --no-verbose-debug --no-emoji --names logger,log
"""
import argparse
import ast
import collections
import re
import sys
from pathlib import Path

# --- mêmes regex que modules_utils/logger.py (repris tels quels : si tu les modifies là-bas, modifie-les ici) ---
_SUCCESS_RE = re.compile(r'\b(success|succ[eè]s|termin[eé]\s*(avec\s*succ[eè]s)?|done|ok)\b', re.I)
_ERROR_RE = re.compile(r'\b(error|erreur|fail(ed|ure)?|critical|fatal|exception|échec|échoué)\b', re.I)
_WARNING_RE = re.compile(r'\b(warning|warn|attention|deprecated)\b', re.I)
_DEBUG_RE = re.compile(r'\b(debug|trace|verbose)\b', re.I)

EMOJI_HINTS = (("error", ("❌", "✖", "🚨", "💥", "⛔")), ("warning", ("⚠",)), ("success", ("✅", "✔", "🎉")),
               ("debug", ("🐛",)))
EXCLUDED_DIRS = {"__pycache__", ".git", "test_utils", "results", "node_modules", "venv", ".venv"}
DEFAULT_PATH = "modules/ids_ips_ia/src/ids_ips_ia"


def regex_level(text: str):
    for name, rx in (("success", _SUCCESS_RE), ("error", _ERROR_RE), ("warning", _WARNING_RE), ("debug", _DEBUG_RE)):
        if rx.search(text):
            return name
    return "info"


def literal_text(call: ast.Call) -> str:
    """Concatène les morceaux de texte FIXES de tous les arguments (y compris la partie fixe des f-strings)."""
    parts = []
    for arg in call.args:
        for n in ast.walk(arg):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                parts.append(n.value)
    return " ".join(parts)


def classify(call, text, parents, opts):
    """Retourne (niveau, raison)."""
    for kw in call.keywords:
        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return "info", "verify=False"
    lvl = regex_level(text)
    reason = f"regex:{lvl.upper()}" if lvl != "info" else "défaut"
    if opts.emoji and lvl == "info":
        for name, emojis in EMOJI_HINTS:
            hit = next((e for e in emojis if e in text), None)
            if hit:
                return name, f"emoji:{hit}"
    if opts.verbose_debug and lvl in ("info", "success"):
        n = call
        while n in parents:
            n = parents[n]
            if isinstance(n, ast.If) and any(isinstance(x, ast.Name) and x.id == "verbose" for x in ast.walk(n.test)):
                return "debug", "sous `if verbose`"
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                break
    return lvl, reason


def in_except(call, parents) -> bool:
    n = call
    while n in parents:
        n = parents[n]
        if isinstance(n, ast.ExceptHandler):
            return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
    return False


def iter_py_files(root: Path, include_tests: bool):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*.py")):
        if any(part in EXCLUDED_DIRS for part in p.relative_to(root).parts[:-1]) and not include_tests:
            continue
        yield p


def process_file(path: Path, names, opts):
    """Retourne (edits, conversions, a_verifier, vides, nouveau_source_ou_None)."""
    raw = path.read_bytes()
    try:
        tree = ast.parse(raw)
    except SyntaxError as e:
        print(f"⚠️  {path} : syntaxe illisible ({e}) — ignoré")
        return [], [], [], 0, None
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    lines = raw.splitlines(keepends=True)
    edits, conversions, to_check, blanks = [], [], [], 0
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "print"
                and isinstance(n.func.value, ast.Name) and n.func.value.id in names):
            continue
        src_line = lines[n.lineno - 1].decode("utf-8", "replace").strip()
        if not n.args and not n.keywords:
            blanks += 1
            continue
        text = literal_text(n)
        if not text.strip():
            hint = " (dans un except -> probablement `error` / `exception`)" if in_except(n, parents) else ""
            to_check.append((n.lineno, src_line[:110] + hint))
            continue
        level, reason = classify(n, text, parents, opts)
        # position EXACTE du mot `print` : fin de `logger.print` moins 5 octets (les offsets de l'AST sont en OCTETS)
        ln, end = n.func.end_lineno, n.func.end_col_offset
        if lines[ln - 1][end - 5:end] != b"print":
            to_check.append((n.lineno, f"position illisible : {src_line[:90]}"))
            continue
        edits.append((ln, end - 5, level))
        conversions.append((n.lineno, level, reason, " ".join(text.split())[:70]))
    new_src = None
    if edits:
        for ln, col, level in sorted(edits, reverse=True):          # de la fin vers le début : les positions restent valides
            line = lines[ln - 1]
            lines[ln - 1] = line[:col] + level.encode() + line[col + 5:]
        new_src = b"".join(lines)
        try:
            ast.parse(new_src)                                      # garde-fou : le résultat doit rester du Python valide
        except SyntaxError as e:
            print(f"❌ {path} : le résultat serait invalide ({e}) — fichier laissé INTACT")
            return [], [], to_check, blanks, None
    return edits, conversions, to_check, blanks, new_src


def logger_is_printlike(start: Path) -> bool:
    """Le logger.py du repo a-t-il les méthodes print-like (présence de `_emit`) ? Introuvable -> on ne bloque pas."""
    for base in [Path.cwd(), *Path.cwd().parents, start.resolve(), *start.resolve().parents]:
        f = base / "modules/modules_utils/src/modules_utils/logger.py"
        if f.is_file():
            return "def _emit(" in f.read_text(encoding="utf-8", errors="replace")
    return True      # introuvable : on ne bloque pas (message plus bas)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--apply", action="store_true", help="écrit les fichiers (sinon : rapport seulement)")
    ap.add_argument("--report", default="logger_level_report.txt")
    ap.add_argument("--names", default="logger", help="noms de variables logger, séparés par des virgules")
    ap.add_argument("--no-emoji", dest="emoji", action="store_false")
    ap.add_argument("--no-verbose-debug", dest="verbose_debug", action="store_false")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--force", action="store_true", help="ne pas vérifier que le Logger est print-like")
    opts = ap.parse_args()

    root = Path(opts.path)
    if not root.exists():
        sys.exit(f"Chemin introuvable : {root} (lance le script depuis la racine du repo ou donne --path)")
    if opts.apply and not opts.force and not logger_is_printlike(root):
        sys.exit("Le Logger n'a pas les méthodes print-like (logger.py non patché) : un print converti pourrait mal "
                 "s'afficher avec plusieurs arguments. Patche logger.py d'abord, ou --force.")
    names = {s.strip() for s in opts.names.split(",") if s.strip()}

    per_level, per_file, all_conv, all_check, total_blank, changed = (collections.Counter(), collections.Counter(), [], [], 0, 0)
    for p in iter_py_files(root, opts.include_tests):
        edits, conv, check, blanks, new_src = process_file(p, names, opts)
        total_blank += blanks
        for ln, lvl, why, txt in conv:
            per_level[lvl] += 1
            per_file[p.name] += 1
            all_conv.append((p, ln, lvl, why, txt))
        for ln, src in check:
            all_check.append((p, ln, src))
        if new_src is not None and opts.apply:
            p.write_bytes(new_src)
            changed += 1

    out = []
    out.append(f"{'APPLIQUÉ' if opts.apply else 'DRY-RUN (rien n’est modifié ; ajoute --apply)'} — cible : {root}")
    out.append(f"Conversions : {sum(per_level.values())}  par niveau : {dict(per_level)}")
    out.append(f"Appels vides logger.print() laissés tels quels : {total_blank}")
    out.append(f"À VÉRIFIER (sans texte littéral, NON modifiés) : {len(all_check)}")
    out.append("Top fichiers : " + ", ".join(f"{k} ({v})" for k, v in per_file.most_common(8)))
    out.append("")
    out.append("=== À VÉRIFIER : fichier:ligne ===")
    for p, ln, src in all_check:
        out.append(f"{p}:{ln}  {src}")
    out.append("")
    out.append("=== CONVERSIONS : fichier:ligne  NIVEAU  raison  | texte ===")
    for p, ln, lvl, why, txt in all_conv:
        out.append(f"{p}:{ln}  {lvl.upper():8s} {why:16s} | {txt}")
    Path(opts.report).write_text("\n".join(out), encoding="utf-8")

    print("\n".join(out[:5]))
    print(f"\n=== À VÉRIFIER ({len(all_check)}) : fichier:ligne ===")
    for p, ln, src in all_check:
        print(f"{p}:{ln}  {src}")
    print(f"\n📝 Rapport complet (chaque conversion avec sa raison) : {opts.report}")
    if opts.apply:
        print(f"✅ {changed} fichier(s) modifié(s). Vérifie avec `git diff` ; annule avec `git checkout -- <fichier>`.")
    else:
        print("👉 Relis le rapport, surtout les WARNING et SUCCESS (les regex devinent), puis relance avec --apply.")


if __name__ == "__main__":
    main()