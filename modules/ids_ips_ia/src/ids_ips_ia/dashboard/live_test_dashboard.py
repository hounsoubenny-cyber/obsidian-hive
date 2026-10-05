#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 20:59:53 2026

@author: hounsousamuel
"""

"""
live_test_dashboard.py — test « en conditions réelles » du Dashboard.

Ce que fait ce script :
  * Ouvre un VRAI pseudo-terminal (pty) et exécute le Dashboard dedans, comme s'il
    tournait dans un vrai terminal (mode "tty" du Dashboard, pas le fallback).
  * Fait tourner un workload réaliste : snapshot_fn qui évolue (compteurs, files,
    pertes, inférence) + des logs écrits directement sur stdout — donc dans la
    région de défilement, en bas.
  * Renvoie en direct la sortie PTY vers VOTRE terminal : vous voyez le dashboard
    vivre, les logs défiler, le bandeau se rafraîchir.
  * Optionnellement, simule un resize en cours de route (SIGWINCH-like).
  * Capture TOUT et analyse à la fin : clear, région de défilement, save/restore
    curseur, count de frames, lignes de logs dans la zone du bas, etc.

Usage :
    python live_test_dashboard.py                          # 15 s
    python live_test_dashboard.py 30                       # 30 s
    python live_test_dashboard.py 15 --dashboard ./dash.py # chemin explicite
    python live_test_dashboard.py 15 --quiet               # pas d'affichage live
    python live_test_dashboard.py 15 --resize              # simule un resize à mi-parcours

Prérequis :
    Python 3.10+
    Linux ou macOS (pty n'existe pas sur Windows)
    Le fichier du Dashboard doit s'appeler `dashboard.py` et être à côté de ce
    script, ou passé en --dashboard.
"""
import argparse
import fcntl
import importlib.util
import logging
import os
import pty
import random
import re
import shutil
import signal
import struct
import sys
import termios
import time
import traceback
from pathlib import Path

# ----------------------------------------------------------------------------- chargement du Dashboard
def load_dashboard_class(path_hint: str | None):
    """Charge la classe Dashboard depuis --dashboard, sinon depuis le module `dashboard`."""
    if path_hint:
        p = Path(path_hint).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Fichier introuvable : {p}")
        spec = importlib.util.spec_from_file_location(p.stem, p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not hasattr(mod, "Dashboard"):
            raise ImportError(f"{p} ne contient pas de classe `Dashboard`")
        return mod.Dashboard
    # Import par nom de module
    here = Path(__file__).resolve().parent
    for name in ("dashboard", "dashboard_ansi"):
        candidate = here / f"{name}.py"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location(name, candidate)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "Dashboard"):
                return mod.Dashboard
    raise ImportError(
        "Impossible de trouver `dashboard.py`. Passez --dashboard chemin/vers/dashboard.py"
    )


# ----------------------------------------------------------------------------- workload côté enfant
def child_workload(Dashboard, duration: float, resize_at: float | None):
    """S'exécute DANS le pseudo-terminal. Écrit le dashboard + des logs sur stdout."""
    state = {"packets": 0, "recv": 0, "kept": 0, "anom": 0, "blocked": 0}
    start = time.monotonic()

    def snapshot():
        t = time.monotonic() - start
        # Rythme ~5000 pkt/s avec du jitter (pour faire vivre le sparkline et l'EWMA)
        jitter = 1 + 0.15 * random.random()
        state["packets"] += int(5000 * jitter * 0.5)  # 0.5 s d'intervalle
        state["recv"] += int(5200 * jitter * 0.5)
        state["kept"] += int(5000 * jitter * 0.5)
        if random.random() < 0.05:
            state["anom"] += 1
        if random.random() < 0.01:
            state["blocked"] += 1
        return {
            "capture": {
                "recv": state["recv"],
                "kept": state["kept"],
                "loss_pct": 3.5 + random.random(),
                "kernel_loss_pct": 0.5,
                "app_loss_pct": 3.0,
            },
            "detector": {
                "uptime_s": t,
                "mode": "pcap",
                "packets_processed": state["packets"],
                "sequences_evaluated": state["packets"] // 4,
                "batches": state["packets"] // 32,
                "last_batch_size": 32,
                "avg_batch_size": 30.5,
                "anomalies_in_memory": state["anom"] % 50,
                "system_alerts_open": 2,
                "queue": {
                    "size": 10 + int(40 * random.random()),
                    "max": 512,
                    "fill_pct": 2 + 8 * random.random(),
                },
                "pipeline": {"ready_batches": random.randint(2, 8), "depth": 16},
                "inference": {"modelA": {"failing": False}},
            },
            "anomalies_logged": state["anom"],
            "blocked": state["blocked"],
            "batcher": {
                "queued": random.randint(0, 5),
                "commands": state["blocked"] * 2,
                "failed": 0,
                "dropped": 0,
            },
        }

    dash = Dashboard(
        snapshot_fn=snapshot,
        title="OBSIDIAN (live test)",
        interval=0.5,
        footer="journaux ci-dessous — Ctrl-C pour arrêter",
    )
    dash.start()

    # Un logger Python normal qui écrit sur stdout : c'est ce qu'on veut tester
    # (les messages doivent aller dans la zone de défilement du bas, sans casser
    # le bandeau du haut).
    log = logging.getLogger("live_test")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S"
    ))
    log.addHandler(h)

    messages = [
        (logging.DEBUG,   "initialisation du pipeline"),
        (logging.INFO,    "capture démarrée sur eth0"),
        (logging.INFO,    "modèle chargé (128 Mo)"),
        (logging.WARNING, "file d'attente à 45 %, ralentissement possible"),
        (logging.INFO,    "lot traité en 12 ms"),
        (logging.ERROR,   "échec du blocage nftables pour 10.0.0.42"),
        (logging.INFO,    "reconnexion au journal système"),
        (logging.WARNING, "dérive détectée sur le détecteur A"),
        (logging.INFO,    "checkpoint sauvegardé"),
    ]

    resize_done = False
    deadline = time.monotonic() + duration
    i = 0
    try:
        while time.monotonic() < deadline:
            level, msg = messages[i % len(messages)]
            log.log(level, msg)
            i += 1
            # Resize en cours de route (le parent ne peut pas le faire à notre place)
            if resize_at and not resize_done and (time.monotonic() - start) >= resize_at:
                resize_done = True
                # Simule un resize : change la taille vue par shutil.get_terminal_size
                # via l'ioctl TIOCSWINSZ sur le fd de sortie (le vrai mécanisme SIGWINCH).
                try:
                    import shutil as _sh
                    cols, rows = _sh.get_terminal_size((100, 40))
                    new_cols, new_rows = max(80, cols - 20), max(20, rows - 10)
                    fcntl.ioctl(
                        sys.stdout.fileno(),
                        termios.TIOCSWINSZ,
                        struct.pack("HHHH", new_rows, new_cols, 0, 0),
                    )
                except Exception:
                    pass
            time.sleep(1.2 + 0.6 * random.random())
    except KeyboardInterrupt:
        pass
    finally:
        try:
            dash.stop()
        except Exception:
            traceback.print_exc()


# ----------------------------------------------------------------------------- boucle parent
def run_live(Dashboard, duration: float, quiet: bool, resize_at: float | None) -> bytes:
    """Fork + PTY, écho vers le terminal réel, capture pour analyse."""
    # Adapter la taille du PTY à celle du terminal réel
    try:
        cols, rows = shutil.get_terminal_size((120, 40))
    except Exception:
        cols, rows = 120, 40

    pid, master_fd = pty.fork()
    if pid == 0:
        # ---------- Enfant ----------
        os.environ.setdefault("TERM", "xterm-256color")
        os.environ["COLUMNS"] = str(cols)
        os.environ["LINES"] = str(rows)
        try:
            child_workload(Dashboard, duration, resize_at)
        except Exception:
            print("\n[child] exception :", flush=True)
            traceback.print_exc()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)

    # ---------- Parent ----------
    try:
        fcntl.ioctl(
            master_fd, termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, cols, 0, 0),
        )
    except Exception:
        pass

    captured = bytearray()
    out = sys.stdout.buffer

    if not quiet:
        # Bandeau d'information pour l'utilisateur (hors PTY)
        out.write(
            f"\r\n[live_test] duration={duration:.0f}s  PTY={cols}x{rows}  "
            f"resize={'oui' if resize_at else 'non'}\r\n\r\n".encode()
        )
        out.flush()

    deadline = time.monotonic() + duration + 5.0
    try:
        while time.monotonic() < deadline:
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            captured.extend(data)
            if not quiet:
                try:
                    out.write(data)
                    out.flush()
                except Exception:
                    pass
    finally:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        # Restaurer le terminal de l'utilisateur (au cas où la sortie du PTY l'a modifié)
        try:
            sys.stdout.write("\x1b[r\x1b[0m\x1b[?25h\n")
            sys.stdout.flush()
        except Exception:
            pass

    return bytes(captured)


# ----------------------------------------------------------------------------- analyse
def analyze(captured: bytes) -> dict:
    text = captured.decode("utf-8", errors="replace")

    scroll_set = re.findall(r"\x1b\[(\d+);(\d+)r", text)
    scroll_reset = len(re.findall(r"\x1b\[r", text))
    clears = text.count("\x1b[2J")
    saves = text.count("\x1b7")
    restores = text.count("\x1b8")

    # Positionnements curseur : \x1b[{n};1H
    pos_all = [int(n) for n in re.findall(r"\x1b\[(\d+);1H", text)]
    pos_top = [n for n in pos_all if 1 <= n <= 10]      # zone du dashboard (HEIGHT=10)
    pos_bottom = [n for n in pos_all if n > 10]          # zone de défilement

    # Compter les "frames" : chaque frame = \x1b7 ... \x1b8
    # On découpe sur \x1b7 puis on cherche \x1b8 dans chacun
    frames = 0
    frame_top_positions: list[int] = []
    frame_pos_counts: list[int] = []
    for chunk in text.split("\x1b7")[1:]:
        end = chunk.find("\x1b8")
        if end < 0:
            continue
        frames += 1
        inner = chunk[:end]
        positions = [int(n) for n in re.findall(r"\x1b\[(\d+);1H", inner)]
        frame_top_positions.extend([n for n in positions if 1 <= n <= 10])
        frame_pos_counts.append(len(positions))

    # Lignes de log : on cherche les timestamps dans la zone basse, sans \x1b[..H
    log_lines = re.findall(r"\d{2}:\d{2}:\d{2} \| (DEBUG|INFO|SUCCESS|WARNING|ERROR|CRITICAL)", text)

    return {
        "clear": clears,
        "scroll_set": scroll_set,
        "scroll_reset": scroll_reset,
        "cursor_saves": saves,
        "cursor_restores": restores,
        "frames": frames,
        "frame_pos_counts": frame_pos_counts,
        "positions_top": len(pos_top),
        "positions_bottom": len(pos_bottom),
        "log_lines_by_level": {
            lvl: log_lines.count(lvl) for lvl in
            {"DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"}
        },
        "total_bytes": len(captured),
    }


def print_report(report: dict, duration: float):
    print("\n" + "=" * 70)
    print("RAPPORT DU TEST LIVE")
    print("=" * 70)
    print(f"Durée simulée          : {duration:.0f} s")
    print(f"Octets capturés        : {report['total_bytes']:,} octets")
    print()

    def chk(label, ok, detail=""):
        mark = "\033[32m✔\033[0m" if ok else "\033[31m✘\033[0m"
        print(f"  {mark}  {label:<40} {detail}")

    # 1. Le terminal a bien été mis en mode dashboard
    chk("Effacement écran (\\x1b[2J)", report["clear"] >= 1,
        f"({report['clear']}×)")

    # 2. La région de défilement a été posée au moins une fois
    chk("Région de défilement posée", len(report["scroll_set"]) >= 1,
        f"({len(report['scroll_set'])}×, ex. {report['scroll_set'][:2]})")

    # 3. Elle a été retirée à la fin (ou lors d'un resize)
    chk("Région de défilement retirée", report["scroll_reset"] >= 1,
        f"({report['scroll_reset']}×)")

    # 4. Les frames utilisent bien save/restore curseur (écriture atomique)
    chk("Frames atomiques (\\x1b7 … \\x1b8)",
        report["frames"] >= 3 and report["cursor_saves"] == report["cursor_restores"],
        f"{report['frames']} frames, {report['cursor_saves']} save / {report['cursor_restores']} restore")

    # 5. Chaque frame positionne bien les 10 lignes du dashboard
    if report["frame_pos_counts"]:
        expected = 10  # Dashboard.HEIGHT
        ok = all(c == expected for c in report["frame_pos_counts"])
        chk("Chaque frame place les 10 lignes du dashboard", ok,
            f"counts={report['frame_pos_counts'][:5]}…" if not ok else f"({len(report['frame_pos_counts'])} frames × {expected} lignes)")

    # 6. Aucun positionnement curseur en zone basse (les logs sont écrits naturellement)
    chk("Aucun curseur forcé en zone basse",
        report["positions_bottom"] == 0,
        f"({report['positions_bottom']} positionnements bas détectés)")

    # 7. Des logs sont bien apparus
    total_logs = sum(report["log_lines_by_level"].values())
    chk("Lignes de log émises", total_logs >= 3,
        f"({total_logs} lignes)")

    # 8. On a vu défiler plusieurs niveaux (DEBUG, INFO, WARNING, ERROR)
    seen_levels = [lvl for lvl, n in report["log_lines_by_level"].items() if n > 0]
    chk("Plusieurs niveaux distincts", len(seen_levels) >= 3,
        f"({sorted(seen_levels)})")

    print()
    print("Détail par niveau :")
    for lvl in ("DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"):
        n = report["log_lines_by_level"].get(lvl, 0)
        if n:
            print(f"    {lvl:<10} {n}")

    print()
    ok_all = (
        report["clear"] >= 1
        and len(report["scroll_set"]) >= 1
        and report["scroll_reset"] >= 1
        and report["frames"] >= 3
        and report["cursor_saves"] == report["cursor_restores"]
        and report["positions_bottom"] == 0
        and total_logs >= 3
    )
    if ok_all:
        print("\033[1;32m→ Tous les invariants critiques sont respectés.\033[0m")
    else:
        print("\033[1;31m→ Au moins un invariant a échoué — voir ci-dessus.\033[0m")
    print("=" * 70)


# ----------------------------------------------------------------------------- entrée
def main():
    ap = argparse.ArgumentParser(description="Test live du Dashboard en PTY réel.")
    ap.add_argument("duration", nargs="?", type=float, default=15.0,
                    help="Durée du test en secondes (défaut : 15)")
    ap.add_argument("--dashboard", default=None,
                    help="Chemin vers dashboard.py (sinon recherche à côté de ce script)")
    ap.add_argument("--quiet", action="store_true",
                    help="Ne pas renvoyer la sortie PTY vers le terminal")
    ap.add_argument("--resize", action="store_true",
                    help="Simule un resize du terminal à mi-parcours")
    args = ap.parse_args()

    if not sys.platform.startswith(("linux", "darwin")):
        print("Ce test utilise pty : Linux/macOS uniquement.", file=sys.stderr)
        sys.exit(2)

    print(f"Chargement de la classe Dashboard…")
    Dashboard = load_dashboard_class(args.dashboard)
    print(f"  → {Dashboard.__module__}.{Dashboard.__qualname__}")

    resize_at = args.duration / 2 if args.resize else None

    print(f"\nDémarrage du test live ({args.duration:.0f} s)…")
    print("  (le dashboard devrait apparaître ci-dessous)\n")
    time.sleep(0.5)

    captured = run_live(Dashboard, args.duration, args.quiet, resize_at)

    report = analyze(captured)
    print_report(report, args.duration)


if __name__ == "__main__":
    main()