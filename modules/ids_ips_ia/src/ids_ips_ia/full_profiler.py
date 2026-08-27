#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PROFILER COMPLET — Obsidian Hive IDS/IPS
==========================================
Profile une exécution réelle avec TOUTES les couches :
  - cProfile        : temps CPU par fonction Python (avec appelants/appelés)
  - py-spy          : sampling natif (voit aussi dans Cython/numpy/TensorFlow/C)
  - tracemalloc     : mémoire allouée par ligne de code
  - strace          : syscalls (recv, execve pour nft, futex pour les locks)
  - psutil          : CPU%, RAM, threads, FDs, I/O disque/réseau en continu
  - py-spy flamegraph SVG interactif

Sort un rapport HTML unique avec tous les graphs + un .stats réutilisable.

Usage:
    sudo python full_profiler.py --duration 120
    sudo python full_profiler.py --duration 120 --skip-strace   # si pas confiance perf
"""

import os
import sys
import time
import json
import shutil
import signal
import socket
import sqlite3
import cProfile
import pstats
import argparse
import threading
import subprocess
import traceback
import tracemalloc
import multiprocessing as mp
from io import StringIO
from datetime import datetime
from pathlib import Path

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

OUTDIR = Path("./profiling_results") / datetime.now().strftime("%Y%m%d_%H%M%S")
OUTDIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# 0. CHECK / INSTALL DES DÉPENDANCES OPTIONNELLES
# ============================================================================

def ensure_tool(pip_name, import_name=None, apt_name=None):
    import_name = import_name or pip_name
    try:
        __import__(import_name)
        return True
    except ImportError:
        print(f"📦 Installation de {pip_name}...")
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name, "--break-system-packages", "-q"],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"⚠️  Échec installation {pip_name} : {r.stderr[-300:]}")
            return False
        return True


def ensure_binary(name, apt_pkg):
    if shutil.which(name):
        return True
    print(f"📦 Tentative d'installation de {name} ({apt_pkg})...")
    r = subprocess.run(["sudo", "apt-get", "install", "-y", apt_pkg], capture_output=True, text=True)
    return shutil.which(name) is not None


# ============================================================================
# 1. MONITORING SYSTÈME EN CONTINU (psutil) — CPU/RAM/threads/FDs/I/O
# ============================================================================

class SystemMonitor:
    """Échantillonne CPU%, RAM, threads, FDs, I/O toutes les 0.5s pendant le run."""

    def __init__(self, pid: int, interval: float = 0.5):
        self.pid = pid
        self.interval = interval
        self.samples = []
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        import psutil
        try:
            proc = psutil.Process(self.pid)
        except Exception as e:
            print(f"⚠️ SystemMonitor: impossible d'attacher au PID {self.pid}: {e}")
            return

        proc.cpu_percent(interval=None)  # warm-up, le premier appel retourne 0.0
        t0 = time.time()

        while not self._stop.is_set():
            try:
                with proc.oneshot():
                    cpu = proc.cpu_percent(interval=None)
                    mem = proc.memory_info()
                    n_threads = proc.num_threads()
                    try:
                        n_fds = proc.num_fds()
                    except Exception:
                        n_fds = -1
                    try:
                        io = proc.io_counters()
                        read_bytes, write_bytes = io.read_bytes, io.write_bytes
                    except Exception:
                        read_bytes, write_bytes = -1, -1

                # Inclut les processus enfants (refit manager en mp.Process, etc.)
                children_cpu = 0.0
                children_mem = 0
                try:
                    for child in proc.children(recursive=True):
                        try:
                            children_cpu += child.cpu_percent(interval=None)
                            children_mem += child.memory_info().rss
                        except Exception:
                            pass
                except Exception:
                    pass

                self.samples.append({
                    "t": time.time() - t0,
                    "cpu_percent": cpu,
                    "children_cpu_percent": children_cpu,
                    "rss_mb": mem.rss / 1024 / 1024,
                    "children_rss_mb": children_mem / 1024 / 1024,
                    "vms_mb": mem.vms / 1024 / 1024,
                    "n_threads": n_threads,
                    "n_fds": n_fds,
                    "read_bytes": read_bytes,
                    "write_bytes": write_bytes,
                })
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.samples, f, indent=2)


# ============================================================================
# 2. cProfile — temps CPU Python pur, avec graphe d'appel
# ============================================================================

def run_cprofile(duration: int):
    from ids_ips_ia.main.orchestrator import IDS_IPS
    from ids_ips_ia.ids_ips_utils.logger import get_logger
    logger = get_logger()

    print(f"🔍 [1/5] cProfile démarré ({duration}s)...")

    monitor = SystemMonitor(os.getpid())
    monitor.start()

    tracemalloc.start(25)  # garde les 25 frames d'appel pour chaque alloc

    profiler = cProfile.Profile()
    ids = IDS_IPS()

    profiler.enable()
    th = threading.Thread(target=ids.main, args=(True,), daemon=True)
    th.start()

    try:
        th.join(duration)
    except KeyboardInterrupt:
        logger.print("[PROFILER] Interruption manuelle")
    finally:
        ids.stop()
        time.sleep(3)

    profiler.disable()
    monitor.stop()

    # Snapshot mémoire
    snapshot = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats_file = OUTDIR / "cprofile.stats"
    profiler.dump_stats(str(stats_file))
    monitor.save(OUTDIR / "system_monitor.json")

    return stats_file, snapshot, monitor


def parse_cprofile_to_json(stats_file):
    """Extrait les stats cProfile en JSON exploitable pour les graphs."""
    p = pstats.Stats(str(stats_file))
    p.calc_callees()

    rows = []
    for func, (cc, nc, tt, ct, callers) in p.stats.items():
        filename, lineno, funcname = func
        rows.append({
            "function": funcname,
            "file": os.path.basename(filename),
            "line": lineno,
            "ncalls": nc,
            "primitive_calls": cc,
            "tottime": tt,
            "cumtime": ct,
            "tottime_per_call": tt / nc if nc else 0,
            "cumtime_per_call": ct / nc if nc else 0,
        })

    rows.sort(key=lambda r: r["cumtime"], reverse=True)
    return rows


# ============================================================================
# 3. py-spy — profiling natif (voit dans Cython/numpy/TensorFlow/C)
# ============================================================================

def run_pyspy(pid: int, duration: int):
    """Lance py-spy en parallèle sur le process déjà démarré, génère un flamegraph SVG."""
    if not shutil.which("py-spy"):
        ensure_tool("py-spy")

    if not shutil.which("py-spy"):
        print("⚠️  py-spy indisponible, étape sautée")
        return None

    print(f"🔥 [2/5] py-spy (sampling natif) attaché au PID {pid} pendant {duration}s...")
    svg_path = OUTDIR / "pyspy_flamegraph.svg"
    speedscope_path = OUTDIR / "pyspy_speedscope.json"

    try:
        subprocess.run(
            ["py-spy", "record", "-o", str(svg_path), "--pid", str(pid),
             "--duration", str(duration), "--rate", "100", "--subprocesses"],
            check=False, timeout=duration + 15
        )
    except Exception as e:
        print(f"⚠️  py-spy record (svg) échoué : {e}")

    try:
        subprocess.run(
            ["py-spy", "record", "-o", str(speedscope_path), "--format", "speedscope",
             "--pid", str(pid), "--duration", "5", "--rate", "100"],
            check=False, timeout=20
        )
    except Exception:
        pass  # optionnel, pas grave si ça échoue (process déjà mort à ce stade)

    return svg_path if svg_path.exists() else None


# ============================================================================
# 4. strace — syscalls (recv, execve pour nft, futex pour locks)
# ============================================================================

def run_strace(pid: int, duration: int):
    if not shutil.which("strace"):
        ensure_binary("strace", "strace")
    if not shutil.which("strace"):
        print("⚠️  strace indisponible (sudo apt install strace), étape sautée")
        return None

    print(f"🖥️  [3/5] strace attaché au PID {pid} pendant {min(duration, 30)}s (résumé syscalls)...")
    out_file = OUTDIR / "strace_summary.txt"

    try:
        # -c = résumé statistique, -f = suit les threads/forks, -p = attache au PID vivant
        proc = subprocess.Popen(
            ["strace", "-c", "-f", "-p", str(pid)],
            stderr=open(out_file, "w"), stdout=subprocess.DEVNULL
        )
        time.sleep(min(duration, 30))
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
    except Exception as e:
        print(f"⚠️  strace échoué (besoin de CAP_SYS_PTRACE ou root) : {e}")
        return None

    return out_file if out_file.exists() else None


def parse_strace_summary(path):
    """Parse le résumé strace -c en liste de dicts (syscall, calls, time%, ...)."""
    if not path or not path.exists():
        return []
    rows = []
    with open(path) as f:
        lines = f.readlines()
    for line in lines:
        parts = line.split()
        # Format typique : % time     seconds  usecs/call     calls    errors syscall
        if len(parts) >= 6 and parts[0].replace('.', '').isdigit():
            try:
                rows.append({
                    "time_pct": float(parts[0]),
                    "seconds": float(parts[1]),
                    "usecs_per_call": float(parts[2]) if parts[2].isdigit() else 0,
                    "calls": int(parts[3]),
                    "syscall": parts[-1],
                })
            except Exception:
                continue
    rows.sort(key=lambda r: r["seconds"], reverse=True)
    return rows


# ============================================================================
# 5. SQLite — stocke tout pour requêtage ultérieur
# ============================================================================

def save_to_sqlite(cprofile_rows, syscall_rows, monitor_samples, db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""CREATE TABLE functions (
        function TEXT, file TEXT, line INT, ncalls INT, primitive_calls INT,
        tottime REAL, cumtime REAL, tottime_per_call REAL, cumtime_per_call REAL
    )""")
    cur.executemany(
        "INSERT INTO functions VALUES (:function,:file,:line,:ncalls,:primitive_calls,"
        ":tottime,:cumtime,:tottime_per_call,:cumtime_per_call)",
        cprofile_rows
    )

    cur.execute("""CREATE TABLE syscalls (
        syscall TEXT, calls INT, seconds REAL, time_pct REAL, usecs_per_call REAL
    )""")
    cur.executemany(
        "INSERT INTO syscalls VALUES (:syscall,:calls,:seconds,:time_pct,:usecs_per_call)",
        syscall_rows
    )

    cur.execute("""CREATE TABLE system_samples (
        t REAL, cpu_percent REAL, children_cpu_percent REAL, rss_mb REAL,
        children_rss_mb REAL, vms_mb REAL, n_threads INT, n_fds INT,
        read_bytes INT, write_bytes INT
    )""")
    cur.executemany(
        "INSERT INTO system_samples VALUES (:t,:cpu_percent,:children_cpu_percent,:rss_mb,"
        ":children_rss_mb,:vms_mb,:n_threads,:n_fds,:read_bytes,:write_bytes)",
        monitor_samples
    )

    conn.commit()
    conn.close()


# ============================================================================
# 6. RAPPORT HTML AVEC GRAPHS (plotly, autonome, pas besoin de serveur)
# ============================================================================

def build_html_report(cprofile_rows, syscall_rows, monitor_samples, mem_top, pyspy_svg, output_path):
    ensure_tool("plotly")
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import plotly.io as pio

    # --- Graph 1 : Top 20 fonctions par cumtime ---
    top_cum = cprofile_rows[:20]
    fig1 = go.Figure(go.Bar(
        x=[r["cumtime"] for r in top_cum][::-1],
        y=[f'{r["function"]} ({r["file"]}:{r["line"]})' for r in top_cum][::-1],
        orientation="h", marker_color="#dc3545"
    ))
    fig1.update_layout(title="Top 20 fonctions — Temps cumulé (cumtime, secondes)",
                        height=600, margin=dict(l=350))

    # --- Graph 2 : Top 20 fonctions par tottime (temps propre, sans sous-appels) ---
    top_tot = sorted(cprofile_rows, key=lambda r: r["tottime"], reverse=True)[:20]
    fig2 = go.Figure(go.Bar(
        x=[r["tottime"] for r in top_tot][::-1],
        y=[f'{r["function"]} ({r["file"]}:{r["line"]})' for r in top_tot][::-1],
        orientation="h", marker_color="#fd7e14"
    ))
    fig2.update_layout(title="Top 20 fonctions — Temps PROPRE (tottime, sans sous-appels)",
                        height=600, margin=dict(l=350))

    # --- Graph 3 : Top 20 fonctions les plus appelées ---
    top_calls = sorted(cprofile_rows, key=lambda r: r["ncalls"], reverse=True)[:20]
    fig3 = go.Figure(go.Bar(
        x=[r["ncalls"] for r in top_calls][::-1],
        y=[f'{r["function"]} ({r["file"]})' for r in top_calls][::-1],
        orientation="h", marker_color="#0d6efd"
    ))
    fig3.update_layout(title="Top 20 fonctions — Nombre d'appels", height=600, margin=dict(l=350))

    # --- Graph 4 : CPU% et RAM dans le temps ---
    if monitor_samples:
        ts = [s["t"] for s in monitor_samples]
        fig4 = make_subplots(specs=[[{"secondary_y": True}]])
        fig4.add_trace(go.Scatter(x=ts, y=[s["cpu_percent"] for s in monitor_samples],
                                   name="CPU% (process principal)", line=dict(color="#dc3545")),
                        secondary_y=False)
        fig4.add_trace(go.Scatter(x=ts, y=[s["children_cpu_percent"] for s in monitor_samples],
                                   name="CPU% (processus enfants)", line=dict(color="#fd7e14")),
                        secondary_y=False)
        fig4.add_trace(go.Scatter(x=ts, y=[s["rss_mb"] for s in monitor_samples],
                                   name="RAM RSS (MB)", line=dict(color="#0d6efd")),
                        secondary_y=True)
        fig4.update_layout(title="CPU% et RAM dans le temps", height=450)
        fig4.update_yaxes(title_text="CPU %", secondary_y=False)
        fig4.update_yaxes(title_text="RAM (MB)", secondary_y=True)
    else:
        fig4 = go.Figure()

    # --- Graph 5 : Threads et FDs dans le temps ---
    if monitor_samples:
        fig5 = make_subplots(specs=[[{"secondary_y": True}]])
        fig5.add_trace(go.Scatter(x=ts, y=[s["n_threads"] for s in monitor_samples],
                                   name="Threads", line=dict(color="#6f42c1")), secondary_y=False)
        fig5.add_trace(go.Scatter(x=ts, y=[s["n_fds"] for s in monitor_samples],
                                   name="File Descriptors", line=dict(color="#20c997")), secondary_y=True)
        fig5.update_layout(title="Threads et File Descriptors dans le temps", height=400)
    else:
        fig5 = go.Figure()

    # --- Graph 6 : I/O disque cumulé ---
    if monitor_samples and monitor_samples[0]["read_bytes"] >= 0:
        fig6 = go.Figure()
        fig6.add_trace(go.Scatter(x=ts, y=[s["read_bytes"]/1024/1024 for s in monitor_samples],
                                   name="Lecture disque (MB)", line=dict(color="#198754")))
        fig6.add_trace(go.Scatter(x=ts, y=[s["write_bytes"]/1024/1024 for s in monitor_samples],
                                   name="Écriture disque (MB)", line=dict(color="#dc3545")))
        fig6.update_layout(title="I/O disque cumulé (MB)", height=400)
    else:
        fig6 = go.Figure()
        fig6.update_layout(title="I/O disque — non disponible sur ce système")

    # --- Graph 7 : Syscalls les plus coûteux ---
    if syscall_rows:
        top_sys = syscall_rows[:15]
        fig7 = go.Figure(go.Bar(
            x=[r["seconds"] for r in top_sys][::-1],
            y=[f'{r["syscall"]} ({r["calls"]} appels)' for r in top_sys][::-1],
            orientation="h", marker_color="#212529"
        ))
        fig7.update_layout(title="Top syscalls — temps total passé (secondes)", height=500, margin=dict(l=250))
    else:
        fig7 = go.Figure()
        fig7.update_layout(title="Syscalls — strace non disponible ou échoué")

    # --- Graph 8 : Top allocations mémoire ---
    if mem_top:
        fig8 = go.Figure(go.Bar(
            x=[m["size_mb"] for m in mem_top][::-1],
            y=[f'{m["file"]}:{m["line"]}' for m in mem_top][::-1],
            orientation="h", marker_color="#e83e8c"
        ))
        fig8.update_layout(title="Top 15 allocations mémoire (par ligne de code)", height=500, margin=dict(l=300))
    else:
        fig8 = go.Figure()

    # --- Assemblage HTML ---
    figs_html = "\n".join(
        pio.to_html(f, include_plotlyjs=(i == 0), full_html=False, div_id=f"fig{i}")
        for i, f in enumerate([fig4, fig1, fig2, fig3, fig7, fig5, fig6, fig8])
    )

    pyspy_section = ""
    if pyspy_svg and pyspy_svg.exists():
        pyspy_section = f"""
        <h2>🔥 Flamegraph natif (py-spy) — inclut Cython/numpy/TensorFlow/C</h2>
        <p>Fichier interactif séparé : <a href="{pyspy_svg.name}">{pyspy_svg.name}</a> (ouvre-le dans un navigateur, zoomable)</p>
        <embed src="{pyspy_svg.name}" type="image/svg+xml" style="width:100%; height:800px; border:1px solid #ccc;">
        """

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport Profiling — Obsidian Hive IDS/IPS</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 1400px; margin: 0 auto; padding: 20px; background:#0d1117; color:#e6edf3; }}
  h1 {{ color: #58a6ff; }}
  h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; margin-top: 40px; }}
  .meta {{ background: #161b22; padding: 16px; border-radius: 8px; margin-bottom: 24px; }}
  .meta span {{ display:inline-block; margin-right: 24px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
  th, td {{ border: 1px solid #30363d; padding: 6px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #161b22; }}
</style>
</head>
<body>
<h1>🔬 Rapport de Profiling — Obsidian Hive IDS/IPS</h1>
<div class="meta">
  <span>📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
  <span>📁 {OUTDIR}</span>
</div>

{figs_html}

{pyspy_section}

<h2>📋 Table complète — fonctions Python (cProfile)</h2>
<table>
<tr><th>Fonction</th><th>Fichier</th><th>Ligne</th><th>Appels</th><th>Tottime (s)</th><th>Cumtime (s)</th></tr>
{"".join(f"<tr><td>{r['function']}</td><td>{r['file']}</td><td>{r['line']}</td><td>{r['ncalls']}</td><td>{r['tottime']:.4f}</td><td>{r['cumtime']:.4f}</td></tr>" for r in cprofile_rows[:100])}
</table>

</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# ============================================================================
# MAIN ORCHESTRATEUR
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Profiler complet IDS/IPS — toutes technos")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--skip-pyspy", action="store_true")
    parser.add_argument("--skip-strace", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("❌ Ce script nécessite root : sudo python full_profiler.py --duration 120")
        sys.exit(1)

    print("=" * 70)
    print("🔬 PROFILER COMPLET — OBSIDIAN HIVE IDS/IPS")
    print(f"   Résultats dans : {OUTDIR}")
    print("=" * 70)

    # On lance cProfile dans un sous-process pour pouvoir l'attacher avec py-spy/strace
    # depuis le process parent en parallèle (sinon ils ne voient que le profiler lui-même)
    own_pid = os.getpid()

    pyspy_thread = None
    strace_thread = None
    pyspy_result = {}
    strace_result = {}

    def _pyspy_job():
        time.sleep(2)  # laisse cProfile démarrer
        pyspy_result["svg"] = run_pyspy(own_pid, max(10, args.duration - 5))

    def _strace_job():
        time.sleep(2)
        strace_result["file"] = run_strace(own_pid, max(10, args.duration - 5))

    if not args.skip_pyspy:
        pyspy_thread = threading.Thread(target=_pyspy_job, daemon=True)
        pyspy_thread.start()
    if not args.skip_strace:
        strace_thread = threading.Thread(target=_strace_job, daemon=True)
        strace_thread.start()

    stats_file, mem_snapshot, monitor = run_cprofile(args.duration)

    if pyspy_thread:
        pyspy_thread.join(timeout=15)
    if strace_thread:
        strace_thread.join(timeout=15)

    print("📊 [4/5] Parsing des résultats...")
    cprofile_rows = parse_cprofile_to_json(stats_file)
    syscall_rows = parse_strace_summary(strace_result.get("file"))

    mem_top_stats = mem_snapshot.statistics("lineno")[:15]
    mem_top = [{
        "file": os.path.basename(s.traceback[0].filename),
        "line": s.traceback[0].lineno,
        "size_mb": s.size / 1024 / 1024,
    } for s in mem_top_stats]

    with open(OUTDIR / "cprofile_top.json", "w") as f:
        json.dump(cprofile_rows[:100], f, indent=2)
    with open(OUTDIR / "syscalls.json", "w") as f:
        json.dump(syscall_rows, f, indent=2)
    with open(OUTDIR / "memory_top.json", "w") as f:
        json.dump(mem_top, f, indent=2)

    save_to_sqlite(cprofile_rows, syscall_rows, monitor.samples, str(OUTDIR / "profiling.db"))

    print("📈 [5/5] Génération du rapport HTML...")
    html_path = OUTDIR / "rapport.html"
    build_html_report(cprofile_rows, syscall_rows, monitor.samples, mem_top,
                       pyspy_result.get("svg"), html_path)

    print("\n" + "=" * 70)
    print("✅ PROFILING TERMINÉ")
    print("=" * 70)
    print(f"📁 Tous les résultats : {OUTDIR}")
    print(f"🌐 Rapport HTML (ouvre dans un navigateur) : {html_path}")
    print(f"🗄️  Base SQLite (requêtable) : {OUTDIR / 'profiling.db'}")
    print(f"📊 Stats brutes cProfile : {stats_file}")
    if pyspy_result.get("svg"):
        print(f"🔥 Flamegraph py-spy : {pyspy_result['svg']}")
    print("\n💡 Envoie-moi le rapport.html ou le profiling.db pour qu'on analyse ensemble !")


if __name__ == "__main__":
    main()