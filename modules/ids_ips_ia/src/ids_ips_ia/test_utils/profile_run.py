#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct  1 00:14:59 2026

@author: hounsousamuel
"""

"""
profile_run.py — Lance l'IDS/IPS (main/api.py) sous charge, le profile avec py-spy,
et écrit un rapport complet (Markdown) qui désigne le goulot.

Ce que fait le script :
  1. (option --traffic) démarre gen_traffic.py (veth + tcpreplay) et attend qu'il soit prêt ;
  2. démarre api.py (même .env que run.sh), log tout dans <out>/target.log ;
  3. attend la fin du chargement (marqueur "DÉMARRAGE DE LA DÉTECTION TEMPS RÉEL") + --settle s,
     pour NE PAS profiler l'import de TensorFlow / le chargement du modèle ;
  4. attache py-spy (--subprocesses --threads) pendant --duration s ;
  5. arrête proprement l'IDS (SIGINT = comme ton Ctrl-C) et le générateur ;
  6. analyse le profil : par thread, fonctions chaudes, lignes chaudes, bibliothèques,
     étapes du pipeline (inclusif), débit réel mesuré dans le log, verdict.

Usage (root requis, comme run.sh) :
  sudo -E $(which python3) profile_run.py --traffic --duration 90
  sudo -E $(which python3) profile_run.py --traffic --attack-after 40 --duration 120
  # débit fixe (au lieu de topspeed) :
  sudo -E $(which python3) profile_run.py --traffic --traffic-rate pps=20000 --duration 90
  # débit dynamique : t (s après le début du profil) : débit
  sudo -E $(which python3) profile_run.py --traffic --duration 150 \\
        --rate-switch "30:pps=10000,60:pps=50000,90:topspeed"
  sudo -E $(which python3) profile_run.py --analyze-only profile_out_XXXX/profile.speedscope.json

Dépendance : pip install py-spy
Sorties (dans --out-dir) : report.md, profile.speedscope.json (à glisser dans https://speedscope.app
pour le flamegraph interactif), folded.txt (pour flamegraph.pl / inferno), target.log.
"""

import argparse
import json
import linecache
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_TARGET = HERE.parent / "main" / "api.py"
DEFAULT_TRAFFIC = HERE / "gen_traffic.py"
READY_MARKER = "DÉMARRAGE DE LA DÉTECTION TEMPS RÉEL"
TRAFFIC_READY = "Commandes disponibles"

# --------------------------------------------------------------------------------------
# Lecture du flux de sortie d'un process (log + marqueurs + compteurs horodatés)
# --------------------------------------------------------------------------------------
RE_STATS = re.compile(r"\|\s*([\d\s]+?)\s*pkt \(([\d\s]+)/s\)\s*\|\s*perdus : noyau ([\d\s]+?)\s*·\s*app ([\d\s]+?)\s*\(([\d.]+) %\)")


# --------------------------------------------------------------------------------------
# Débit du générateur : validation (miroir léger de gen_traffic.parse_rate — à garder synchro)
# --------------------------------------------------------------------------------------
RATE_FORMATS = "topspeed | pps=N (suffixes k/M) | mbps=X | gbps=X"


def check_rate(spec: str) -> str:
    """Valide une spec de débit et la renvoie normalisée (sans '--'). ValueError sinon."""
    s = str(spec).strip().lower().lstrip("-")
    s = re.sub(r"^(pps|mbps|gbps)\s+(?=\d)", r"\1=", s)
    if s in ("topspeed", "top", "max"):
        return "topspeed"
    m = re.fullmatch(r"(pps|mbps|gbps)[=:](\d+(?:\.\d+)?)([km]?)", s)
    if not m or float(m[2]) <= 0 or (m[3] and m[1] != "pps"):
        raise ValueError(f"débit invalide {spec!r} (formats : {RATE_FORMATS})")
    return s


def parse_rate_switch(text: str):
    """'30:pps=10000,60:topspeed' -> [(30.0, 'pps=10000'), (60.0, 'topspeed')] trié par temps."""
    plan = []
    for item in filter(None, (x.strip() for x in (text or "").split(","))):
        t, sep, spec = item.partition(":")
        if not sep:
            raise ValueError(f"« {item} » : format attendu  <secondes>:<débit>  (ex. 30:pps=10000)")
        try:
            t = float(t)
        except ValueError:
            raise ValueError(f"« {item} » : « {t} » n'est pas un nombre de secondes")
        if t < 0:
            raise ValueError(f"« {item} » : le temps doit être >= 0")
        plan.append((t, check_rate(spec)))
    return sorted(plan, key=lambda x: x[0])


def _num(s: str) -> int:
    return int(re.sub(r"\D", "", s) or 0)


class LineTap(threading.Thread):
    """Vide stdout du process (sinon il bloque), l'écrit dans un fichier, détecte des marqueurs."""

    def __init__(self, proc, logfile: Path, name: str, markers=(), echo=True):
        super().__init__(daemon=True, name=f"tap-{name}")
        self.proc, self.echo, self.tag = proc, echo, name
        self.fh = open(logfile, "w", encoding="utf-8", errors="replace")
        self.events = {m: threading.Event() for m in markers}
        self.recording = False
        self.times = defaultdict(list)       # kind -> [timestamps] pendant la fenêtre de profil
        self.stats = []                      # (t, kept, rate, kernel_drops, app_drops, loss_pct)
        self.pre_stats = []                  # idem, AVANT la fenêtre de profil (référence sans py-spy)

    def run(self):
        for line in self.proc.stdout:
            self.fh.write(line)
            self.fh.flush()
            if self.echo:
                sys.stdout.write(f"[{self.tag}] {line}")
            for m, ev in self.events.items():
                if m in line:
                    ev.set()
            now = time.time()
            m = RE_STATS.search(line)
            if m:
                row = (now, _num(m[1]), _num(m[2]), _num(m[3]), _num(m[4]), float(m[5]))
                (self.stats if self.recording else self.pre_stats).append(row)
            if self.recording:
                if "[SÉQUENCE]" in line and "paquets anormaux" in line:
                    self.times["sequences"].append(now)
                elif "[PAQUET] Anomalie" in line:
                    self.times["pkt_anomalies"].append(now)
                elif "Blocage de" in line:
                    self.times["blocks"].append(now)
        self.fh.close()


def load_env(path: Path) -> dict:
    env = {}
    if not path.is_file():
        return env
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        env[k.strip()] = v
    return env


def stop_group(p, name: str, wait: int = 25):
    """SIGINT au groupe (= Ctrl-C), puis SIGTERM, puis SIGKILL."""
    if p is None or p.poll() is not None:
        return
    for sig, w in ((signal.SIGINT, wait), (signal.SIGTERM, 8), (signal.SIGKILL, 3)):
        try:
            os.killpg(os.getpgid(p.pid), sig)
        except ProcessLookupError:
            return
        try:
            p.wait(timeout=w)
            return
        except subprocess.TimeoutExpired:
            print(f"⚠️  {name} ne répond pas à {sig.name}, escalade...")


# --------------------------------------------------------------------------------------
# CPU RÉEL : vérité terrain lue dans /proc (indépendante de py-spy)
#
# Pourquoi : py-spy dit où le thread PASSE son temps, pas s'il CALCULE. Un thread bloqué dans
# socket.gethostbyaddr() peut apparaître « actif » (surtout avec --idle). Le CPU consommé (utime+stime
# du noyau) ne ment pas : on s'en sert pour valider ET recaler les chiffres de py-spy.
# --------------------------------------------------------------------------------------
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
RE_PNAME = re.compile(r"Process (\d+) Thread (\d+)")


def _key_of(pname: str):
    """'Process 604893 Thread 605002 "Capture"' -> (604893, 605002) ; le tid de py-spy = tid OS (/proc/<pid>/task/<tid>)."""
    m = RE_PNAME.search(pname or "")
    return (int(m[1]), int(m[2])) if m else None


def _read_stat(path: str):
    """Parse un /proc/.../stat -> {comm, state, ppid, ticks} ; None si le thread/process a disparu.
    `comm` peut contenir espaces et parenthèses : on coupe autour de la DERNIÈRE ')'."""
    try:
        raw = Path(path).read_text(errors="replace")
    except OSError:
        return None
    lp, rp = raw.find("("), raw.rfind(")")
    if lp < 0 or rp < 0:
        return None
    f = raw[rp + 2:].split()
    try:        # f[0]=state, f[1]=ppid, f[11]=utime, f[12]=stime (champs 3, 4, 14, 15 de proc(5))
        return {"comm": raw[lp + 1:rp], "state": f[0], "ppid": int(f[1]), "ticks": int(f[11]) + int(f[12])}
    except (IndexError, ValueError):
        return None


def process_tree(root_pid: int) -> list:
    """root + tous ses descendants (les workers 'spawn' de l'IDS comptent aussi)."""
    children = defaultdict(list)
    try:
        names = os.listdir("/proc")
    except OSError:
        return [root_pid]
    for dname in names:
        if dname.isdigit():
            st = _read_stat(f"/proc/{dname}/stat")
            if st:
                children[st["ppid"]].append(int(dname))
    out, todo = [], [root_pid]
    while todo:
        pid = todo.pop()
        out.append(pid)
        todo.extend(children.get(pid, ()))
    return out


def cpu_snapshot(root_pid: int) -> dict:
    """Instantané CPU du process `root_pid` et de ses descendants : par process (total, threads morts inclus) et par thread."""
    snap = {"t": time.monotonic(), "procs": {}, "threads": {}}
    for pid in process_tree(root_pid):
        st = _read_stat(f"/proc/{pid}/stat")
        if not st:
            continue
        snap["procs"][pid] = st["ticks"]
        try:
            tids = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue
        for tid in tids:
            ts = _read_stat(f"/proc/{pid}/task/{tid}/stat")
            if ts:
                snap["threads"][(pid, int(tid))] = (ts["comm"], ts["ticks"])
    return snap


def cpu_delta(a: dict, b: dict) -> dict:
    """CPU consommé entre deux instantanés, en SECONDES. Absent de `a` (créé pendant la fenêtre) -> base 0."""
    thr = [{"pid": k[0], "tid": k[1], "comm": comm, "cpu": max(ticks - a["threads"].get(k, (None, 0))[1], 0) / CLK_TCK}
           for k, (comm, ticks) in b["threads"].items()]
    procs = {pid: max(t - a["procs"].get(pid, 0), 0) / CLK_TCK for pid, t in b["procs"].items()}
    total = sum(procs.values())
    alive = sum(t["cpu"] for t in thr)
    return {"wall": max(b["t"] - a["t"], 1e-9), "threads": thr, "procs": {str(k): v for k, v in procs.items()},
            "total_cpu": total, "exited_threads_cpu": max(total - alive, 0.0),
            "lost_procs": sorted(set(a["procs"]) - set(b["procs"]))}


def system_cpu_times():
    """(ticks occupés, ticks totaux) de la machine entière (ligne 'cpu' de /proc/stat), ou None."""
    try:
        v = [int(x) for x in Path("/proc/stat").read_text().split("\n", 1)[0].split()[1:9]]
        idle = v[3] + v[4]            # idle + iowait
        return sum(v) - idle, sum(v)
    except Exception:
        return None


def build_cpu_meta(snap0, snap1, gen0, gen1, sys0, sys1, spy_cpu) -> dict:
    d = cpu_delta(snap0, snap1)
    d["ncpu"] = os.cpu_count() or 1
    d["generator_cpu"] = cpu_delta(gen0, gen1)["total_cpu"] if gen0 and gen1 else None
    d["spy_cpu"] = spy_cpu
    d["system_busy_pct"] = (100.0 * (sys1[0] - sys0[0]) / max(sys1[1] - sys0[1], 1)) if sys0 and sys1 else None
    return d


# --------------------------------------------------------------------------------------
# Analyse du profil (format speedscope de py-spy : frames racine -> feuille)
# --------------------------------------------------------------------------------------
# (label, sous-chaînes de chemin de fichier) — la FEUILLE de chaque pile décide (où le CPU brûle)
LEAF_CATEGORIES = [
    ("TensorFlow / Keras", ("tensorflow", "keras")),
    ("scikit-learn", ("sklearn",)),
    ("numpy / scipy", ("numpy", "scipy")),
    ("dpkt (parsing paquets)", ("dpkt",)),
    ("scapy", ("scapy",)),
    ("logs / print", ("logging", "logger", "/logs/")),
    ("réaction nft / subprocess", ("subprocess", "nftables", "reaction_module")),
    ("extraction de features", ("features_extractor",)),
    ("scoring / corrélation", ("anomaly_scorer",)),
    ("capture", ("/capture.py", "af_capture")),
    ("json / pickle / dill / joblib", ("json", "pickle", "dill", "joblib")),
    ("asyncio / threads / queue", ("asyncio", "threading", "queue", "selectors", "concurrent")),
]

# Étapes du pipeline, en INCLUSIF : (label, noms de fonctions, sous-chaîne de fichier ou None)
_PKT = {"predict_packet", "apredict_packet", "predict_packet_batch", "apredict_packet_batch"}
_SEQ = {"predict_sequence", "apredict_sequence", "predict_sequence_batch", "apredict_sequence_batch"}
_IF = ({"decision_function"}, "_iforest")
_LOF = ({"decision_function", "score_samples", "kneighbors"}, "_lof")
STAGE_PKT = "predict_packet (AE + IF + LOF)"
STAGE_SEQ = "predict_sequence (CNN + AE + IF + LOF)"
# (label, noms de fonctions, sous-chaîne de fichier ou None, fonctions "parent" exigées dans la pile ou None)
# Les lignes "dont" exigent leur parent : avant, "dont IsolationForest" mélangeait paquet ET séquence
# (et pouvait dépasser son parent).
PIPELINE_STAGES = [
    ("detect() — boucle consommateur (total)", {"detect"}, "detection_module", None),
    ("extract_pack_features (par paquet)", {"extract_pack_features"}, None, None),
    (STAGE_PKT, _PKT, None, None),
    ("  dont IsolationForest (paquet)", _IF[0], _IF[1], _PKT),
    ("  dont LOF (paquet)", _LOF[0], _LOF[1], _PKT),
    ("extract_seq_features", {"extract_seq_features"}, None, None),
    (STAGE_SEQ, _SEQ, None, None),
    ("  dont IsolationForest (séquence)", _IF[0], _IF[1], _SEQ),
    ("  dont LOF (séquence)", _LOF[0], _LOF[1], _SEQ),
    ("  dont Keras predict()", {"predict", "predict_function", "predict_step"}, "keras", None),
    ("AnomalyScorer.detect_pkt (voie lente)", {"detect_pkt"}, None, None),
    ("log_anomaly / _add_alert", {"log_anomaly", "_add_alert"}, None, None),
    ("persistance joblib/pickle (dump)", {"dump"}, None, None),
    ("logger.print", {"print"}, "logger", None),
    ("blocage nft (_run_command / block)", {"_run_command", "block"}, None, None),
    ("graphes (add_data*)", {"add_data1", "add_data2", "add_data3"}, None, None),
]


# Frames qui signifient "le thread DORT / attend" (py-spy --native les compte comme actives !)
IDLE_NAMES = ("epoll_wait", "epoll_pwait", "futex_abstimed_wait", "futex_wait", "clock_nanosleep", "nanosleep",
              "wait4", "sem_wait", "pthread_cond_timedwait", "pthread_cond_wait", "__poll", "ppoll",
              "uv__io_poll", "PyThread_acquire_lock_timed", "_do_waitpid", "select (")


# Attentes côté Python (sans --native, py-spy ne voit que la frame Python qui appelle le C bloquant)
PY_IDLE = {("wait", "threading.py"), ("get", "queue.py"), ("_worker", "thread.py"), ("select", "selectors.py"),
           ("run", "runners.py"), ("_run_once", "base_events.py"), ("_run_once", "nest_asyncio.py"),
           ("acquire", "threading.py"), ("join", "threading.py"), ("_wait_for_tstate_lock", "threading.py"),
           ("sleep", "tasks.py")}
# Ligne source de la frame feuille qui contient un appel dormant/attendant (recv volontairement exclu :
# sous charge réseau saturée, recv_into = vrai travail de capture)
BLOCK_LINE = re.compile(r"(time\.sleep|asyncio\.sleep|\.wait|\.join|\.poll|\.get\(\s*(block|timeout)"
                        r"|gethostbyaddr|gethostbyname|getaddrinfo|getnameinfo|\.communicate|\.acquire)\s*\(?")


def read_seq_stride() -> int:
    """Stride configuré (ANOMALY_CONFIG.seq_stride), lu dans le JSON de config SANS importer le package
    (son import exige des variables d'environnement et écrit des logs). 1 si introuvable."""
    path = os.environ.get("IDS_CONFIG_PATH") or str(Path(__file__).resolve().parent.parent / "config" / "config_json.json")
    try:
        try:
            import json5 as _json
        except ImportError:
            _json = json
        with open(path, encoding="utf-8") as fh:
            return max(1, int(_json.load(fh).get("ANOMALY_CONFIG", {}).get("seq_stride", 1)))
    except Exception:
        return 1


SEQ_STRIDE = read_seq_stride()


def short(fr: dict) -> str:
    return f"{fr['name']} ({os.path.basename(fr.get('file') or '?')})"


def analyze(json_path: Path, project_marker: str, top: int, tap: "LineTap | None", wall: float, meta: dict | None = None):
    """Analyse un profil speedscope de py-spy.

    meta (run_meta.json) = vérité terrain mesurée pendant le run : CPU réel par thread (/proc), options py-spy,
    log py-spy, etc. Sans meta (vieux profil) : mode dégradé, uniquement les échantillons py-spy.
    """
    meta = meta or {}
    cpu = meta.get("cpu")
    opts = meta.get("opts") or {}
    d = json.loads(Path(json_path).read_text())
    frames = d["shared"]["frames"]
    profiles = d["profiles"]
    if not wall:   # --analyze-only : la durée de la fenêtre est dans le profil lui-même (unité = secondes)
        try:   # durée la plus fréquente parmi les threads durables (un thread mal attribué par py-spy peut doubler)
            durs = [round(p["endValue"] - p["startValue"]) for p in profiles if p["endValue"] - p["startValue"] > 1]
            wall = Counter(durs).most_common(1)[0][0] if durs else 0
        except Exception:
            wall = 0
    fkey = [(f["name"], f.get("file") or "?") for f in frames]
    fpath = [(f.get("file") or "").lower() for f in frames]
    # frames synthétiques ajoutées par py-spy (--threads/--subprocesses) : "process N", "thread (N)" -> sans fichier
    synth = [not f.get("file") for f in frames]
    generic = {"asyncio / threads / queue"}

    # Tout est accumulé PAR THREAD : à la fin chaque thread est recalé sur son CPU réel (si disponible).
    acc = defaultdict(lambda: {k: Counter() for k in ("self", "incl", "proj", "cat", "stage", "line", "stacks", "folded")})
    thread_tot, idle_tot = {}, {}
    thread_leaf = defaultdict(Counter)
    idle_all = src_missing = 0.0
    n_active = 0

    for p in profiles:
        w_list = p.get("weights") or [1.0] * len(p["samples"])
        pname = p["name"]
        for stack, w in zip(p["samples"], w_list):
            stack = [i for i in stack if not synth[i]]
            if not stack:
                continue
            tail = [frames[i]["name"] + (" (" if "selectors" in fpath[i] else "") for i in stack[-8:]]
            lf = frames[stack[-1]]
            lbase = os.path.basename(lf.get("file") or "")
            leaf_idle = (lf["name"], lbase) in PY_IDLE
            if not leaf_idle and lf.get("file") and lf.get("line"):
                src_line = linecache.getline(lf["file"], lf["line"])
                if not src_line:
                    src_missing += w      # source illisible ici -> les time.sleep/wait ne peuvent pas être repérés
                leaf_idle = bool(src_line and BLOCK_LINE.search(src_line))
            if leaf_idle or any(k in n for n in tail for k in IDLE_NAMES):
                idle_tot[pname] = idle_tot.get(pname, 0.0) + w
                idle_all += w
                continue
            A = acc[pname]
            n_active += 1
            thread_tot[pname] = thread_tot.get(pname, 0.0) + w
            leaf = stack[-1]
            thread_leaf[pname][fkey[leaf]] += w
            A["self"][fkey[leaf]] += w
            A["line"][leaf] += w
            for k in {fkey[i] for i in stack}:
                A["incl"][k] += w
            for k in {fkey[i] for i in stack if project_marker in fpath[i]}:
                A["proj"][k] += w
            # catégorie de feuille : on remonte jusqu'à la première frame reconnue
            cat = None
            for i in reversed(stack):      # on remonte de la feuille jusqu'à une bibliothèque "spécifique"
                cat = next((lab for lab, subs in LEAF_CATEGORIES
                            if lab not in generic and any(x in fpath[i] for x in subs)), None)
                if cat:
                    break
            if cat is None:                # sinon : asyncio/threads seulement si la feuille elle-même y est
                cat = next((lab for lab, subs in LEAF_CATEGORIES
                            if lab in generic and any(x in fpath[stack[-1]] for x in subs)), "Python pur (ton code / autre)")
            A["cat"][cat] += w
            # étapes inclusives
            for label, names, fsub, parents in PIPELINE_STAGES:
                if any(frames[i]["name"] in names and (fsub is None or fsub in fpath[i]) for i in stack) \
                        and (parents is None or any(frames[i]["name"] in parents for i in stack)):
                    A["stage"][label] += w
            A["stacks"][tuple(stack[-7:])] += w
            A["folded"][";".join([pname.replace(";", ",").replace(" ", "_")] +
                                 [frames[i]["name"].replace(";", ",") for i in stack])] += w

    act_raw = sum(thread_tot.values())            # « temps actif » brut selon py-spy + heuristiques
    if act_raw <= 0:
        return "# ❌ Profil vide (aucun échantillon actif). Vérifie que py-spy a bien pu s'attacher (root ?).\n", Counter()

    # ------------------------------------------------------------------ recalage sur le CPU réel
    recal = bool(cpu) and not opts.get("gil")     # --gil = « qui tient le GIL » : pas comparable au CPU d'un thread
    cpu_thread = {(t["pid"], t["tid"]): t for t in (cpu or {}).get("threads", [])}
    py_keys = {_key_of(p["name"]) for p in profiles} - {None}
    scale, matched = {}, set()
    for pname, act in thread_tot.items():
        key = _key_of(pname)
        t = cpu_thread.get(key)
        if recal:
            if t is not None:
                matched.add(key)
            scale[pname] = (t["cpu"] / act) if (t is not None and act > 0) else 0.0
        else:
            scale[pname] = 1.0

    def agg(field):
        out = Counter()
        for pname, A in acc.items():
            s = scale.get(pname, 0.0)
            if s > 0:
                for k, v in A[field].items():
                    out[k] += v * s
        return out

    self_fn, incl_fn, proj_incl = agg("self"), agg("incl"), agg("proj")
    leaf_cat, stage_incl, self_line, stacks, folded = agg("cat"), agg("stage"), agg("line"), agg("stacks"), agg("folded")

    py_cpu = sum(scale[p] * thread_tot[p] for p in thread_tot)           # CPU attribué aux threads Python échantillonnés
    native = [t for k, t in cpu_thread.items() if k not in py_keys and t["cpu"] > 0.01]
    unsampled = [t for k, t in cpu_thread.items() if k in py_keys and k not in matched and t["cpu"] > 0.01]
    native_cpu = sum(t["cpu"] for t in native)
    unsampled_cpu = sum(t["cpu"] for t in unsampled)
    exited_cpu = (cpu or {}).get("exited_threads_cpu", 0.0) if recal else 0.0
    if recal:
        leaf_cat = Counter(leaf_cat)
        if native_cpu > 0:
            leaf_cat["⟨threads natifs hors Python : BLAS / TF / OpenMP…⟩"] += native_cpu
        if unsampled_cpu > 0:
            leaf_cat["⟨threads Python sans échantillon actif⟩"] += unsampled_cpu
        if exited_cpu > 0:
            leaf_cat["⟨threads terminés pendant la fenêtre⟩"] += exited_cpu
    denom = (cpu["total_cpu"] if recal and cpu.get("total_cpu", 0) > 0 else py_cpu) or 1.0
    pct = lambda x: f"{100 * x / denom:5.1f} %"
    unit = "CPU réel" if recal else "échantillons actifs"

    # ------------------------------------------------------------------ fiabilité de la mesure
    Q, warn = [], 0

    def chk(ok, good, bad):
        nonlocal warn
        if ok:
            Q.append(f"- ✅ {good}")
        else:
            warn += 1
            Q.append(f"- ⚠️ {bad}")

    if not cpu:
        chk(False, "", "**CPU réel indisponible** (profil analysé sans `run_meta.json`) : les chiffres reposent uniquement sur les "
                       "échantillons py-spy et des heuristiques de noms pour repérer les attentes. À prendre avec précaution.")
    else:
        if opts.get("gil"):
            chk(False, "", "`--gil` : vue « qui tient le GIL », NON recalée sur le CPU réel (les tables sont en échantillons).")
        if opts.get("idle"):
            chk(False, "", "`--idle` utilisé : py-spy n'élimine plus lui-même les threads en attente, la classification repose sur des "
                           "heuristiques de noms. Les tables ci-dessous sont recalées sur le CPU réel, mais **préfère lancer SANS `--idle`**.")
        else:
            chk(True, "py-spy filtre les threads en attente d'après l'état OS (pas de `--idle`).", "")
        ratio = act_raw / py_cpu if py_cpu > 0 else float("inf")
        chk(0.8 <= ratio <= 1.25,
            f"« actif » py-spy = {act_raw:.0f} s pour {py_cpu:.0f} s de CPU réel sur les mêmes threads (×{ratio:.2f}) : cohérent.",
            f"« actif » py-spy = {act_raw:.0f} s pour {py_cpu:.0f} s de CPU réel (×{ratio:.2f}). "
            + ("py-spy compte des **attentes comme du calcul** (corrigé par le recalage)." if ratio > 1.25 else
               "py-spy a manqué des échantillons (fréquence trop haute ?) ou du CPU est consommé hors de ses frames."))
        sus = [(pn, thread_tot[pn], cpu_thread[_key_of(pn)]["cpu"]) for pn in thread_tot
               if _key_of(pn) in cpu_thread and thread_tot[pn] >= 2 and thread_tot[pn] > 1.5 * cpu_thread[_key_of(pn)]["cpu"] + 1]
        if sus:
            sus.sort(key=lambda x: x[1] - x[2], reverse=True)
            ex = ", ".join(f"`{pn.split('Thread')[-1].strip()}` ({a:.0f} s « actif » vs {c:.1f} s de CPU)" for pn, a, c in sus[:4])
            chk(False, "", f"**{len(sus)} thread(s) « actifs » pour py-spy mais quasi sans CPU = en attente** (réseau/DNS/verrou…) : {ex}"
                           + (" …" if len(sus) > 4 else "") + ". Ils sont neutralisés dans les tables.")
        else:
            chk(True, "aucun thread « actif » sans CPU réel correspondant.", "")
        n_unm = sum(1 for k in py_keys if k not in cpu_thread)
        if n_unm:
            chk(False, "", f"{n_unm} thread(s) vus par py-spy ont disparu de /proc avant la fin de la fenêtre (leur CPU est compté dans "
                           f"« threads terminés »).")
        dw = abs(cpu["wall"] - wall) / wall if wall else 0
        chk(dw < 0.05, f"fenêtre CPU ({cpu['wall']:.0f} s) alignée sur celle de py-spy ({wall:.0f} s).",
            f"fenêtre CPU ({cpu['wall']:.0f} s) ≠ fenêtre py-spy ({wall:.0f} s) : l'attache/le détachement de py-spy décale les deux mesures.")
        if cpu.get("lost_procs"):
            chk(False, "", f"process terminés pendant la fenêtre (CPU non comptabilisé) : {cpu['lost_procs']}.")
        if opts.get("target_alive") is False:
            chk(False, "", "🚨 **la cible s'est arrêtée pendant la fenêtre de profil** : le rapport est partiel.")
        sysb, ncpu = cpu.get("system_busy_pct"), cpu.get("ncpu") or 1
        if sysb is not None:
            gen = cpu.get("generator_cpu")
            share = (f" (IDS {cpu['total_cpu'] / cpu['wall']:.1f} cœur"
                     + (f", générateur {gen / cpu['wall']:.1f}" if gen is not None else "")
                     + (f", py-spy {cpu['spy_cpu'] / cpu['wall']:.1f}" if cpu.get("spy_cpu") is not None else "") + f" · {ncpu} cœurs au total)")
            chk(sysb < 85, f"machine à {sysb:.0f} % de CPU{share} : pas de famine de CPU.",
                f"**machine à {sysb:.0f} % de CPU**{share} : IDS, générateur de trafic et profileur se disputent les cœurs, "
                f"les débits mesurés ne sont pas représentatifs d'une machine dédiée.")
    if opts.get("native") or opts.get("nonblocking"):
        chk(False, "", "`--native` / `--nonblocking` : mode intrusif ou inexact → les **débits absolus sont faussés**, fie-toi aux proportions.")
    slog = meta.get("spy_log") or ""
    if "behind in sampling" in slog:
        chk(False, "", "py-spy signale du **retard d'échantillonnage** (« behind in sampling ») : baisse `--rate`, ou profile moins de threads à la fois.")
    mm = re.search(r"Errors?:\s*(\d+)", slog)
    if mm and int(mm[1]) > 0:
        ms = re.search(r"Samples?:\s*(\d+)", slog)
        chk(False, "", f"py-spy a eu {mm[1]} erreur(s) de lecture" + (f" sur {ms[1]} échantillons" if ms else "") + " : stacks incomplètes ignorées.")
    chk(not wall or wall >= 30, f"fenêtre de {wall:.0f} s.", f"fenêtre de seulement {wall:.0f} s : statistiquement fragile (vise ≥ 60 s).")
    chk(n_active >= 500, f"{n_active:,} échantillons actifs.".replace(",", " "), f"seulement {n_active} échantillons actifs : trop peu pour des pourcentages fins.")
    if tap is not None and tap.pre_stats and tap.stats:
        a_, b_ = [s[2] for s in tap.pre_stats[-5:]], [s[2] for s in tap.stats[:5]]
        ma, mb = sum(a_) / len(a_), sum(b_) / len(b_)
        if ma > 0:
            chk(mb >= 0.8 * ma, f"débit capturé stable à l'attache de py-spy ({ma:,.0f} → {mb:,.0f} pkt/s).".replace(",", " "),
                f"le débit capturé passe de {ma:,.0f} à {mb:,.0f} pkt/s dès que py-spy s'attache : **le profileur perturbe la cible** "
                f"(ou le trafic a changé).".replace(",", " "))
    if src_missing > 0.05 * (act_raw + idle_all):
        chk(False, "", "fichiers source introuvables pour une partie des frames : les `time.sleep`/`wait` ne peuvent pas être repérés par "
                       "leur ligne. Relance l'analyse sur la machine qui a profilé.")
    conf = "🟢 bonne" if warn == 0 else ("🟡 moyenne" if warn <= 2 else "🔴 faible")

    L = []
    add = L.append
    add(f"# Rapport de profilage IDS/IPS — {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    if recal:
        add(f"- **Base des chiffres : CPU réel** (noyau, `/proc`) : **{cpu['total_cpu']:.1f} s** de CPU pour **{wall:.0f} s** de fenêtre "
            f"= **{cpu['total_cpu'] / cpu['wall']:.2f} cœur(s)** en moyenne. "
            f"py-spy sert à **répartir** ce CPU par fonction, thread et étape. Pourcentages = part du CPU réel total.")
    else:
        add(f"- Temps **actif** (hors attentes) : **{act_raw:.1f} s** cumulés sur {len(profiles)} thread(s)/process"
            + (f" pour **{wall:.0f} s** de fenêtre" if wall else "")
            + f" · attentes ignorées : {idle_all:.1f} s. Pourcentages relatifs au temps actif total.")
    add(f"- **Confiance de la mesure : {conf}** ({warn} avertissement(s), voir ci-dessous).\n")

    add("## 🧪 Fiabilité de la mesure\n")
    L.extend(Q)
    add("")

    # --- verdict ---
    add("## 🎯 Verdict automatique\n")
    cats = leaf_cat.most_common()
    cats_named = [(k, v) for k, v in cats if k not in generic] or cats   # le fourre-tout n'est pas un "coupable"
    stage_nodetect = [(k, v) for k, v in stage_incl.most_common() if not k.startswith("detect()") and not k.startswith("  ")]
    add(f"- Bibliothèque qui consomme le plus ({unit}, feuille) : **{cats_named[0][0]}** ({pct(cats_named[0][1]).strip()})")
    if stage_nodetect:
        add(f"- Étape du pipeline la plus coûteuse : **{stage_nodetect[0][0]}** ({pct(stage_nodetect[0][1]).strip()})")
    if wall:
        infer = stage_incl.get(STAGE_PKT, 0) + stage_incl.get(STAGE_SEQ, 0)
        busy = infer / wall
        add(f"- Inférence (paquet + séquence) : **{infer:.0f} s ({unit}) sur {wall:.0f} s** de fenêtre (≈ {busy:.2f} cœur)"
            + (" → 🚨 **consommateur probablement SATURÉ** : le débit max est celui de l'inférence, la capture/la file débordent."
               if busy >= 0.8 else " → le consommateur n'est pas saturé."))
    hints = []
    s = lambda label: stage_incl.get(label, 0) / denom
    if s(STAGE_SEQ) > 0.25:
        hints.append("`predict_sequence` pèse lourd → augmenter `seq_stride` (config) : une séquence tous les N paquets.")
    if s(STAGE_PKT) > 0.15:
        hints.append("`predict_packet` pèse lourd → vérifier la taille des lots (`detect_batch_size`) ; "
                     "sinon réduire `n_estimators` / `n_neighbors`.")
    if leaf_cat.get("TensorFlow / Keras", 0) / denom > 0.30:
        hints.append("Keras domine → `model(x, training=False)` ou `tf.function` à signature fixe au lieu de `model.predict` par petit lot.")
    if leaf_cat.get("scikit-learn", 0) / denom > 0.20:
        hints.append("sklearn domine (IF/LOF sur 1 échantillon) → batcher, réduire `n_estimators` / `n_neighbors`, éviter le lock.")
    if s("persistance joblib/pickle (dump)") > 0.10:
        hints.append("🚨 Une sauvegarde joblib/pickle tourne DANS la boucle de détection : écrire par lots, "
                     "en append (1 fichier par paquet d'alertes) et/ou dans un thread dédié — jamais re-dumper toute la liste.")
    if s("logger.print") > 0.08 or leaf_cat.get("logs / print", 0) / denom > 0.08:
        hints.append("Les logs coûtent cher → niveau WARNING en production / pendant les benchs, ou logger via une queue asynchrone.")
    if s("blocage nft (_run_command / block)") > 0.05:
        hints.append("Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.")
    if s("graphes (add_data*)") > 0.05:
        hints.append("Les graphes Bokeh coûtent → `enable_graph=False` pour mesurer le pipeline seul.")
    if recal and native_cpu / denom > 0.15:
        hints.append(f"**{100 * native_cpu / denom:.0f} % du CPU est consommé par des threads NATIFS invisibles pour py-spy** "
                     "(BLAS/OpenMP/TensorFlow) : voir la table des threads natifs ; `perf top -p <pid>` les détaille.")
    for h in hints or ["Pas de règle évidente déclenchée : regarde les tables ci-dessous et le flamegraph."]:
        add(f"- 💡 {h}")
    add("\n_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_\n")

    # --- débit réel ---
    if tap is not None and wall:
        add("## 📈 Débit mesuré pendant la fenêtre\n")
        seq = len(tap.times["sequences"])
        est = seq * SEQ_STRIDE / wall
        add(f"- Séquences évaluées : **{seq}** → {seq / wall:.2f}/s "
            f"(≈ {est:.0f} paquets/s, **estimation** : séquences × stride={SEQ_STRIDE} ; elle ignore les paquets écartés par le skipper)")
        add(f"- Anomalies paquet : {len(tap.times['pkt_anomalies'])} · blocages nft : {len(tap.times['blocks'])}")
        if tap.stats:
            a, b = tap.stats[0], tap.stats[-1]
            mean_kept = sum(x[2] for x in tap.stats) / len(tap.stats)
            add(f"- Capture au début : {a[2]:,} pkt/s gardés, pertes {a[5]:.1f} % (noyau {a[3]:,} · app {a[4]:,})".replace(",", " "))
            add(f"- Capture à la fin : {b[2]:,} pkt/s gardés, pertes {b[5]:.1f} % (noyau {b[3]:,} · app {b[4]:,})".replace(",", " "))
            add(f"- Capture, moyenne des relevés : {mean_kept:,.0f} pkt/s gardés".replace(",", " "))
            if est and mean_kept > 2 * est:
                add(f"- ⚠️ La capture garde ~{mean_kept:,.0f} pkt/s mais seulement ~{est:,.0f} pkt/s arrivent aux séquences : "
                    f"le consommateur ne suit pas (ou le skipper écarte beaucoup de paquets). Compare avec le compteur `pkt_proccessed`.".replace(",", " "))
        add("")

    # --- étapes ---
    add(f"## 🧱 Étapes du pipeline (inclusif, {unit})\n")
    add(f"| Étape | % {'du CPU réel' if recal else 'temps actif'} | secondes |\n|---|---:|---:|")
    for label, *_ in PIPELINE_STAGES:
        v = stage_incl.get(label, 0)
        if v:
            add(f"| {label} | {pct(v)} | {v:.1f} |")
    add("")

    # --- catégories ---
    add("## 🔥 Où le CPU brûle (bibliothèque de la feuille)\n")
    add("| Bibliothèque | % | secondes |\n|---|---:|---:|")
    for k, v in cats:
        add(f"| {k} | {pct(v)} | {v:.1f} |")
    add("")

    # --- threads ---
    add("## 🧵 Par thread / process\n")
    if recal:
        add("| Thread | CPU réel (s) | % d'un cœur | py-spy « actif » (s) | statut | fonction la plus chaude |\n|---|---:|---:|---:|---|---|")
        rows = sorted(thread_tot.items(), key=lambda kv: -(cpu_thread.get(_key_of(kv[0]), {"cpu": 0})["cpu"]))
        for pname, act in rows[:top]:
            c = cpu_thread.get(_key_of(pname), {"cpu": 0.0})["cpu"]
            (fn, fl), _ = thread_leaf[pname].most_common(1)[0]
            status = "⚠️ attente comptée active" if (act >= 2 and act > 1.5 * c + 1) else "✅"
            add(f"| {pname} | {c:.1f} | {100 * c / cpu['wall']:.0f} % | {act:.1f} | {status} | {fn} ({os.path.basename(fl)}) |")
        add("")
        if native:
            add("**Threads natifs (non Python — invisibles pour py-spy sans `--native`)**\n")
            add("| pid / tid | nom OS | CPU réel (s) | % d'un cœur |\n|---|---|---:|---:|")
            for t in sorted(native, key=lambda x: -x["cpu"])[:10]:
                add(f"| {t['pid']} / {t['tid']} | {t['comm']} | {t['cpu']:.1f} | {100 * t['cpu'] / cpu['wall']:.0f} % |")
            add("")
        if len(cpu.get("procs", {})) > 1:
            add("**Par process**\n")
            add("| pid | CPU réel (s) | % d'un cœur |\n|---|---:|---:|")
            for pid, v in sorted(cpu["procs"].items(), key=lambda kv: -kv[1])[:8]:
                add(f"| {pid} | {v:.1f} | {100 * v / cpu['wall']:.0f} % |")
            add("")
    else:
        add("| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |\n|---|---:|---:|---:|---|")
        for pname, t in sorted(thread_tot.items(), key=lambda kv: -kv[1])[:top]:
            (fn, fl), _ = thread_leaf[pname].most_common(1)[0]
            add(f"| {pname} | {t:.1f} | {pct(t)} | {idle_tot.get(pname, 0.0):.1f} | {fn} ({os.path.basename(fl)}) |")
        add("")

    # --- fonctions ---
    add(f"## ⏱️ Top {top} fonctions — temps propre (self, {unit})\n")
    add("| Fonction | % | s |\n|---|---:|---:|")
    for (fn, fl), v in self_fn.most_common(top):
        add(f"| `{fn}` ({os.path.basename(fl)}) | {pct(v)} | {v:.1f} |")
    add("")
    add(f"## ⏱️ Top {top} fonctions — temps inclusif ({unit})\n")
    add("| Fonction | % | s |\n|---|---:|---:|")
    for (fn, fl), v in incl_fn.most_common(top):
        add(f"| `{fn}` ({os.path.basename(fl)}) | {pct(v)} | {v:.1f} |")
    add("")
    if proj_incl:
        add(f"## 🧩 Fonctions de TON code (`{project_marker}`) — inclusif ({unit})\n")
        add("| Fonction | % | s |\n|---|---:|---:|")
        for (fn, fl), v in proj_incl.most_common(top):
            add(f"| `{fn}` ({os.path.basename(fl)}) | {pct(v)} | {v:.1f} |")
        add("")

    add(f"## 📍 Top {top} lignes chaudes ({unit})\n")
    add("| Ligne | % |\n|---|---:|")
    for i, v in self_line.most_common(top):
        add(f"| `{frames[i]['name']}` — {os.path.basename(frames[i].get('file') or '?')}:{frames[i].get('line')} | {pct(v)} |")
    add("")

    add("## 🥞 Piles les plus fréquentes (feuille ← appelants)\n")
    for stk, v in stacks.most_common(min(top, 10)):
        chain = " ← ".join(short(frames[i]) for i in reversed(stk))
        add(f"- **{pct(v).strip()}** {chain}")
    add("")
    return "\n".join(L), folded


def phase_table(timeline, ttap, t_start: float, t_end: float) -> str:
    """Une ligne par phase de trafic (changement de pcap ou de débit) avec le débit mesuré par l'IDS.

    timeline : [(t_relatif_s, "normal @ pps=10000"), ...] trié ; ttap.stats : (t, kept, rate, kdrop, adrop, loss%)
    """
    total = max(t_end - t_start, 0.0)
    bounds = [t for t, _ in timeline] + [total]
    L = ["", "## 🎚️ Phases de trafic (débit mesuré par l'IDS)\n",
         "| Début | Fin | Trafic injecté | Relevés | pkt/s moyen | pkt/s max | Perte cumulée (fin de phase) |",
         "|---|---|---|---|---|---|---|"]
    for i, (t0, label) in enumerate(timeline):
        t1 = min(bounds[i + 1], total)
        rows = [s for s in ttap.stats if t0 <= s[0] - t_start < t1]
        if rows:
            rates = [s[2] for s in rows]
            L.append(f"| {t0:.0f}s | {t1:.0f}s | `{label}` | {len(rows)} | {sum(rates) / len(rates):,.0f} | "
                     f"{max(rates):,.0f} | {rows[-1][5]:.2f} % |".replace(",", " "))
        else:
            L.append(f"| {t0:.0f}s | {t1:.0f}s | `{label}` | 0 | – | – | – |")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default=str(DEFAULT_TARGET), help="script lancé (défaut : ../main/api.py)")
    ap.add_argument("--python", default=sys.executable, help="interpréteur pour lancer la cible")
    ap.add_argument("--env-file", default=".env", help="fichier .env (comme run.sh)")
    ap.add_argument("--duration", type=int, default=60, help="durée du profil en secondes")
    ap.add_argument("--rate", type=int, default=100, help="fréquence d'échantillonnage py-spy (Hz)")
    ap.add_argument("--settle", type=int, default=5, help="secondes d'attente après le démarrage de la détection")
    ap.add_argument("--ready-timeout", type=int, default=180, help="attente max du marqueur de démarrage")
    ap.add_argument("--ready-marker", default=READY_MARKER)
    ap.add_argument("--native", action="store_true",
                    help="py-spy --native (frames C/C++) ; TRÈS intrusif : à combiner avec --nonblocking, sur courte durée")
    ap.add_argument("--gil", action="store_true", help="py-spy --gil (seulement les threads qui tiennent le GIL)")
    ap.add_argument("--idle", action="store_true",
                    help="py-spy --idle : inclut les threads en attente. DÉCONSEILLÉ : py-spy ne filtre plus les attentes "
                         "(DNS, verrous…) et la classification retombe sur des heuristiques. Le rapport se recale sur le CPU réel, "
                         "mais sans --idle les chiffres sont plus propres")
    ap.add_argument("--nonblocking", action="store_true", help="py-spy --nonblocking (moins intrusif, moins exact)")
    ap.add_argument("--traffic", action="store_true", help="démarre gen_traffic.py avant la cible")
    ap.add_argument("--traffic-script", default=str(DEFAULT_TRAFFIC))
    ap.add_argument("--attack-after", type=int, default=0, help="envoie 'attack' au générateur N s après le début du profil")
    ap.add_argument("--traffic-rate", default="topspeed", metavar="SPEC",
                    help="débit initial du générateur : " + RATE_FORMATS + " (défaut : topspeed). "
                         "Ne pas confondre avec --rate = fréquence d'échantillonnage py-spy")
    ap.add_argument("--rate-switch", default="", metavar="T:SPEC,...",
                    help="change le débit du générateur EN COURS de profil, ex. \"30:pps=10000,60:topspeed\" "
                         "(T = secondes après le début du profil). Sans cette option : débit fixe = --traffic-rate")
    ap.add_argument("--project-marker", default="ids_ips_ia", help="chemin identifiant TON code dans les piles")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--quiet", action="store_true", help="n'affiche pas les logs de la cible/du générateur")
    ap.add_argument("--analyze-only", metavar="SPEEDSCOPE_JSON", help="ne lance rien : analyse un profil existant")
    a = ap.parse_args()
    try:
        initial_rate = check_rate(a.traffic_rate)
        rate_plan = parse_rate_switch(a.rate_switch)
    except ValueError as e:
        ap.error(str(e))
    if rate_plan and not a.traffic:
        ap.error("--rate-switch nécessite --traffic")
    late = [f"{t:g}s" for t, _ in rate_plan if t >= a.duration]
    if late:
        print(f"⚠️  --rate-switch : {', '.join(late)} >= --duration ({a.duration}s) : jamais atteint")

    if a.analyze_only:
        jp = Path(a.analyze_only)
        mp = jp.parent / "run_meta.json"      # CPU réel mesuré pendant le run, s'il existe
        meta = json.loads(mp.read_text()) if mp.is_file() else {}
        if not meta:
            print("⚠️  pas de run_meta.json à côté du profil : analyse dégradée (sans CPU réel).")
        report, folded = analyze(jp, a.project_marker, a.top, None, 0, meta)
        out = jp.parent
        (out / "report.md").write_text(report, encoding="utf-8")
        (out / "folded.txt").write_text("".join(f"{k} {int(v * 1000)}\n" for k, v in folded.items()))
        print(report)
        print(f"\n📝 {out / 'report.md'}")
        return

    if os.geteuid() != 0:
        sys.exit("Root requis (AF_PACKET, nft, ptrace) : sudo -E $(which python3) profile_run.py ...")
    if not shutil.which("py-spy"):
        sys.exit("py-spy introuvable : pip install py-spy (et vérifie qu'il est dans le PATH de root, ou sudo -E env PATH=$PATH ...)")
    if not Path(a.target).is_file():
        sys.exit(f"Cible introuvable : {a.target}")

    if a.idle:
        print("⚠️  --idle : py-spy ne filtre plus les threads en attente (ex. DNS bloquant) ; le rapport sera recalé sur le CPU réel "
              "mesuré dans /proc, mais lance plutôt SANS --idle.")
    if a.native or a.nonblocking:
        print("⚠️  --native/--nonblocking : mode intrusif/inexact, les débits absolus seront faussés.")
    out = Path(a.out_dir or f"profile_out_{datetime.now():%Y%m%d_%H%M%S}")
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(load_env(Path(a.env_file)))
    env.setdefault("PYTHONUNBUFFERED", "1")

    traffic = target = spy = None
    ttap = gtap = stap = None
    snap0 = snap1 = gen0 = gen1 = sys0 = sys1 = None
    spy_cpu = target_alive = None
    timers = []
    stdin_lock = threading.Lock()
    state = {"mode": "normal", "rate": initial_rate}
    timeline = [(0.0, f"normal @ {initial_rate}")]      # (t relatif, trafic injecté)
    t_start = t_end = 0.0
    spy_json = out / "profile.speedscope.json"
    try:
        # 1) générateur de trafic (le veth doit exister AVANT que l'IDS capture dessus)
        if a.traffic:
            print("🚦 Démarrage du générateur de trafic (génération des pcaps : ça peut prendre un moment)...")
            traffic = subprocess.Popen([a.python, "-u", a.traffic_script, f"--rate={initial_rate}"], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                       env=env, start_new_session=True)
            gtap = LineTap(traffic, out / "traffic.log", "traffic", markers=(TRAFFIC_READY,), echo=not a.quiet)
            gtap.start()
            if not gtap.events[TRAFFIC_READY].wait(300):
                raise RuntimeError("gen_traffic n'est pas prêt après 300 s (voir traffic.log)")

        # 2) cible
        print(f"🚀 Lancement de {a.target}")
        target = subprocess.Popen([a.python, "-u", a.target], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, env=env, start_new_session=True)
        ttap = LineTap(target, out / "target.log", "ids", markers=(a.ready_marker,), echo=not a.quiet)
        ttap.start()
        ok = ttap.events[a.ready_marker].wait(a.ready_timeout)
        if target.poll() is not None:
            raise RuntimeError(f"La cible s'est arrêtée (code {target.returncode}) — voir {out / 'target.log'}")
        if not ok:
            print(f"⚠️  Marqueur « {a.ready_marker} » non vu après {a.ready_timeout}s : on profile quand même.")
        print(f"⏳ Stabilisation {a.settle}s...")
        time.sleep(a.settle)

        # 3) py-spy
        cmd = ["py-spy", "record", "--pid", str(target.pid), "--rate", str(a.rate),
               "--duration", str(a.duration), "--threads", "--subprocesses",
               "--format", "speedscope", "--output", str(spy_json)]
        for flag, on in (("--native", a.native), ("--gil", a.gil), ("--idle", a.idle), ("--nonblocking", a.nonblocking)):
            if on:
                cmd.append(flag)
        print("🔬", " ".join(cmd))
        snap0 = cpu_snapshot(target.pid)       # CPU réel : instantané de départ (/proc)
        gen0 = cpu_snapshot(traffic.pid) if traffic is not None else None
        sys0, ru0 = system_cpu_times(), resource.getrusage(resource.RUSAGE_CHILDREN)
        ttap.recording = True
        t_start = time.time()
        if traffic is not None:
            def _send(line, mode=None, rate=None):
                """Envoie une commande au générateur et note la phase dans la timeline."""
                try:
                    with stdin_lock:
                        traffic.stdin.write(line + "\n")
                        traffic.stdin.flush()
                    state["mode"] = mode or state["mode"]
                    state["rate"] = rate or state["rate"]
                    timeline.append((time.time() - t_start, f"{state['mode']} @ {state['rate']}"))
                    print(f"{'⚔️ ' if mode == 'attack' else '🎚️ '} '{line}' envoyé au générateur "
                          f"(t+{timeline[-1][0]:.0f}s)")
                except Exception as e:
                    print(f"⚠️  impossible d'envoyer '{line}' : {e}")

            if a.attack_after > 0:
                timers.append(threading.Timer(a.attack_after, _send, ("attack", "attack")))
            for t_, spec_ in rate_plan:
                timers.append(threading.Timer(t_, _send, (f"rate {spec_}", None, spec_)))
            for tm in timers:
                tm.daemon = True
                tm.start()
        spy = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stap = LineTap(spy, out / "pyspy.log", "py-spy", echo=not a.quiet)   # garde le log py-spy (retards, erreurs)
        stap.start()
        try:
            spy.wait(timeout=a.duration + 60)
        except (KeyboardInterrupt, subprocess.TimeoutExpired) as e:
            print("\n⛔ Interruption" if isinstance(e, KeyboardInterrupt) else
                  f"\n⚠️  py-spy ne s'est pas arrêté après {a.duration + 60}s", ": SIGINT, il termine l'écriture du profil...")
            spy.send_signal(signal.SIGINT)
            spy.wait(timeout=30)
        t_end = time.time()
        ttap.recording = False
        snap1 = cpu_snapshot(target.pid)       # CPU réel : instantané de fin, AVANT d'arrêter l'IDS
        gen1 = cpu_snapshot(traffic.pid) if traffic is not None else None
        sys1, ru1 = system_cpu_times(), resource.getrusage(resource.RUSAGE_CHILDREN)
        spy_cpu = (ru1.ru_utime + ru1.ru_stime) - (ru0.ru_utime + ru0.ru_stime)
        target_alive = target.poll() is None
    except KeyboardInterrupt:
        print("\n⛔ Interruption")
    except Exception as e:
        print(f"❌ {e}")
    finally:
        for tm in timers:
            tm.cancel()
        if spy is not None and spy.poll() is None:
            spy.send_signal(signal.SIGINT)
        print("🧹 Arrêt de l'IDS (SIGINT, comme Ctrl-C)...")
        stop_group(target, "IDS")
        if traffic is not None:
            try:
                traffic.stdin.write("quit\n")
                traffic.stdin.flush()
                traffic.wait(timeout=8)
            except Exception:
                pass
            stop_group(traffic, "gen_traffic", wait=8)

    if not spy_json.is_file():
        sys.exit(f"❌ Pas de profil écrit. Voir {out}/target.log (py-spy a-t-il pu s'attacher ? ptrace_scope ?)")
    wall = (t_end - t_start) if t_end else a.duration
    meta = {"opts": {"idle": a.idle, "native": a.native, "nonblocking": a.nonblocking, "gil": a.gil,
                     "rate": a.rate, "duration": a.duration, "target_alive": target_alive}}
    if stap is not None:
        stap.join(timeout=3)
        try:
            meta["spy_log"] = (out / "pyspy.log").read_text(errors="replace")
        except OSError:
            pass
    if snap0 and snap1:
        meta["cpu"] = build_cpu_meta(snap0, snap1, gen0, gen1, sys0, sys1, spy_cpu)
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")   # pour --analyze-only
    report, folded = analyze(spy_json, a.project_marker, a.top, ttap, wall, meta)
    if traffic is not None and ttap is not None:
        report += "\n" + phase_table(timeline, ttap, t_start, t_end or (t_start + wall))
    (out / "report.md").write_text(report, encoding="utf-8")
    (out / "folded.txt").write_text("".join(f"{k} {int(v * 1000)}\n" for k, v in folded.items()))
    print("\n" + report)
    print(f"\n📝 Rapport : {out / 'report.md'}")
    print(f"🔥 Flamegraph interactif : glisse {spy_json} dans https://speedscope.app")


if __name__ == "__main__":
    cmd = (
        'sudo env "PATH=$PATH" /home/hounsousamuel/pyglobal0/bin/python3.11 '
        '/home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/profile_run.py '
        '--rate 70 --python /home/hounsousamuel/pyglobal0/bin/python3.11 --duration 365 --settle 15 --idle '
        '--traffic-rate pps=1000 --rate-switch "60:pps=5000,120:pps=10000,200:pps=15000,300:pps=20000" '
        '--traffic --attack-after 60 --out-dir /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/'
    )
    main()
    # sudo env "PATH=$PATH" /home/hounsousamuel/pyglobal0/bin/python3.11 /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/profile_run.py 
    # --python /home/hounsousamuel/pyglobal0/bin/python3.11 --duration 365 --settle 15 --idle --traffic --attack-after 60
    # --out-dir /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/ --native