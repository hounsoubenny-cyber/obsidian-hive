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

    def run(self):
        for line in self.proc.stdout:
            self.fh.write(line)
            self.fh.flush()
            if self.echo:
                sys.stdout.write(f"[{self.tag}] {line}")
            for m, ev in self.events.items():
                if m in line:
                    ev.set()
            if self.recording:
                now = time.time()
                if "[SÉQUENCE]" in line and "paquets anormaux" in line:
                    self.times["sequences"].append(now)
                elif "[PAQUET] Anomalie" in line:
                    self.times["pkt_anomalies"].append(now)
                elif "Blocage de" in line:
                    self.times["blocks"].append(now)
                m = RE_STATS.search(line)
                if m:
                    self.stats.append((now, _num(m[1]), _num(m[2]), _num(m[3]), _num(m[4]), float(m[5])))
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
PIPELINE_STAGES = [
    ("detect() — boucle consommateur (total)", {"detect"}, "detection_module"),
    ("extract_pack_features (par paquet)", {"extract_pack_features"}, None),
    ("predict_packet (AE + IF + LOF, batch=1)", {"predict_packet", "apredict_packet"}, None),
    ("extract_seq_features", {"extract_seq_features"}, None),
    ("predict_sequence (CNN + AE + IF + LOF)", {"predict_sequence", "apredict_sequence"}, None),
    ("  dont Keras predict()", {"predict", "predict_function", "predict_step"}, "keras"),
    ("  dont IsolationForest.decision_function", {"decision_function"}, "_iforest"),
    ("  dont LOF.decision_function", {"decision_function", "score_samples", "kneighbors"}, "_lof"),
    ("AnomalyScorer.detect_pkt (voie lente)", {"detect_pkt"}, None),
    ("log_anomaly / _add_alert", {"log_anomaly", "_add_alert"}, None),
    ("persistance joblib/pickle (dump)", {"dump"}, None),
    ("logger.print", {"print"}, "logger"),
    ("blocage nft (_run_command / block)", {"_run_command", "block"}, None),
    ("graphes (add_data*)", {"add_data1", "add_data2", "add_data3"}, None),
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
BLOCK_LINE = re.compile(r"(time\.sleep|asyncio\.sleep|\.wait|\.join|\.get\(\s*(block|timeout))\s*\(?")


def short(fr: dict) -> str:
    return f"{fr['name']} ({os.path.basename(fr.get('file') or '?')})"


def analyze(json_path: Path, project_marker: str, top: int, tap: "LineTap | None", wall: float):
    d = json.loads(Path(json_path).read_text())
    frames = d["shared"]["frames"]
    profiles = d["profiles"]
    fkey = [(f["name"], f.get("file") or "?") for f in frames]
    fpath = [(f.get("file") or "").lower() for f in frames]
    # frames synthétiques ajoutées par py-spy (--threads/--subprocesses) : "process N", "thread (N)" -> sans fichier
    synth = [not f.get("file") for f in frames]
    generic = {"asyncio / threads / queue"}

    total = 0.0
    idle_all = 0.0
    idle_tot = {}
    thread_tot = {}
    thread_leaf = defaultdict(Counter)
    self_fn, incl_fn, self_line = Counter(), Counter(), Counter()
    leaf_cat = Counter()
    stage_incl = Counter()
    proj_incl = Counter()
    stacks = Counter()
    folded = Counter()

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
                leaf_idle = bool(src_line and BLOCK_LINE.search(src_line))
            if leaf_idle or any(k in n for n in tail for k in IDLE_NAMES):
                idle_tot[pname] = idle_tot.get(pname, 0.0) + w
                idle_all += w
                continue
            total += w
            thread_tot[pname] = thread_tot.get(pname, 0.0) + w
            leaf = stack[-1]
            thread_leaf[pname][fkey[leaf]] += w
            self_fn[fkey[leaf]] += w
            self_line[leaf] += w
            for k in {fkey[i] for i in stack}:
                incl_fn[k] += w
            for k in {fkey[i] for i in stack if project_marker in fpath[i]}:
                proj_incl[k] += w
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
            leaf_cat[cat] += w
            # étapes inclusives
            for label, names, fsub in PIPELINE_STAGES:
                if any(frames[i]["name"] in names and (fsub is None or fsub in fpath[i]) for i in stack):
                    stage_incl[label] += w
            stacks[tuple(stack[-7:])] += w
            folded[";".join([pname.replace(";", ",").replace(" ", "_")] +
                            [frames[i]["name"].replace(";", ",") for i in stack])] += w

    if total <= 0:
        return "# ❌ Profil vide (aucun échantillon). Vérifie que py-spy a bien pu s'attacher (root ?).\n", folded

    pct = lambda x: f"{100 * x / total:5.1f} %"
    L = []
    add = L.append
    add(f"# Rapport de profilage IDS/IPS — {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    add(f"- Temps **actif** (hors attentes) : **{total:.1f} s** cumulés sur {len(profiles)} thread(s)/process"
        + (f" pour **{wall:.0f} s** de fenêtre" if wall else "")
        + f" · attentes ignorées (wait/sleep/queue.get/epoll…) : {idle_all:.1f} s")
    add("- Les pourcentages sont relatifs au temps actif total. "
        "⚠️ `--native` en mode bloquant ralentit fortement la cible : fie-toi aux PROPORTIONS, pas au débit absolu.\n")

    # --- verdict ---
    add("## 🎯 Verdict automatique\n")
    cats = leaf_cat.most_common()
    stage_nodetect = [(k, v) for k, v in stage_incl.most_common() if not k.startswith("detect()") and not k.startswith("  ")]
    add(f"- Bibliothèque qui consomme le plus (feuille) : **{cats[0][0]}** ({pct(cats[0][1]).strip()})")
    if stage_nodetect:
        add(f"- Étape du pipeline la plus coûteuse : **{stage_nodetect[0][0]}** ({pct(stage_nodetect[0][1]).strip()})")
    hints = []
    s = lambda label: stage_incl.get(label, 0) / total
    if s("predict_sequence (CNN + AE + IF + LOF)") > 0.25:
        hints.append("`predict_sequence` pèse lourd → l'appeler toutes les N paquets (stride), pas à chaque paquet.")
    if s("predict_packet (AE + IF + LOF, batch=1)") > 0.15:
        hints.append("`predict_packet` en batch=1 → regrouper 128-512 paquets par appel.")
    if leaf_cat.get("TensorFlow / Keras", 0) / total > 0.30:
        hints.append("Keras domine → `model(x, training=False)` ou `tf.function` à signature fixe au lieu de `model.predict` par petit lot.")
    if leaf_cat.get("scikit-learn", 0) / total > 0.20:
        hints.append("sklearn domine (IF/LOF sur 1 échantillon) → batcher, réduire `n_estimators` / `n_neighbors`, éviter le lock.")
    if s("persistance joblib/pickle (dump)") > 0.10:
        hints.append("🚨 Une sauvegarde joblib/pickle tourne DANS la boucle de détection : écrire par lots, "
                     "en append (1 fichier par paquet d'alertes) et/ou dans un thread dédié — jamais re-dumper toute la liste.")
    if s("logger.print") > 0.08 or leaf_cat.get("logs / print", 0) / total > 0.08:
        hints.append("Les logs coûtent cher → verbose=0 pendant les benchs, ou logger via une queue asynchrone.")
    if s("blocage nft (_run_command / block)") > 0.05:
        hints.append("Les commandes nft sont bloquantes dans la boucle → file d'attente dédiée + ne pas re-bloquer une IP déjà bloquée.")
    if s("graphes (add_data*)") > 0.05:
        hints.append("Les graphes Bokeh coûtent → `enable_graph=False` pour mesurer le pipeline seul.")
    for h in hints or ["Pas de règle évidente déclenchée : regarde les tables ci-dessous et le flamegraph."]:
        add(f"- 💡 {h}")
    add("\n_(Heuristiques indicatives : vérifie toujours dans le flamegraph.)_\n")

    # --- débit réel ---
    if tap is not None and wall:
        add("## 📈 Débit mesuré pendant la fenêtre\n")
        seq = len(tap.times["sequences"])
        add(f"- Séquences évaluées : **{seq}** → {seq / wall:.2f}/s "
            f"(≈ {seq / wall:.2f} paquets/s traités si stride=1)")
        add(f"- Anomalies paquet : {len(tap.times['pkt_anomalies'])} · blocages nft : {len(tap.times['blocks'])}")
        if tap.stats:
            a, b = tap.stats[0], tap.stats[-1]
            add(f"- Capture au début : {a[2]:,} pkt/s gardés, pertes {a[5]:.1f} % (noyau {a[3]:,} · app {a[4]:,})".replace(",", " "))
            add(f"- Capture à la fin : {b[2]:,} pkt/s gardés, pertes {b[5]:.1f} % (noyau {b[3]:,} · app {b[4]:,})".replace(",", " "))
        add("")

    # --- étapes ---
    add("## 🧱 Étapes du pipeline (temps inclusif)\n")
    add("| Étape | % temps actif | secondes |\n|---|---:|---:|")
    for label, _, _ in PIPELINE_STAGES:
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
    add("| Thread | actif (s) | % | en attente (s) | fonction la plus chaude |\n|---|---:|---:|---:|---|")
    for pname, t in sorted(thread_tot.items(), key=lambda kv: -kv[1])[:top]:
        (fn, fl), _ = thread_leaf[pname].most_common(1)[0]
        add(f"| {pname} | {t:.1f} | {pct(t)} | {idle_tot.get(pname, 0.0):.1f} | {fn} ({os.path.basename(fl)}) |")
    add("")

    # --- fonctions ---
    add(f"## ⏱️ Top {top} fonctions — temps propre (self)\n")
    add("| Fonction | % | s |\n|---|---:|---:|")
    for (fn, fl), v in self_fn.most_common(top):
        add(f"| `{fn}` ({os.path.basename(fl)}) | {pct(v)} | {v:.1f} |")
    add("")
    add(f"## ⏱️ Top {top} fonctions — temps inclusif\n")
    add("| Fonction | % | s |\n|---|---:|---:|")
    for (fn, fl), v in incl_fn.most_common(top):
        add(f"| `{fn}` ({os.path.basename(fl)}) | {pct(v)} | {v:.1f} |")
    add("")
    if proj_incl:
        add(f"## 🧩 Fonctions de TON code (`{project_marker}`) — inclusif\n")
        add("| Fonction | % | s |\n|---|---:|---:|")
        for (fn, fl), v in proj_incl.most_common(top):
            add(f"| `{fn}` ({os.path.basename(fl)}) | {pct(v)} | {v:.1f} |")
        add("")

    add(f"## 📍 Top {top} lignes chaudes\n")
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
    ap.add_argument("--idle", action="store_true", help="inclure les threads inactifs")
    ap.add_argument("--nonblocking", action="store_true", help="py-spy --nonblocking (moins intrusif, moins exact)")
    ap.add_argument("--traffic", action="store_true", help="démarre gen_traffic.py avant la cible")
    ap.add_argument("--traffic-script", default=str(DEFAULT_TRAFFIC))
    ap.add_argument("--attack-after", type=int, default=0, help="envoie 'attack' au générateur N s après le début du profil")
    ap.add_argument("--project-marker", default="ids_ips_ia", help="chemin identifiant TON code dans les piles")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--quiet", action="store_true", help="n'affiche pas les logs de la cible/du générateur")
    ap.add_argument("--analyze-only", metavar="SPEEDSCOPE_JSON", help="ne lance rien : analyse un profil existant")
    a = ap.parse_args()

    if a.analyze_only:
        jp = Path(a.analyze_only)
        report, folded = analyze(jp, a.project_marker, a.top, None, 0)
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

    out = Path(a.out_dir or f"profile_out_{datetime.now():%Y%m%d_%H%M%S}")
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(load_env(Path(a.env_file)))
    env.setdefault("PYTHONUNBUFFERED", "1")

    traffic = target = spy = None
    ttap = gtap = None
    timer = None
    t_start = t_end = 0.0
    spy_json = out / "profile.speedscope.json"
    try:
        # 1) générateur de trafic (le veth doit exister AVANT que l'IDS capture dessus)
        if a.traffic:
            print("🚦 Démarrage du générateur de trafic (génération des pcaps : ça peut prendre un moment)...")
            traffic = subprocess.Popen([a.python, "-u", a.traffic_script], stdin=subprocess.PIPE,
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
        ttap.recording = True
        t_start = time.time()
        if traffic is not None and a.attack_after > 0:
            def _attack():
                try:
                    traffic.stdin.write("attack\n")
                    traffic.stdin.flush()
                    print("⚔️  'attack' envoyé au générateur")
                except Exception as e:
                    print(f"⚠️  impossible d'envoyer 'attack' : {e}")
            timer = threading.Timer(a.attack_after, _attack)
            timer.start()
        spy = subprocess.Popen(cmd)
        try:
            spy.wait(timeout=a.duration + 60)
        except KeyboardInterrupt:
            print("\n⛔ Interruption : py-spy termine l'écriture du profil...")
            spy.send_signal(signal.SIGINT)
            spy.wait(timeout=30)
        t_end = time.time()
        ttap.recording = False
    except KeyboardInterrupt:
        print("\n⛔ Interruption")
    except Exception as e:
        print(f"❌ {e}")
    finally:
        if timer:
            timer.cancel()
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
    report, folded = analyze(spy_json, a.project_marker, a.top, ttap, wall)
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
        '--traffic --attack-after 60 --out-dir /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/'
    )
    main()
    # sudo env "PATH=$PATH" /home/hounsousamuel/pyglobal0/bin/python3.11 /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/profile_run.py 
    # --python /home/hounsousamuel/pyglobal0/bin/python3.11 --duration 365 --settle 15 --idle --traffic --attack-after 60
    # --out-dir /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/test_utils/ --native