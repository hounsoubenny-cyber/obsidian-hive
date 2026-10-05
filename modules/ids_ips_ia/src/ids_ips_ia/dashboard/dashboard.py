#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dashboard.py — mini dashboard terminal « façon top », sans dépendance.

Comment ça marche
  * Le terminal est coupé en deux avec une RÉGION DE DÉFILEMENT ANSI : les N premières lignes sont réservées au
    dashboard (redessiné 1×/s par un thread), le reste de l'écran défile normalement. Tout ce qui écrit sur le
    terminal (logger, print, traceback...) s'affiche dans la zone du bas sans jamais écraser l'en-tête.
  * Le thread ne fait que LIRE un instantané (snapshot_fn) : aucun verrou, aucun coût sur le chemin chaud.
    Les débits (pkt/s...) sont calculés ici à partir des DIFFÉRENCES entre deux instantanés (lissage EWMA).
  * Pas de terminal (service systemd, redirection, CI) -> repli automatique : UNE ligne de synthèse toutes les
    `fallback_every` secondes (envoyée à `fallback_log`, ex. logger.info).
  * Terminal trop petit -> le dashboard se met en pause (et revient tout seul si on agrandit la fenêtre).

Utilisation
    dash = Dashboard(snapshot_fn=ma_fonction, fallback_log=logger.info)
    dash.start()
    ...
    dash.stop()          # restaure le terminal (aussi appelé à la sortie du programme)

snapshot_fn() renvoie un dict ; toutes les clés sont optionnelles (absent -> « – ») :
  "capture"  : Capture.metrics()          (recv, kept, loss_pct, kernel_loss_pct, app_loss_pct...)
  "detector" : AnomalyDetector.stats()    (uptime_s, packets_processed, queue, batches, pipeline, inference...)
  "anomalies_logged" : int                (total des anomalies enregistrées)
  "blocked"  : int                        (IP bloquées)
  "batcher"  : BlockBatcher.stats()       (queued, commands, failed, dropped, committed)

Si le terminal reste cassé après un kill -9 (région de défilement figée) : tape `reset`.
"""
import atexit
import collections
import os
import re
import shutil
import sys
import threading
import time
from datetime import datetime

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_TOK = re.compile(r"(\x1b\[[0-9;?]*[A-Za-z])|(.)", re.S)
RESET, BOLD, DIM, INV = "\x1b[0m", "\x1b[1m", "\x1b[2m", "\x1b[7m"
GREEN, YELLOW, RED, CYAN, GREY = "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[36m", "\x1b[90m"
SPARK = "▁▂▃▄▅▆▇█"
DASH = "–"


# ----------------------------------------------------------------------------- utilitaires d'affichage
def vlen(s: str) -> int:
    """Longueur VISIBLE (sans les séquences ANSI)."""
    return len(_ANSI.sub("", s))


def clip(s: str, width: int) -> str:
    """Coupe à `width` colonnes visibles en conservant les séquences ANSI, puis remet les couleurs à zéro."""
    out, n = [], 0
    for m in _TOK.finditer(s):
        if m.group(1):
            out.append(m.group(1))
        else:
            if n >= width:
                break
            out.append(m.group(2))
            n += 1
    return "".join(out) + RESET


def fmt_int(v) -> str:
    return DASH if v is None else f"{int(v):,}".replace(",", " ")


def fmt_rate(v) -> str:
    if v is None:
        return DASH
    return f"{v:,.0f}".replace(",", " ") if v >= 100 else f"{v:.1f}"


def fmt_dur(s) -> str:
    s = int(s or 0)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return (f"{d}j " if d else "") + f"{h:02d}:{m:02d}:{s:02d}"


def fmt_bytes(n) -> str:
    if n is None:
        return DASH
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit in ("o", "Ko") else f"{n:.1f} {unit}"
        n /= 1024


def bar(frac, width=10) -> str:
    frac = 0.0 if frac is None else max(0.0, min(1.0, frac))
    k = round(frac * width)
    return "█" * k + "░" * (width - k)


def spark(values, width=24) -> str:
    vals = list(values)[-width:]
    if not vals:
        return " " * width
    hi = max(vals) or 1.0
    return "".join(SPARK[min(7, int(7 * v / hi))] for v in vals).ljust(width)


def color(text, value, warn, crit) -> str:
    """Vert < warn <= jaune < crit <= rouge."""
    c = GREEN if value is None or value < warn else (YELLOW if value < crit else RED)
    return f"{c}{text}{RESET}"


def g(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d if d is not None else default


def _rss_bytes():
    try:
        import psutil
        return psutil.Process().memory_info().rss
    except Exception:
        try:
            with open("/proc/self/statm") as f:
                return int(f.read().split()[1]) * (os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096)
        except Exception:
            return None


class Dashboard:
    HEIGHT = 10                      # lignes réservées en haut de l'écran

    def __init__(self, snapshot_fn, title="OBSIDIAN IDS/IPS", interval=1.0, stream=None,
                 fallback_log=None, fallback_every=10.0, force=None, footer="", history=24):
        """
        force=None : dashboard seulement si le flux est un terminal ; True : toujours ; False : repli ligne.
        footer     : texte gris sous le tableau (ex. « journaux : WARNING+ en console · détail dans logs/ »).
        """
        self.snapshot_fn, self.title, self.interval = snapshot_fn, title, float(interval)
        self.stream = stream or sys.stdout
        tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.mode = "tty" if (force is True or (force is None and tty)) else "log"
        self.fallback_log = fallback_log or (lambda line: print(line, flush=True))
        self.fallback_every = float(fallback_every)
        self.footer = footer
        self._stop = threading.Event()
        self._thread = None
        self._t0 = time.monotonic()
        self._prev, self._ewma = {}, {}
        self._hist = collections.deque(maxlen=history)
        self._peak = 0.0
        self._active = False          # région de défilement en place ?
        self._size = None
        self._cpu_prev = (time.monotonic(), time.process_time())
        self._cpu_pct = 0.0
        self.last_error = None
        self._started = False
        self._closed = False

    # ------------------------------------------------------------------ cycle de vie
    def start(self):
        if self._started:
            return self
        self._started = True
        if self.mode == "tty":
            self._enter()
        self._thread = threading.Thread(target=self._loop, name="Dashboard", daemon=True)
        self._thread.start()
        atexit.register(self.stop)
        return self

    def stop(self):
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._leave()

    # ------------------------------------------------------------------ boucle
    def _loop(self):
        last_log = 0.0
        while not self._stop.wait(self.interval):
            try:
                model = self._compute(self.snapshot_fn() or {})
                if self.mode == "tty":
                    self._draw(model)
                elif time.monotonic() - last_log >= self.fallback_every:
                    last_log = time.monotonic()
                    self.fallback_log(self.summary_line(model))
            except Exception as e:                       # le dashboard ne doit JAMAIS faire tomber la détection
                self.last_error = repr(e)

    # ------------------------------------------------------------------ calculs
    def _rate(self, key, value, now):
        """Débit lissé (EWMA) d'un compteur monotone ; None tant qu'on n'a qu'un seul point."""
        if value is None:
            return None
        prev = self._prev.get(key)
        self._prev[key] = (now, value)
        if prev is None or now <= prev[0]:
            return self._ewma.get(key)
        r = max(0.0, (value - prev[1]) / (now - prev[0]))      # compteur remis à zéro -> 0
        self._ewma[key] = r if key not in self._ewma else 0.5 * r + 0.5 * self._ewma[key]
        return self._ewma[key]

    def _compute(self, snap: dict) -> dict:
        now = time.monotonic()
        cap, det = snap.get("capture") or {}, snap.get("detector") or {}
        bat = snap.get("batcher") or {}
        m = {"now": datetime.now().strftime("%H:%M:%S")}
        m["uptime"] = g(det, "uptime_s", default=now - self._t0)
        m["mode"] = g(det, "mode", default=DASH)
        proc = g(det, "packets_processed")
        m["processed"] = proc
        m["proc_rate"] = self._rate("proc", proc, now)
        m["proc_avg"] = (proc / m["uptime"]) if proc is not None and m["uptime"] else None
        m["seq"] = g(det, "sequences_evaluated")
        m["seq_rate"] = self._rate("seq", m["seq"], now)
        if m["proc_rate"] is not None:
            self._hist.append(m["proc_rate"])
            self._peak = max(self._peak, m["proc_rate"])
        m["peak"] = self._peak or None
        m["recv_rate"] = self._rate("recv", cap.get("recv"), now)
        m["kept_rate"] = self._rate("kept", cap.get("kept"), now)
        m["loss"], m["kloss"], m["aloss"] = cap.get("loss_pct"), cap.get("kernel_loss_pct"), cap.get("app_loss_pct")
        m["q_size"], m["q_max"], m["q_fill"] = g(det, "queue", "size"), g(det, "queue", "max"), g(det, "queue", "fill_pct")
        m["ready"], m["depth"] = g(det, "pipeline", "ready_batches"), g(det, "pipeline", "depth")
        m["batches"], m["last_batch"], m["avg_batch"] = g(det, "batches"), g(det, "last_batch_size"), g(det, "avg_batch_size")
        m["anom"] = snap.get("anomalies_logged")
        m["anom_rate"] = self._rate("anom", m["anom"], now)
        m["anom_mem"], m["sys_alerts"] = g(det, "anomalies_in_memory"), g(det, "system_alerts_open")
        m["blocked"] = snap.get("blocked")
        m["b_queued"], m["b_cmd"], m["b_fail"], m["b_drop"] = (bat.get("queued"), bat.get("commands"),
                                                                 bat.get("failed"), bat.get("dropped"))
        inf = g(det, "inference", default={}) or {}
        m["infer_ok"] = not any(v.get("failing") for v in inf.values()) if inf else True
        wall, cpu = time.monotonic(), time.process_time()
        if wall - self._cpu_prev[0] >= 1.0:
            self._cpu_pct = 100.0 * (cpu - self._cpu_prev[1]) / (wall - self._cpu_prev[0])
            self._cpu_prev = (wall, cpu)
        m["cpu"], m["threads"], m["rss"] = self._cpu_pct, threading.active_count(), _rss_bytes()
        return m

    # ------------------------------------------------------------------ rendu
    def render_lines(self, m: dict, width: int):
        """Les HEIGHT lignes du dashboard (avec couleurs ANSI), sans toucher au terminal : testable seul."""
        W = max(60, width)
        title = f" {self.title}  |  mode {m['mode']}  |  uptime {fmt_dur(m['uptime'])}  |  {m['now']} "
        L = [f"{INV}{BOLD}{title.ljust(W)}{RESET}"]
        L.append(f" {BOLD}DEBIT{RESET}    traité {BOLD}{fmt_rate(m['proc_rate']):>7}{RESET} pkt/s  {CYAN}{spark(self._hist)}{RESET}"
                 f"  moy {fmt_rate(m['proc_avg'])} · pic {fmt_rate(m['peak'])} · séquences {fmt_rate(m['seq_rate'])}/s")
        loss = f"{m['loss']:.1f} %" if m["loss"] is not None else DASH
        L.append(f" {BOLD}CAPTURE{RESET}  reçus {fmt_rate(m['recv_rate'])}/s · gardés {fmt_rate(m['kept_rate'])}/s · "
                 f"pertes {color(loss, m['loss'], 1, 10)}"
                 f" (noyau {fmt_rate(m['kloss'])} % · file {fmt_rate(m['aloss'])} %)")
        qf = (m["q_fill"] or 0) / 100.0
        qtxt = f"{fmt_int(m['q_size'])}/{fmt_int(m['q_max'])}" if m["q_max"] else fmt_int(m["q_size"])
        L.append(f" {BOLD}FILE{RESET}     amont {qtxt} {color(bar(qf), (m['q_fill'] or 0), 30, 80)} "
                 f"{fmt_rate(m['q_fill'])} % · pipeline prêt {fmt_int(m['ready'])}/{fmt_int(m['depth'])}")
        L.append(f" {BOLD}LOTS{RESET}     {fmt_int(m['batches'])} lots · dernier {fmt_int(m['last_batch'])} · "
                 f"moyen {fmt_rate(m['avg_batch'])} · séquences évaluées {fmt_int(m['seq'])}")
        L.append(f" {BOLD}ALERTES{RESET}  anomalies {fmt_rate(m['anom_rate'])}/s (total {fmt_int(m['anom'])}) · "
                 f"en mémoire {fmt_int(m['anom_mem'])} · alertes système ouvertes {fmt_int(m['sys_alerts'])}")
        fails = color(fmt_int(m["b_fail"]), m["b_fail"] or 0, 1, 5)
        L.append(f" {BOLD}REACTION{RESET} IP bloquées {fmt_int(m['blocked'])} · batcher: file {fmt_int(m['b_queued'])}"
                 f" · cmd nft {fmt_int(m['b_cmd'])} · échecs {fails} · abandons {fmt_int(m['b_drop'])}")
        infer = f"{GREEN}OK{RESET}" if m["infer_ok"] else f"{RED}EN PANNE{RESET}"
        cpu_txt = "%.0f %%" % m["cpu"]                      # (pas de f-string imbriquée : compatible Python 3.11)
        L.append(f" {BOLD}SYSTEME{RESET}  RAM {fmt_bytes(m['rss'])} · threads {m['threads']} · "
                 f"CPU {color(cpu_txt, m['cpu'], 150, 300)} · inférence {infer}")
        L.append(f"{GREY}{'─' * W}{RESET}")
        L.append(f"{DIM} {self.footer or 'journaux ci-dessous (Ctrl-C pour arrêter)'}{RESET}")
        return [clip(line, W) for line in L[:self.HEIGHT]]

    def summary_line(self, m: dict) -> str:
        """Une seule ligne (repli sans terminal)."""
        return (f"[dashboard] uptime {fmt_dur(m['uptime'])} | traité {fmt_rate(m['proc_rate'])} pkt/s "
                f"(moy {fmt_rate(m['proc_avg'])}, pic {fmt_rate(m['peak'])}) | gardés {fmt_rate(m['kept_rate'])}/s | "
                f"pertes {fmt_rate(m['loss'])} % | file {fmt_rate(m['q_fill'])} % | anomalies {fmt_rate(m['anom_rate'])}/s | "
                f"bloquées {fmt_int(m['blocked'])} | RAM {fmt_bytes(m['rss'])} | CPU {m['cpu']:.0f} %")

    # ------------------------------------------------------------------ terminal
    def _term_size(self):
        s = shutil.get_terminal_size((100, 30))
        return s.columns, s.lines

    def _write(self, text):
        try:
            self.stream.write(text)
            self.stream.flush()
        except Exception:
            pass

    def _enter(self):
        cols, rows = self._term_size()
        if rows < self.HEIGHT + 6 or cols < 60:               # trop petit : pas de dashboard
            self._active = False
            self._size = (cols, rows)
            return
        # efface l'écran, réserve les HEIGHT premières lignes (région de défilement = le reste), curseur dans la zone du bas
        self._write(f"\x1b[2J\x1b[H\x1b[{self.HEIGHT + 1};{rows}r\x1b[{self.HEIGHT + 1};1H")
        self._active = True
        self._size = (cols, rows)

    def _leave(self):
        if self._active:
            cols, rows = self._term_size()
            self._write(f"\x1b[r\x1b[{rows};1H\n")           # supprime la région de défilement
        self._active = False

    def _draw(self, model):
        size = self._term_size()
        if size != self._size:                               # fenêtre redimensionnée
            self._leave()
            self._enter()
        if not self._active:
            return
        lines = self.render_lines(model, size[0])
        # \x1b7 / \x1b8 : sauvegarde / restaure le curseur -> les logs en cours d'écriture ne sont pas perturbés ;
        # tout le cadre part en UN SEUL write.
        frame = "\x1b7" + "".join(f"\x1b[{i + 1};1H\x1b[2K{line}" for i, line in enumerate(lines)) + "\x1b8"
        self._write(frame)
