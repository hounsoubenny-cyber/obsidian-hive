#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct  2 10:48:34 2026

@author: hounsousamuel
"""


"""
block_batcher.py — Blocages nftables groupés et asynchrones.

Problème mesuré (result007) : chaque anomalie = 1 commande nft (~8,8 ms, sous un _nft_lock global) que
detect_pkt ATTEND (await to_thread(action)), une anomalie après l'autre -> 146 s sur 360 s de fenêtre
(16 699 blocages), le thread de détection passe 80 % de son temps à attendre. Pire : sous un vrai DDoS
(beaucoup d'IP sources distinctes) l'IPS ralentirait exactement quand il faut bloquer vite.

Ici :
  - submit() ne fait QUE déposer la demande dans une queue (quelques µs) -> la détection ne bloque plus ;
  - un thread dédié regroupe, par fenêtre de `flush_interval` (20 ms) ou `max_batch` éléments, toutes les IP
    d'un même (set, timeout) en UNE commande :  add element inet T S { ip1 timeout 60s , ip2 timeout 60s }
    (le coût fixe d'un appel libnftables est payé une fois pour N IP) ;
  - dédup : la clé est (set, ip) ET la FORCE du blocage : une demande n'est écartée que si une demande au moins
    aussi longue est déjà en attente pour le même (set, ip). Un blocage permanent qui suit un temporaire
    n'est donc JAMAIS perdu ; dans un même lot on ne garde que la plus forte (comportement déterministe) ;
  - si une commande groupée échoue (une IP invalide fait échouer toute la transaction nft), repli : les
    éléments sont rejoués un par un -> seule la mauvaise IP est perdue ;
  - on_blocked(meta) est appelé pour chaque IP réellement bloquée (c'est là qu'on met à jour React.blocked) ;
  - close() vide la queue (atexit) : aucune demande acceptée n'est perdue à l'arrêt propre.

Le blocage devient effectif au plus `flush_interval` (+ durée d'une commande) après submit() : dans les faits
bien AVANT qu'aujourd'hui, où chaque blocage attend derrière les précédents.

run_cmd(cmd_list) doit renvoyer un objet avec .returncode (ex. React._run_command) ou None (= échec).
"""

import re
import time
import queue
import atexit
import threading
from typing import Callable

_STOP = object()
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_TOK = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([smhd]?)$")


def _rank(tok) -> float:
    """Force d'un blocage = sa durée en secondes ('never' / None = permanent = inf). Illisible -> inf (jamais écarté)."""
    if tok is None or tok == "never":
        return float("inf")
    m = _TOK.match(str(tok))
    return float(m.group(1)) * _UNITS[m.group(2) or "s"] if m else float("inf")


class BlockBatcher:
    def __init__(
        self, 
        run_cmd: Callable,
        table: str,
        on_blocked: Callable,
        *,
        flush_interval: float = 0.03,
        max_batch: int = 256,
        queue_max: int = 500_000, 
        on_warning: Callable | None = None
    ):
        self.run_cmd = run_cmd
        self.table = table
        self.on_blocked = on_blocked
        self.flush_interval = float(flush_interval)
        self.max_batch = max(1, int(max_batch))
        self._warn_cb = on_warning or print
        self._q = queue.Queue(maxsize=int(queue_max))
        self._pending = {}                         # (set_name, ip) -> force (rang) de la demande en route : dédup
        self._plock = threading.Lock()
        self._tlock = threading.Lock()
        self._thread = None
        self._closed = False
        self._last_warn = 0.0
        self.submitted = self.committed = self.commands = self.failed = self.dropped = self.deduped = 0
        atexit.register(self.close)

    # ------------------------------------------------------------------ API
    def submit(
        self,
        ip: str, set_name: str,
        timeout_token: str | None = None,
        meta: dict | None = None
    ) -> bool:
        """Enfile un blocage. timeout_token : '60s' | 'never' | None. Non bloquant. False si refusé."""
        if self._closed:
            return False
        
        key = (set_name, ip)
        rank = _rank(timeout_token)
        with self._plock:
            cur = self._pending.get(key)
            if cur is not None and rank <= cur:      # une demande au moins aussi forte est déjà en route
                self.deduped += 1
                return True
            self._pending[key] = rank                # nouvelle, ou PLUS FORTE que celle en attente
        try:
            self._ensure_thread()
            self._q.put_nowait((set_name, ip, timeout_token, meta))
            self.submitted += 1
            return True
        except queue.Full:
            with self._plock:
                if self._pending.get(key) == rank:
                    del self._pending[key]
            self.dropped += 1
            self._warn(f"BlockBatcher : queue pleine, blocage de {ip} abandonné ({self.dropped} au total)")
            return False

    def close(self, timeout: float = 20.0):
        if self._closed:
            return
        
        self._closed = True
        t = self._thread
        if t is not None and t.is_alive():
            try:
                self._q.put(_STOP, timeout=timeout)
            except queue.Full:
                return
            t.join(timeout)

    def stats(self) -> dict:
        return {
            "submitted": self.submitted, "committed": self.committed, 
            "commands": self.commands, "failed": self.failed, 
            "dropped": self.dropped, "deduped": self.deduped,
            "queued": self._q.qsize()
        }

    # ------------------------------------------------------------- interne
    def _warn(self, msg):
        now = time.monotonic()
        if now - self._last_warn > 10.0:
            self._last_warn = now
            try:
                self._warn_cb(msg)
            except Exception:
                pass

    def _ensure_thread(self):
        t = self._thread
        if t is not None and t.is_alive():
            return
        
        with self._tlock:
            t = self._thread
            if t is None or not t.is_alive():
                self._thread = threading.Thread(target=self._run, name="BlockBatcher", daemon=True)
                self._thread.start()

    def _run(self):
        while True:
            first = self._q.get()                              # attend la 1ère demande
            items, stop = [], first is _STOP
            if not stop:
                items.append(first)
                deadline = time.monotonic() + self.flush_interval
                while len(items) < self.max_batch:             # fenêtre de coalescence
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        it = self._q.get(timeout=remaining)
                    except queue.Empty:
                        break
                    if it is _STOP:
                        stop = True
                        break
                    items.append(it)
            if items:
                try:
                    self._flush(items)
                except Exception as e:                         # le thread ne doit jamais mourir
                    self._warn(f"BlockBatcher._flush : {e!r}")
                finally:
                    with self._plock:
                        for set_name, ip, tok, _meta in items:      # ne libère que sa propre demande
                            if self._pending.get((set_name, ip)) == _rank(tok):
                                del self._pending[(set_name, ip)]
            if stop:
                return

    def _flush(self, items):
        best = {}                                           # une seule demande par (set, ip) : la plus forte
        for set_name, ip, tok, meta in items:
            r = _rank(tok)
            cur = best.get((set_name, ip))
            if cur is None or r > cur[0]:
                best[(set_name, ip)] = (r, tok, meta)
        groups = {}
        for (set_name, ip), (_r, tok, meta) in best.items():
            groups.setdefault((set_name, tok), []).append((ip, meta))
        for (set_name, tok), els in groups.items():
            if self._commit(set_name, tok, els):
                continue
            if len(els) > 1:                                   # une IP invalide casse toute la transaction
                for e in els:
                    self._commit(set_name, tok, [e])

    def _commit(self, set_name, tok, els) -> bool:
        toks = []
        for k, (ip, _meta) in enumerate(els):
            if k:
                toks.append(",")
            toks.append(ip)
            if tok:
                toks += ["timeout", tok]
        cmd = ["nft", "add", "element", "inet", self.table, set_name, "{", *toks, "}"]
        self.commands += 1
        try:
            r = self.run_cmd(
                cmd, check=False,
                success_msg=(
                    f"Blocage de {len(els)} IP ({set_name}) : {els[0][0]}"
                    + (f" … +{len(els) - 1}" if len(els) > 1 else "")
                )
            )
        except Exception as e:
            self._warn(f"BlockBatcher commande : {e!r}")
            r = None
            
        if r is not None and getattr(r, "returncode", 1) == 0:
            for _ip, meta in els:
                try:
                    self.on_blocked(meta)
                except Exception as e:
                    self._warn(f"BlockBatcher on_blocked : {e!r}")
            self.committed += len(els)
            return True
        
        if len(els) == 1:
            self.failed += 1
        return False


if __name__ == "__main__":
    # Auto-test : python3 block_batcher.py   (faux backend nft, latence 8,8 ms par commande comme result007)
    import types

    LAT = 0.0088

    class FakeNft:
        def __init__(self, latency=LAT):
            self.cmds, self.set, self.latency = [], set(), latency

        def __call__(self, cmd, check=False, success_msg=None):
            time.sleep(self.latency)
            self.cmds.append(cmd)
            body = cmd[cmd.index("{") + 1:-1]
            ips = [t for t in body if t not in (",", "timeout") and not t[0].isdigit() is False and "." in t]
            if "BAD" in body:
                return types.SimpleNamespace(returncode=1)
            self.set.update(ips)
            return types.SimpleNamespace(returncode=0)

    # 1) 2000 IP distinctes d'un coup
    nft, done = FakeNft(), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.02, max_batch=256)
    t0 = time.perf_counter()
    for i in range(2000):
        assert b.submit(f"10.{i // 250}.{i % 250}.1", "blacklist_input_ip4", "3600s", {"ip": i})
    t_submit = time.perf_counter() - t0
    b.close()
    s = b.stats()
    assert len(done) == 2000 and len(nft.set) == 2000 and s["committed"] == 2000, s
    print(f"✅ 2000 IP : submit() = {t_submit * 1000:.0f} ms au total dans le thread appelant ; "
          f"{s['commands']} commandes nft au lieu de 2000 (soit ~{s['commands'] * LAT * 1000:.0f} ms de nft au lieu de ~{2000 * LAT:.0f} s)")

    # 2) dédup + syntaxe exacte + groupes (set, timeout) distincts
    nft, done = FakeNft(0), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.05)
    b.submit("1.1.1.1", "S_in", "60s", "a"); b.submit("1.1.1.1", "S_in", "60s", "a")     # doublon
    b.submit("2.2.2.2", "S_in", "60s", "b"); b.submit("3.3.3.3", "S_in", "never", "c"); b.submit("4.4.4.4", "S_rl", None, "d")
    b.close()
    got = sorted(" ".join(c[1:]) for c in nft.cmds)
    exp = sorted(["add element inet ids S_in { 1.1.1.1 timeout 60s , 2.2.2.2 timeout 60s }",
                  "add element inet ids S_in { 3.3.3.3 timeout never }",
                  "add element inet ids S_rl { 4.4.4.4 }"])
    assert got == exp, got
    assert sorted(done) == ["a", "b", "c", "d"] and b.stats()["deduped"] == 1
    print("✅ dédup + syntaxe nft exacte + groupes (set, timeout) séparés")

    # 2b) escalade : temporaire PUIS permanent dans la même fenêtre -> le permanent ne doit JAMAIS être perdu
    nft, done = FakeNft(0), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.05)
    b.submit("9.9.9.9", "S", "60s", "temp"); b.submit("9.9.9.9", "S", "never", "PERM")
    b.submit("9.9.9.9", "S", "30s", "plus-faible")                     # plus faible que la permanente : écartée
    b.close()
    assert done == ["PERM"] and [" ".join(c[1:]) for c in nft.cmds] == ["add element inet ids S { 9.9.9.9 timeout never }"], (done, nft.cmds)
    # et l'inverse : une demande plus forte arrive APRÈS le flush de la plus faible -> envoyée aussi
    nft, done = FakeNft(0), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.01)
    b.submit("9.9.9.9", "S", "60s", "temp"); time.sleep(0.2); b.submit("9.9.9.9", "S", "never", "PERM"); b.close()
    assert done == ["temp", "PERM"], done
    print("✅ escalade temporaire -> permanent : le permanent n'est jamais perdu (fenêtre identique ou lots différents)")

    # 3) une IP invalide ne fait pas perdre les autres (repli unitaire)
    nft, done = FakeNft(0), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.05)
    for ip in ("5.5.5.5", "BAD", "6.6.6.6"):
        b.submit(ip, "S", "60s", ip)
    b.close()
    assert sorted(done) == ["5.5.5.5", "6.6.6.6"] and b.stats()["failed"] == 1, (done, b.stats())
    print("✅ repli unitaire : seule l'IP invalide est perdue")

    # 4) close() vide la queue
    nft, done = FakeNft(0.01), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.5)
    for i in range(50):
        b.submit(f"7.7.7.{i}", "S", "60s", i)
    b.close()
    assert len(done) == 50
    print("✅ close() n'abandonne aucune demande acceptée")

    # 5) queue pleine : jamais bloquant
    nft, done = FakeNft(0.2), []
    b = BlockBatcher(nft, "ids", lambda m: done.append(m), flush_interval=0.01, max_batch=1, queue_max=5, on_warning=lambda m: None)
    res = [b.submit(f"8.8.8.{i}", "S", None, i) for i in range(40)]
    assert res.count(False) > 0 and b.stats()["dropped"] == res.count(False)
    b.close(timeout=10)
    print(f"✅ queue pleine : {res.count(False)}/40 refusées sans bloquer")
