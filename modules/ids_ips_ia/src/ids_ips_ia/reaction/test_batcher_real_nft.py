#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_batcher_real_nft.py — teste BlockBatcher contre un VRAI nftables.

Il crée une table TEMPORAIRE isolée (ids_batch_test_<pid>) avec des sets IDENTIQUES aux tiens
(type ipv4_addr/ipv6_addr ; flags interval,timeout ; timeout 60m), n'ajoute AUCUNE règle (aucun risque pour
ton trafic), et supprime la table à la fin. Ta vraie table obsidian_ids_ips_table_* n'est jamais touchée.

Ce qu'il mesure / vérifie :
  S1  sémantique de nft sur set INTERVAL : ré-ajout identique, ré-ajout avec un autre timeout, "timeout never",
      IP adjacentes, et surtout : un lot contenant une IP DÉJÀ PRÉSENTE échoue-t-il en entier ?
  S2  exactitude : N IP (v4+v6, timeouts variés) via le batcher -> toutes présentes dans le vrai set ?
  S3  re-blocage : 50 % d'IP déjà présentes -> combien de lots échouent, le repli unitaire récupère-t-il tout ?
  S4  latence par commande selon la taille du lot (1 -> 1024) et selon la taille déjà atteinte du set
  S5  gain : N ajouts un par un vs via le batcher
  S6  IP invalide / mauvaise famille dans un lot : seules les mauvaises sont perdues ?
  S7  concurrence : plusieurs threads, doublons croisés
  S8  (--slow) expiration réelle des timeouts

Usage :
  sudo python3 test_batcher_real_nft.py                 # vrai nft (backend auto : python-nftables sinon CLI `nft`)
  sudo python3 test_batcher_real_nft.py --backend cli   # force la CLI
  sudo python3 test_batcher_real_nft.py --n 5000 --big 30000 --slow
  python3 test_batcher_real_nft.py --fake               # SIMULATION (valide le script, ne prouve rien sur nft)
  python3 test_batcher_real_nft.py --fake --fake-overlap  # simule l'erreur "interval overlaps" sur doublon exact
Le fichier block_batcher.py doit être dans le même dossier (ou dans ../reaction).
"""
import argparse
import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.join(HERE, "..", "reaction"), os.path.join(HERE, "reaction")):
    if os.path.isfile(os.path.join(p, "block_batcher.py")):
        sys.path.insert(0, p)
        break
from block_batcher import BlockBatcher  # noqa: E402

SET4, SET6 = "blacklist_input_ip4", "blacklist_input_ip6"


# ----------------------------------------------------------------------------- backends
def _expand(val, cap=1 << 16):
    if isinstance(val, str):
        return {val}
    if isinstance(val, dict) and "range" in val:
        a, b = (int(ipaddress.ip_address(x)) for x in val["range"])
        fam = ipaddress.ip_address(val["range"][0]).__class__
        return {str(fam(i)) for i in range(a, min(b, a + cap) + 1)}
    if isinstance(val, dict) and "prefix" in val:
        net = ipaddress.ip_network(f"{val['prefix']['addr']}/{val['prefix']['len']}")
        return {str(x) for x in net} if net.num_addresses <= cap else {str(net)}
    return set()


def parse_elems(doc):
    raw, addrs = [], set()
    for item in doc.get("nftables", []):
        s = item.get("set")
        if not s:
            continue
        for e in s.get("elem", []):
            raw.append(e)
            addrs |= _expand(e["elem"]["val"] if isinstance(e, dict) and "elem" in e else e)
    return raw, addrs


class CliNft:
    name = "cli"

    def __init__(self):
        self.bin = shutil.which("nft")
        if not self.bin:
            sys.exit("`nft` introuvable dans le PATH.")

    def version(self):
        return subprocess.run([self.bin, "--version"], capture_output=True, text=True).stdout.strip()

    def run(self, cmdline):
        p = subprocess.run([self.bin, "-f", "-"], input=cmdline + "\n", capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    def elems(self, table, setname):
        p = subprocess.run([self.bin, "-j", "list", "set", "inet", table, setname], capture_output=True, text=True)
        if p.returncode:
            raise RuntimeError(p.stderr)
        return parse_elems(json.loads(p.stdout))


class LibNft:
    name = "lib"

    def __init__(self):
        import nftables
        self.n = nftables.Nftables()
        self.n.set_json_output(False)
        self.j = nftables.Nftables()
        self.j.set_json_output(True)

    def version(self):
        return "python-nftables (libnftables)"

    def run(self, cmdline):
        rc, out, err = self.n.cmd(cmdline)
        return rc, out or "", err or ""

    def elems(self, table, setname):
        rc, out, err = self.j.cmd(f"list set inet {table} {setname}")
        if rc:
            raise RuntimeError(err)
        return parse_elems(json.loads(out))


class FakeNft:
    """SIMULATION minimale (valide le script). Ne reproduit PAS le vrai comportement de nft."""
    name = "fake"

    def __init__(self, overlap_on_dup=False):
        self.sets, self.overlap = {}, overlap_on_dup

    def version(self):
        return "simulation (pas de vrai nft)"

    def run(self, cmdline):
        t = cmdline.split()
        n = 1 + sum(1 for c in cmdline if c == ",") if "{" in cmdline else 1
        time.sleep(0.004 + 0.00001 * n)
        if t[:2] == ["add", "table"] or t[:2] == ["delete", "table"]:
            if t[0] == "delete":
                self.sets = {}
            return 0, "", ""
        if t[:2] == ["add", "set"]:
            self.sets[t[4]] = (6 if "ipv6_addr" in cmdline else 4, {})
            return 0, "", ""
        if t[:2] == ["add", "element"]:
            fam, store = self.sets[t[4]]
            body = cmdline[cmdline.index("{") + 1:cmdline.rindex("}")]
            new = {}
            for el in body.split(","):
                tok = el.split()
                try:
                    ip = ipaddress.ip_address(tok[0])
                except ValueError:
                    return 1, "", f"Error: syntax error, unexpected string near '{tok[0]}'"
                if ip.version != fam:
                    return 1, "", "Error: Could not process rule: Invalid argument"
                if self.overlap and tok[0] in store:
                    return 1, "", "Error: Could not process rule: File exists (interval overlaps with an existing one)"
                new[str(ip)] = tok[2] if len(tok) >= 3 else "60m"
            store.update(new)
            return 0, "", ""
        return 1, "", "commande inconnue du simulateur"

    def elems(self, table, setname):
        store = self.sets[setname][1]
        return [{"elem": {"val": ip, "timeout": tok}} for ip, tok in store.items()], set(store)


# ----------------------------------------------------------------------------- contexte
class Ctx:
    def __init__(self, nft, table):
        self.nft, self.T = nft, table
        self.lock = threading.Lock()                  # comme ton _nft_lock : un seul appel nft à la fois
        self.log = []                                 # (n_elements, durée, rc, stderr)
        self._ip = 0
        self.fail = []                                # assertions échouées

    def run_cmd(self, cmd, check=False, success_msg=None):
        """Même signature que React._run_command ; mesure chaque commande."""
        line = " ".join(cmd[1:] if cmd and cmd[0] == "nft" else cmd)
        n = 1 + line.count(",") if "{" in line else 1
        with self.lock:
            t0 = time.perf_counter()
            rc, out, err = self.nft.run(line)
            dt = time.perf_counter() - t0
        self.log.append((n, dt, rc, err.strip().splitlines()[0] if err.strip() else ""))
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    def ips4(self, n):                                # IP v4 espacées de 2 : jamais adjacentes entre elles
        base = self._ip
        self._ip += n
        return [str(ipaddress.IPv4Address(0x0A000000 + 2 * (base + i))) for i in range(n)]

    def ips6(self, n):
        base = self._ip
        self._ip += n
        return [str(ipaddress.IPv6Address((0x20010DB8 << 96) | (2 * (base + i)))) for i in range(n)]

    def present(self, setname):
        return self.nft.elems(self.T, setname)[1]

    def check(self, ok, msg):
        print(("   ✅ " if ok else "   ❌ ") + msg)
        if not ok:
            self.fail.append(msg)

    def add(self, setname, body):
        return self.nft.run(f"add element inet {self.T} {setname} {{ {body} }}")


def new_batcher(ctx, **kw):
    kw.setdefault("flush_interval", 0.02)
    return BlockBatcher(ctx.run_cmd, ctx.T, lambda m: None, on_warning=lambda m: print("   ⚠️", m), **kw)


def title(s):
    print(f"\n━━ {s}")


# ----------------------------------------------------------------------------- scénarios
def s1_semantics(ctx):
    title("S1  Sémantique de nft sur set INTERVAL (ce que ton batch peut rencontrer)")
    a, b, c, d, e = ctx.ips4(5)
    probes = [
        ("ajout simple (timeout 60s)", f"{a} timeout 60s"),
        ("ré-ajout IDENTIQUE", f"{a} timeout 60s"),
        ("ré-ajout avec un AUTRE timeout (escalade -> never)", f"{a} timeout never"),
        ("syntaxe « timeout never » sur une nouvelle IP", f"{b} timeout never"),
        ("IP sans timeout (défaut du set : 60m)", f"{c}"),
        ("lot = 1 IP déjà présente + 2 nouvelles", f"{a} timeout 60s , {d} timeout 60s , {e} timeout 60s"),
    ]
    res = {}
    for label, body in probes:
        rc, out, err = ctx.add(SET4, body)
        res[label] = rc
        print(f"   {'ok ' if rc == 0 else 'ERR'} {label}" + (f"  ->  {err.strip().splitlines()[0][:110]}" if rc else ""))
    raw, addrs = ctx.nft.elems(ctx.T, SET4)
    mine = [r for r in raw if (r["elem"]["val"] if isinstance(r, dict) and "elem" in r else r) == a]
    print(f"   état de {a} après escalade vers never : {json.dumps(mine[0]) if mine else 'ABSENTE'}")
    print("   (si 'expires' est absent/très long -> nft a MIS À JOUR le timeout ; sinon il l'a ignoré)")
    lot_key = "lot = 1 IP déjà présente + 2 nouvelles"
    if res[lot_key] != 0:
        print(f"   ⚠️ UN LOT CONTENANT UNE IP DÉJÀ PRÉSENTE ÉCHOUE EN ENTIER ; nouvelles ajoutées malgré tout : "
              f"{ {d, e} <= addrs }  -> le repli unitaire du batcher sera sollicité à chaque re-blocage.")
    else:
        print("   ℹ️ un lot avec une IP déjà présente passe : pas de repli nécessaire pour les re-blocages.")
    return res


def s2_correct(ctx, n):
    title(f"S2  Exactitude via le batcher ({n} IPv4 + {n // 10} IPv6, timeouts variés)")
    v4, v6 = ctx.ips4(n), ctx.ips6(max(1, n // 10))
    toks = ["60s", "3600s", "never"]
    b = new_batcher(ctx)
    t0 = time.perf_counter()
    for i, ip in enumerate(v4):
        b.submit(ip, SET4, toks[i % 3], i)
    for i, ip in enumerate(v6):
        b.submit(ip, SET6, toks[i % 3], i)
    t_sub = time.perf_counter() - t0
    b.close()
    s = b.stats()
    miss4, miss6 = set(v4) - ctx.present(SET4), set(v6) - ctx.present(SET6)
    print(f"   submit() total {t_sub * 1000:.0f} ms ; {s['commands']} commandes pour {s['submitted']} IP ; stats={s}")
    ctx.check(not miss4 and not miss6, f"toutes les IP sont présentes dans le vrai set (manquantes : v4={len(miss4)} v6={len(miss6)})")
    ctx.check(s["failed"] == 0 and s["committed"] == s["submitted"], f"committed == submitted == {s['submitted']}, failed == 0")


def s3_reblock(ctx, n):
    title("S3  Re-blocage : 50 % d'IP déjà présentes dans le set")
    pool = sorted(x for x in ctx.present(SET4) if x.startswith("10."))
    old = random.sample(pool, min(len(pool), n // 2))
    new = ctx.ips4(len(old))
    mix = old + new
    random.shuffle(mix)
    before = len(ctx.log)
    b = new_batcher(ctx, flush_interval=0.2, max_batch=512)
    for ip in mix:
        b.submit(ip, SET4, "3600s", None)
    b.close()
    cmds = ctx.log[before:]
    bad = [c for c in cmds if c[2] != 0]
    s = b.stats()
    print(f"   {len(mix)} IP ({len(old)} déjà présentes) -> {s['commands']} commandes dont {len(bad)} en ÉCHEC "
          f"(lots échoués : {sum(1 for c in bad if c[0] > 1)})")
    for c in bad[:3]:
        print(f"      échec ({c[0]} éléments) : {c[3][:120]}")
    miss = set(new) - ctx.present(SET4)
    ctx.check(not miss, f"les {len(new)} nouvelles IP sont bien présentes malgré les doublons (manquantes : {len(miss)})")
    ctx.check(s["failed"] == 0, f"aucune IP définitivement perdue (failed={s['failed']})")
    if bad:
        print("   💡 des lots échouent à cause des doublons : filtre les IP déjà dans React.blocked AVANT submit()"
              " (le skipper le fait côté paquets) pour éviter le repli unitaire.")


def s4_latency(ctx, big):
    title("S4  Latence d'une commande selon la taille du lot, puis selon la taille du set")
    print("   taille du lot |  ms / commande |  µs / IP")
    for size in (1, 16, 64, 256, 1024):
        ts = []
        for _ in range(3):
            ips = ctx.ips4(size)
            body = " , ".join(f"{ip} timeout 3600s" for ip in ips)
            t0 = time.perf_counter()
            rc, _, err = ctx.add(SET4, body)
            ts.append(time.perf_counter() - t0)
            if rc:
                print("      échec :", err.strip().splitlines()[0][:100])
        m = sum(ts) / len(ts)
        print(f"   {size:13d} | {m * 1000:14.2f} | {m / size * 1e6:8.0f}")
    print("   coût d'un lot de 256 IP selon la taille ACTUELLE du set (hypothèse : le coût grandit avec le set) :")
    cur = len(ctx.present(SET4))
    for target in sorted({0, big // 4, big}):
        while cur < target:
            k = min(512, target - cur)
            ips = ctx.ips4(k)
            ctx.add(SET4, " , ".join(f"{ip} timeout 3600s" for ip in ips))
            cur += k
        ips = ctx.ips4(256)
        t0 = time.perf_counter()
        ctx.add(SET4, " , ".join(f"{ip} timeout 3600s" for ip in ips))
        print(f"      set ≈ {max(cur, 0):7d} éléments -> {(time.perf_counter() - t0) * 1000:7.1f} ms pour 256 IP")
        cur += 256


def s5_gain(ctx, n):
    title("S5  Un par un vs batcher")
    k = min(n, 600)
    ips = ctx.ips4(k)
    t0 = time.perf_counter()
    for ip in ips:
        ctx.run_cmd(["nft", "add", "element", "inet", ctx.T, SET4, "{", ip, "timeout", "3600s", "}"])
    t_one = time.perf_counter() - t0
    ips = ctx.ips4(k)
    t0 = time.perf_counter()
    b = new_batcher(ctx)
    for ip in ips:
        b.submit(ip, SET4, "3600s", None)
    b.close()
    t_b = time.perf_counter() - t0
    print(f"   {k} IP : un par un = {t_one * 1000:.0f} ms ({t_one / k * 1000:.2f} ms/IP) | batcher = {t_b * 1000:.0f} ms "
          f"({t_b / k * 1000:.3f} ms/IP) -> ×{t_one / max(t_b, 1e-9):.1f}")
    ctx.check(set(ips) <= ctx.present(SET4), "toutes les IP du batcher sont présentes")


def s6_bad(ctx):
    title("S6  IP invalide / mauvaise famille dans un lot")
    good = ctx.ips4(40)
    b = new_batcher(ctx, flush_interval=0.3)
    for i, ip in enumerate(good):
        b.submit(ip, SET4, "3600s", None)
        if i == 20:
            b.submit("999.1.1.1", SET4, "3600s", None)          # invalide
            b.submit("10.200.200.200", SET6, "3600s", None)     # IPv4 dans un set IPv6
    b.close()
    s = b.stats()
    miss = set(good) - ctx.present(SET4)
    print(f"   stats={s}")
    ctx.check(not miss, f"les 40 IP valides sont toutes présentes (manquantes : {len(miss)})")
    ctx.check(s["failed"] == 2, f"exactement 2 IP perdues (l'invalide et la mauvaise famille) : failed={s['failed']}")


def s7_threads(ctx, n):
    title("S7  Concurrence : 8 threads, doublons croisés")
    pool = ctx.ips4(max(50, n // 2))
    b = new_batcher(ctx)
    errs = []

    def worker(seed):
        r = random.Random(seed)
        for _ in range(len(pool)):
            if not b.submit(r.choice(pool), SET4, "3600s", None):
                errs.append(1)

    th = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in th]
    [t.join() for t in th]
    b.close()
    seen = {ip for ip in pool if ip in ctx.present(SET4)}
    s = b.stats()
    print(f"   stats={s}")
    ctx.check(s["dropped"] == 0 and not errs, "aucune demande refusée")
    ctx.check(s["failed"] == 0, f"aucune IP perdue (failed={s['failed']}) ; {len(seen)}/{len(pool)} IP du pool vues (au hasard des tirages)")


def s8_expiry(ctx):
    title("S8  Expiration réelle des timeouts (3 s)")
    ips = ctx.ips4(3)
    ctx.add(SET4, " , ".join(f"{ip} timeout 3s" for ip in ips))
    ctx.check(set(ips) <= ctx.present(SET4), "présentes juste après l'ajout")
    time.sleep(5)
    ctx.check(not (set(ips) & ctx.present(SET4)), "disparues après ~5 s")


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["auto", "lib", "cli"], default="auto")
    ap.add_argument("--n", type=int, default=3000, help="nombre d'IP des scénarios (défaut 3000)")
    ap.add_argument("--big", type=int, default=20000, help="taille cible du set pour S4 (défaut 20000)")
    ap.add_argument("--slow", action="store_true", help="active S8 (attend 5 s)")
    ap.add_argument("--keep", action="store_true", help="ne supprime pas la table de test")
    ap.add_argument("--fake", action="store_true", help="simulation sans nft (valide le script)")
    ap.add_argument("--fake-overlap", action="store_true", help="avec --fake : un doublon exact échoue (simule 'interval overlaps')")
    a = ap.parse_args()

    if a.fake:
        nft = FakeNft(a.fake_overlap)
    else:
        if os.geteuid() != 0:
            sys.exit("Root requis : sudo python3 test_batcher_real_nft.py")
        nft = None
        if a.backend in ("auto", "lib"):
            try:
                nft = LibNft()
            except Exception as e:
                if a.backend == "lib":
                    sys.exit(f"python-nftables indisponible : {e}")
        nft = nft or CliNft()

    table = f"ids_batch_test_{os.getpid()}"
    ctx = Ctx(nft, table)
    print(f"Backend : {nft.name} — {nft.version()} — table de test : inet {table}")
    random.seed(1)
    rc, _, err = nft.run(f"add table inet {table}")
    if rc:
        sys.exit(f"impossible de créer la table de test : {err}")
    try:
        for fam, name in (("ipv4_addr", SET4), ("ipv6_addr", SET6)):
            rc, _, err = nft.run(f"add set inet {table} {name} {{ type {fam} ; flags interval,timeout ; timeout 60m ; }}")
            if rc:
                sys.exit(f"création du set {name} impossible : {err}")
        s1_semantics(ctx)
        s2_correct(ctx, a.n)
        s3_reblock(ctx, a.n)
        s4_latency(ctx, a.big)
        s5_gain(ctx, a.n)
        s6_bad(ctx)
        s7_threads(ctx, a.n)
        if a.slow:
            s8_expiry(ctx)
    finally:
        if not a.keep:
            nft.run(f"delete table inet {table}")
            print(f"\n🧹 table inet {table} supprimée")
    n_cmd, n_bad = len(ctx.log), sum(1 for c in ctx.log if c[2] != 0)
    n_bad_batch = sum(1 for c in ctx.log if c[2] != 0 and c[0] > 1)
    print(f"\n━━ BILAN : {n_cmd} commandes nft, {n_bad} en échec (dont {n_bad_batch} LOTS), assertions échouées : {len(ctx.fail)}")
    for f in ctx.fail:
        print("   ❌", f)
    print("   Envoie-moi toute cette sortie : je lis surtout S1 (doublons / timeout), S3 (lots échoués) et S4 (coût vs taille).")
    sys.exit(1 if ctx.fail else 0)


if __name__ == "__main__":
    main()
