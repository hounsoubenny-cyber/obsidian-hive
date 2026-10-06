#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_nft_extra.py — 2 sondes ciblées, À METTRE dans le même dossier que test_batcher_real_nft.py (il le réutilise).

  S1b  Ré-ajout d'une IP avec un AUTRE timeout : nft MET-IL À JOUR le timeout, ou l'IGNORE-T-IL ?
       (ma sonde S1 était ambiguë : l'ordre des opérations masquait la réponse)
  S9   Set INTERVAL (ton cas) vs set SIMPLE (hash) : coût d'un lot de 256 IP selon la taille du set.
       Si le set simple reste plat alors que l'interval grandit -> tu peux retirer `interval` de tes blacklists.

Usage :  sudo python3 probe_nft_extra.py            (vrai nft)       |   python3 probe_nft_extra.py --fake   (valide le script)
         sudo python3 probe_nft_extra.py --big 40000 --backend cli
Durée : ~1 min. Tout est dans une table temporaire supprimée à la fin.
"""
import argparse, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_batcher_real_nft import Ctx, CliNft, LibNft, FakeNft, SET4, SET6, title  # noqa: E402


def elem_state(ctx, setname, ip):
    raw, _ = ctx.nft.elems(ctx.T, setname)
    for r in raw:
        e = r["elem"] if isinstance(r, dict) and "elem" in r else {"val": r}
        if e["val"] == ip:
            return e
    return None


def s1b(ctx):
    title("S1b  Ré-ajout avec un autre timeout : MISE À JOUR ou IGNORÉ ?")
    x = ctx.ips4(1)[0]
    ctx.add(SET4, f"{x} timeout 60s")
    time.sleep(2.2)
    print(f"   après `timeout 60s` + 2,2 s          : {elem_state(ctx, SET4, x)}")
    for label, tok in (("PLUS LONG  (3600s)", "3600s"), ("PERMANENT (never)", "never"), ("PLUS COURT (5s)", "5s")):
        rc, _, err = ctx.add(SET4, f"{x} timeout {tok}")
        print(f"   re-ajout {label} : rc={rc} état = {elem_state(ctx, SET4, x)}" + (f"  err={err.strip()[:80]}" if rc else ""))
    print("   Lecture : si 'timeout'/'expires' CHANGENT à chaque re-ajout -> nft METS À JOUR ;"
          "\n             s'ils restent à ~60 / ~58 -> nft IGNORE : une escalade temporaire -> permanent sur une IP déjà"
          "\n             présente ne sera PAS appliquée (il faudrait `delete element` puis `add element` dans la même transaction).")


def s9(ctx, big):
    title("S9  Set INTERVAL vs set SIMPLE : coût d'un lot de 256 IP selon la taille du set")
    r1 = ctx.nft.run(f"add set inet {ctx.T} plain4 {{ type ipv4_addr ; flags timeout ; timeout 60m ; }}")
    r2 = ctx.nft.run(f"add set inet {ctx.T} intv4 {{ type ipv4_addr ; flags interval,timeout ; timeout 60m ; }}")
    if r1[0] or r2[0]:
        print("   création impossible :", (r1[2] or r2[2]).strip()[:150]); return
    print("   éléments déjà dans le set |  SIMPLE (hash) |  INTERVAL (ton cas) | rapport")
    cur = 0
    for target in sorted({0, big // 4, big // 2, big}):
        while cur < target:
            k = min(1024, target - cur)
            body = " , ".join(f"{ip} timeout 3600s" for ip in ctx.ips4(k))
            ctx.add("plain4", body); ctx.add("intv4", body); cur += k
        body = " , ".join(f"{ip} timeout 3600s" for ip in ctx.ips4(256))
        t0 = time.perf_counter(); r_p = ctx.add("plain4", body); tp = time.perf_counter() - t0
        t0 = time.perf_counter(); r_i = ctx.add("intv4", body); ti = time.perf_counter() - t0
        flag = "" if not (r_p[0] or r_i[0]) else "  (échec !)"
        print(f"   {cur:25d} | {tp * 1000:11.1f} ms | {ti * 1000:15.1f} ms | ×{ti / max(tp, 1e-9):4.1f}{flag}")
        cur += 256
    print("   Si SIMPLE reste ~constant et INTERVAL monte avec la taille -> retirer `interval` règle le problème (si tu ne bloques"
          "\n   jamais de plages/CIDR dans les blacklists).")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["auto", "lib", "cli"], default="auto")
    ap.add_argument("--big", type=int, default=20000)
    ap.add_argument("--fake", action="store_true")
    a = ap.parse_args()
    if a.fake:
        nft = FakeNft()
    else:
        if os.geteuid() != 0:
            sys.exit("Root requis : sudo python3 probe_nft_extra.py")
        nft = None
        if a.backend in ("auto", "lib"):
            try: nft = LibNft()
            except Exception as e:
                if a.backend == "lib": sys.exit(f"python-nftables indisponible : {e}")
        nft = nft or CliNft()
    table = f"ids_probe_{os.getpid()}"
    ctx = Ctx(nft, table)
    print(f"Backend : {nft.name} — {nft.version()} — table de test : inet {table}")
    rc, _, err = nft.run(f"add table inet {table}")
    if rc: sys.exit(f"table impossible : {err}")
    try:
        for fam, name in (("ipv4_addr", SET4), ("ipv6_addr", SET6)):
            rc, _, err = nft.run(f"add set inet {table} {name} {{ type {fam} ; flags interval,timeout ; timeout 60m ; }}")
            if rc: sys.exit(f"set {name} : {err}")
        s1b(ctx)
        s9(ctx, a.big)
    finally:
        nft.run(f"delete table inet {table}")
        print(f"\n🧹 table inet {table} supprimée")


if __name__ == "__main__":
    main()
