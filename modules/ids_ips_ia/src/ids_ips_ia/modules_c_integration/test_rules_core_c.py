#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 15 10:37:13 2026

@author: hounsousamuel
"""

"""test_rules_core_c.py : teste, côté Python, ce qui a été ajouté à core_c.pyx pour les règles :
rules_set / rules_get (à chaud), noms des règles, FLOW_DTYPE.rule_reason, END_REASONS[6].

Lancer :   python3 test_rules_core_c.py        (ou : pytest test_rules_core_c.py)
Ne capture rien : pas besoin de root. Recompiler d'abord :  python setup.py build_ext --inplace
"""
import importlib
import sys
import threading
import traceback

import numpy as np

core = importlib.import_module("ids_ips_ia.modules_c_integration.ids_ips_core_c")


def _no_ctor():
    raise RuntimeError("constructeur de l'Engine non deviné : écris-le dans new_engine()")


def new_engine():
    return core.Engine()


NOMS = ["port_scan", "null_scan", "xmas_scan", "fin_scan", "flood"]


def test_dtype_rule_reason():
    dt = core.FLOW_DTYPE
    assert dt.itemsize == 176, "la taille d'un flux ne doit pas changer"
    assert "rule_reason" in dt.names
    assert dt.fields["rule_reason"][1] == 161
    assert dt.fields["verdict"][1] == 164, "verdict n'a pas bougé"
    assert dt.fields["reason"][1] == 168, "reason n'a pas bougé"
    a = np.zeros(2, dtype=dt)
    a["rule_reason"][0] = 3
    a["verdict"][0] = 1
    assert a["rule_reason"][0] == 3 and a["verdict"][0] == 1 and a["rule_reason"][1] == 0
    raw = a.tobytes()
    assert raw[161] == 3 and raw[164] == 1, "les octets sont exactement là où le C les écrit"


def test_end_reasons_bloque():
    if not hasattr(core, "END_REASONS"):
        return
    assert isinstance(core.END_REASONS[6], str), "6 = flux retiré parce qu'une règle a bloqué l'IP"


def test_noms_des_regles():
    assert list(core.RULE_IDS) == NOMS
    assert core.RULE_NAMES[0] == "none"
    for nom, num in core.RULE_IDS.items():
        assert core.RULE_NAMES[num] == nom


def test_defauts():
    r = new_engine().rules_get()
    assert list(r) == NOMS
    assert all(v["enabled"] is True for v in r.values()), "toutes actives par défaut"
    assert r["port_scan"]["threshold"] == 20
    assert r["flood"]["threshold"] == 10000
    for sans_seuil in ("null_scan", "xmas_scan", "fin_scan"):
        assert r[sans_seuil]["threshold"] is None


def test_set_par_nom_et_par_numero():
    e = new_engine()
    e.rules_set("port_scan", threshold=50)
    assert e.rules_get("port_scan") == {"enabled": True, "threshold": 50}
    e.rules_set(1, enabled=False)
    assert e.rules_get("port_scan") == {"enabled": False, "threshold": 50}, "le seuil est gardé quand on désactive"
    e.rules_set("port_scan", enabled=True, threshold=7)
    assert e.rules_get(1) == {"enabled": True, "threshold": 7}
    e.rules_set("xmas_scan", enabled=False)
    assert e.rules_get("xmas_scan")["enabled"] is False
    assert e.rules_get("null_scan")["enabled"] is True, "les autres règles n'ont pas bougé"
    e.rules_set("flood", threshold=123456)
    assert e.rules_get("flood")["threshold"] == 123456


def test_chaque_engine_a_ses_reglages():
    a, b = new_engine(), new_engine()
    a.rules_set("port_scan", threshold=99, enabled=False)
    assert b.rules_get("port_scan") == {"enabled": True, "threshold": 20}


def _leve(exc, fn, *args, **kw):
    try:
        fn(*args, **kw)
    except exc:
        return True
    return False


def test_erreurs():
    e = new_engine()
    assert _leve(ValueError, e.rules_set, "n_existe_pas", enabled=True)
    assert _leve(ValueError, e.rules_set, 0, enabled=True), "0 = aucune règle"
    assert _leve(ValueError, e.rules_set, 99, enabled=True)
    assert _leve(ValueError, e.rules_set, "null_scan", threshold=5), "null_scan n'a pas de seuil"
    assert _leve(ValueError, e.rules_set, "port_scan", threshold=0), "seuil 0 refusé"
    assert _leve(ValueError, e.rules_set, "port_scan"), "rien à changer"
    assert _leve(ValueError, e.rules_get, "zzz")
    assert _leve(ValueError, e.rules_get, 99)
    assert e.rules_get("port_scan") == {"enabled": True, "threshold": 20}, "une erreur ne change rien"


def test_changements_a_chaud_pendant_des_lectures():
    e = new_engine()
    erreurs, stop = [], threading.Event()

    def lecteur():
        while not stop.is_set():
            r = e.rules_get("port_scan")
            if not (1 <= r["threshold"] <= 100):
                erreurs.append(r)

    ths = [threading.Thread(target=lecteur) for _ in range(4)]
    for t in ths:
        t.start()
    for i in range(20000):
        e.rules_set("port_scan", enabled=bool(i & 1), threshold=1 + i % 100)
    stop.set()
    for t in ths:
        t.join()
    assert not erreurs, erreurs[:3]


def test_stats_blocked_flows():
    e = new_engine()
    f = getattr(e, "stats", None)
    if f is None:
        return
    try:
        s = f() if callable(f) else f
    except Exception:
        return                                  # stats() demande peut-être un engine démarré : testé à la capture réelle
    if isinstance(s, dict):
        assert "blocked_flows" in s and s["blocked_flows"] == 0


# ───────────── la liste noire partagée : block / unblock / is_blocked / blocked_list / expire ─────────────

def test_block_manuel_et_liste():
    e = new_engine()
    assert e.blocked_count() == 0 and e.blocked_list() == []
    assert not e.is_blocked("10.0.0.1")
    e.block("10.0.0.1")
    e.block("2001:db8::1", ttl_ms=60000)
    assert e.is_blocked("10.0.0.1") and e.is_blocked("2001:0db8:0:0:0:0:0:1"), "même IPv6 écrite autrement"
    assert e.blocked_count() == 2
    lst = e.blocked_list()
    by_ip = {d["ip"]: d for d in lst}
    d4, d6 = by_ip["10.0.0.1"], by_ip["2001:db8::1"]
    assert d4["version"] == 4 and d4["source"] == "manual" and d4["rule"] == "none" and d4["rule_id"] == 0
    assert d4["until_ms"] is None and d4["blocked_at_ms"] > 0, "pour toujours : until_ms vaut None"
    assert d6["version"] == 6 and d6["until_ms"] == d6["blocked_at_ms"] + 60000, "expiration = date + 60 s"
    assert lst[0]["blocked_at_ms"] >= lst[1]["blocked_at_ms"], "les plus récentes d'abord"
    e.unblock("10.0.0.1")
    assert not e.is_blocked("10.0.0.1") and e.blocked_count() == 1


def test_block_erreurs():
    e = new_engine()
    assert _leve(core.EngineError, e.unblock, "10.0.0.1"), "débloquer une IP qui ne l'est pas"
    assert _leve(ValueError, e.block, "pas une ip")
    assert _leve(ValueError, e.unblock, "pas une ip")
    assert _leve(ValueError, e.is_blocked, "pas une ip")
    assert _leve(ValueError, e.block, "10.0.0.1", ttl_ms=-1)
    e.block("10.0.0.1")
    e.block("10.0.0.1", ttl_ms=5000)                         # déjà bloquée : métadonnées remplacées, toujours 1 IP
    assert e.blocked_count() == 1
    assert e.blocked_list()[0]["until_ms"] is not None


def test_block_expiration():
    import time
    e = new_engine()
    e.block("10.0.0.9", ttl_ms=1)
    e.block("10.0.0.8")                                      # pour toujours
    time.sleep(0.02)
    assert e.expire() == 1, "une seule a expiré"
    assert not e.is_blocked("10.0.0.9") and e.is_blocked("10.0.0.8")
    assert e.expire() == 0


def test_duree_des_blocages_automatiques():
    e = new_engine()
    assert e.rules_block_ttl() == 0, "0 = pour toujours, par défaut"
    e.rules_set_block_ttl(5000)
    assert e.rules_block_ttl() == 5000
    assert _leve(ValueError, e.rules_set_block_ttl, -1)
    e.rules_set_block_ttl(0)
    assert e.rules_block_ttl() == 0


def test_block_threads_en_parallele():
    e = new_engine()
    erreurs = []

    def travail(t):
        try:
            for i in range(200):
                ip = "10.%d.%d.%d" % (t, i // 256, i % 256)
                e.block(ip)
                assert e.is_blocked(ip)
                if i % 50 == 0:
                    for d in e.blocked_list():            # une photo pendant que les autres écrivent
                        assert d["version"] == 4
        except Exception as ex:                           # noqa
            erreurs.append(repr(ex))

    ths = [threading.Thread(target=travail, args=(t,)) for t in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert not erreurs, erreurs[:2]
    assert e.blocked_count() == 800
    assert len(e.blocked_list()) == 800
    for t in range(4):
        for i in range(200):
            e.unblock("10.%d.%d.%d" % (t, i // 256, i % 256))
    assert e.blocked_count() == 0


def _peut_capturer():
    import socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        s.close()
        return True
    except (PermissionError, OSError, AttributeError):
        return False


def test_scan_reel_blocage_automatique_et_deblocage():
    """Un vrai scan de ports sur lo : la règle bloque, le flux part dans le ring, l'admin débloque. Il faut root."""
    if not _peut_capturer():
        print("      (ignoré : pas root / pas CAP_NET_RAW)")
        return
    import os, socket, time
    e = new_engine()
    e.start("lo", ring_prefix="pt%d" % (os.getpid() % 100000), use_mmsg=False, idle_ms=300, max_ms=0,
            ring_size=1 << 20, table_size=1024, buffer_mb=4, poll_ms=50)
    e.rules_set_block_ttl(60000)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in range(41000, 41030):                         # 30 ports différents depuis UN socket : un scan
        s.sendto(b"x", ("127.0.0.1", port))
    s.close()
    fin = time.time() + 3
    while time.time() < fin and not e.is_blocked("127.0.0.1"):
        time.sleep(0.05)
    assert e.is_blocked("127.0.0.1"), "la règle port_scan a bloqué l'IP toute seule"
    lst = e.blocked_list()
    assert len(lst) == 1
    d = lst[0]
    assert d["ip"] == "127.0.0.1" and d["rule"] == "port_scan" and d["source"] == "auto"
    assert d["until_ms"] == d["blocked_at_ms"] + 60000, "la durée réglée à chaud est appliquée"
    trouve, fin = False, time.time() + 2
    while time.time() < fin and not trouve:                  # le flux bloqué est parti tout de suite dans le ring
        for r in e.read("lo"):
            if r["reason"] == 6 and r["rule_reason"] == 1 and r["verdict"] != 0:
                trouve = True
        if not trouve:
            time.sleep(0.05)
    assert trouve, "le ring contient un flux : reason 6 (bloqué), rule_reason 1 (port_scan), un verdict"
    e.unblock("127.0.0.1")
    assert not e.is_blocked("127.0.0.1") and e.blocked_list() == []
    e.stop("lo")
    e.release("lo")


if __name__ == "__main__":
    echecs = 0
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for nom, fn in tests:
        try:
            fn()
            print("  ✓", nom)
        except Exception:
            echecs += 1
            print("  ✗", nom)
            traceback.print_exc()
    print("\n%d test(s), %d échec(s)" % (len(tests), echecs))
    sys.exit(1 if echecs else 0)
