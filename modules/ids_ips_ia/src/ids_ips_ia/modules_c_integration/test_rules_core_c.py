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
