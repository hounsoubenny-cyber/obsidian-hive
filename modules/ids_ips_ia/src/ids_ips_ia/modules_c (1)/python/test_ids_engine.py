"""Test de bout en bout, depuis Python : capture réelle sur « lo » (il faut root ou CAP_NET_RAW).
    cd python && python3 setup.py build_ext --inplace && sudo python3 test_ids_engine.py
Chaque test affiche OK ou lève une AssertionError. """
import os, socket, threading, time
import numpy as np
import ids_engine
from ids_engine import Engine, EngineError, FLOW_DTYPE, flow_addresses

PREFIX = "py%d" % (os.getpid() % 100000)


def send_udp(port, n=10, payload=20):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(n):
        s.sendto(b"\0" * payload, ("127.0.0.1", port))
    s.close()


def sink(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    return s


def read_until(eng, ifname, want, timeout=5.0):
    out, t0 = [], time.time()
    while sum(len(a) for a in out) < want and time.time() - t0 < timeout:
        a = eng.read(ifname)
        if len(a):
            out.append(a)
        else:
            time.sleep(0.05)
    return np.concatenate(out) if out else np.empty(0, dtype=FLOW_DTYPE)


def test_dtype():
    assert FLOW_DTYPE.itemsize == 176
    print("OK  dtype : 176 octets, identique à sizeof(FlowRecord) (vérifié aussi à la création du moteur)")


def test_erreurs():
    with Engine() as eng:
        for bad in ["interface_inconnue0", "a/b", ""]:
            try:
                eng.start(bad)
                assert False, "aurait dû lever"
            except EngineError as e:
                assert len(str(e)) > 5
        try:
            eng.stop("lo")
            assert False
        except EngineError as e:
            assert "aucune capture" in str(e)
        try:
            eng.ignore_add("pas une ip")
            assert False
        except ValueError:
            pass
    print("OK  erreurs : interface inconnue, nom invalide, stop sans capture, IP invalide → exceptions Python claires")


def test_cycle_et_lecture():
    with Engine() as eng:
        eng.start("lo", ring_prefix=PREFIX, idle_ms=300, max_ms=0, ring_size=1 << 20, poll_ms=50)
        name = eng.ring_name("lo")
        assert name == "/%s_lo" % PREFIX and os.path.exists("/dev/shm" + name)
        s = sink(44001)
        send_udp(44001, n=10)
        flows = read_until(eng, "lo", 1)
        assert len(flows) >= 1, "aucun flux reçu"
        mine = [f for f in flows if f["proto"] == 17 and flow_addresses(f)[3] == 44001]
        assert mine, "le flux UDP vers 44001 manque"
        f = mine[0]
        ini, pi, rec, pr = flow_addresses(f)
        assert ini == "127.0.0.1" and rec == "127.0.0.1" and pr == 44001 and pi != 44001
        assert f["v4"] == 1 and f["n_pkt_ltr"] >= 10 and f["octets_ltr"] >= 620
        assert f["reason"] == 1 and ids_engine.END_REASONS[int(f["reason"])] == "inactif"
        assert f["start_time"] > 1_700_000_000_000 and f["end_time"] >= f["start_time"]
        st = eng.stats("lo")
        assert st["state"] == "en cours" and st["frames_in"] >= 10 and st["flows_lost"] == 0
        assert [d["ifname"] for d in eng.list()] == ["lo"]

        send_udp(44001, n=3)                         # un flux encore vivant quand on arrête
        time.sleep(0.2)
        eng.stop("lo")
        assert eng.stats("lo")["state"] == "arrêtée"
        rest = read_until(eng, "lo", 1, timeout=2)
        assert len(rest) >= 1 and rest[0]["reason"] == 4, "l'arrêt doit envoyer les flux restants (raison : arrêt)"
        assert len(eng.read("lo")) == 0
        eng.release("lo")
        assert not os.path.exists("/dev/shm" + name)
        s.close()
    print("OK  cycle complet : start, ring dans /dev/shm, lecture numpy, stats, stop + flush, release")


def test_ignore():
    with Engine() as eng:
        eng.start("lo", ring_prefix=PREFIX, idle_ms=0, max_ms=0, ring_size=1 << 20, poll_ms=50)
        s = sink(44002)
        eng.ignore_add("127.0.0.1", "src")
        assert eng.ignore_contains("127.0.0.1", "src") and not eng.ignore_contains("127.0.0.1", "dst")
        send_udp(44002, n=10)
        time.sleep(0.4)
        st = eng.stats("lo")
        assert st["frames_ignored"] >= 10 and st["frames_ok"] == 0 and st["active_flows"] == 0
        eng.ignore_remove("127.0.0.1", "src")
        assert eng.ignore_count("src") == 0
        send_udp(44002, n=10)
        time.sleep(0.4)
        assert eng.stats("lo")["frames_ok"] >= 10
        s.close()
    print("OK  listes d'IP : ignorer en source, retirer, la capture continue")


def test_ring_plein():
    with Engine() as eng:
        eng.start("lo", ring_prefix=PREFIX, idle_ms=200, ring_size=256 + 176 * 3, poll_ms=50)
        s = sink(44003)
        for _ in range(15):
            send_udp(44003, n=2)
        time.sleep(1.0)
        st = eng.stats("lo")
        assert st["flows_exported"] == 3 and st["flows_lost"] >= 12
        before = st["frames_in"]
        send_udp(44003, n=10)
        time.sleep(0.3)
        assert eng.stats("lo")["frames_in"] > before, "un ring plein ne doit jamais bloquer la capture"
        assert len(eng.read("lo")) == 3
        s.close()
    print("OK  ring plein : 3 flux gardés, le reste compté comme perdu, la capture continue")


def test_threads_python():
    with Engine() as eng:
        eng.start("lo", ring_prefix=PREFIX, idle_ms=100, poll_ms=50)
        s = sink(44004)
        errors, stop = [], threading.Event()

        def hammer():
            try:
                while not stop.is_set():
                    eng.stats("lo"); eng.list(); eng.read("lo", 16)
                    eng.ignore_add("10.1.1.1"); eng.ignore_remove("10.1.1.1")
            except Exception as e:                   # noqa
                errors.append(e)

        ths = [threading.Thread(target=hammer) for _ in range(4)]
        [t.start() for t in ths]
        for _ in range(30):
            send_udp(44004, n=20)
            time.sleep(0.02)
        stop.set()
        [t.join() for t in ths]
        assert not errors, errors
        s.close()
    print("OK  4 threads Python appellent le moteur pendant le trafic : aucune erreur")


def test_fermeture():
    eng = Engine()
    eng.start("lo", ring_prefix=PREFIX)
    name = eng.ring_name("lo")
    eng.close()
    assert not os.path.exists("/dev/shm" + name), "close() doit tout arrêter et supprimer le ring"
    try:
        eng.stats("lo")
        assert False
    except EngineError as e:
        assert "fermé" in str(e)
    print("OK  close() : arrête tout, supprime le ring, le moteur refuse ensuite les appels")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Il faut root (ou CAP_NET_RAW) pour capturer."); raise SystemExit(1)
    for t in [test_dtype, test_erreurs, test_cycle_et_lecture, test_ignore, test_ring_plein, test_threads_python, test_fermeture]:
        t()
    print("\nTout est OK.")
