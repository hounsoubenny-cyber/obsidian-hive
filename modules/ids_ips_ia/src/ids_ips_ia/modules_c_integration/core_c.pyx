# cython: language_level=3
"""ids_engine : la porte d'entrée Python du moteur de capture C.

    import ids_engine
    with ids_engine.Engine() as eng:
        eng.start("eth0", idle_ms=30000)
        flows = eng.read("eth0")          # tableau numpy : un flux par ligne
        print(eng.stats("eth0"))
        eng.stop("eth0")                  # envoie les derniers flux au ring
        flows = eng.read("eth0")          # on finit de vider
        eng.release("eth0")               # supprime le ring

Il faut root ou CAP_NET_RAW pour capturer.
"""
import ipaddress
import numpy as np
from libc.stdint cimport uint8_t, uint32_t, uint64_t

cdef extern from "../modules_c/engine/engine.h":
    ctypedef struct FlowRecord:
        pass
    cdef int ENGINE_MAX_CAPTURES
    cdef int IGNORE_SRC
    cdef int IGNORE_DST
    cdef int IGNORE_BOTH
    ctypedef struct CEngine "Engine":       # le type C s'appelle Engine ; en Cython on le nomme CEngine (la classe Python prend « Engine »)
        pass
    struct EngineConfig:
        const char *ifname
        const char *ring_prefix
        int use_mmsg
        int promisc
        uint32_t buffer_mb
        uint32_t table_size
        uint64_t idle_ms
        uint64_t max_ms
        int close_on_tcp_end
        int scan_rule
        uint64_t ring_size
        uint32_t batch_size
        uint32_t max_turns
        int poll_ms
    struct EngineStats:
        char ifname[32]
        char ring_name[64]
        int state
        uint64_t frames_in
        uint64_t frames_ok
        uint64_t frames_failed
        uint64_t frames_ignored
        uint64_t blocked_pkts
        uint64_t flows_exported
        uint64_t flows_lost
        uint64_t flows_evicted
        uint64_t kernel_recv
        uint64_t kernel_drop
        uint64_t active_flows
        uint64_t ring_size
        uint64_t ring_used
        uint64_t ring_free
        uint64_t ring_n_read;
        uint64_t ring_n_write;
        uint64_t ring_dropped
        uint64_t blocked_flows

    void engine_config_default(EngineConfig *cfg)
    uint32_t engine_record_size()
    const char *engine_last_error()
    CEngine *engine_create()
    void engine_destroy(CEngine *e) nogil
    int engine_start(CEngine *e, const EngineConfig *cfg) nogil
    int engine_stop(CEngine *e, const char *ifname) nogil
    int engine_release(CEngine *e, const char *ifname) nogil
    int engine_read(CEngine *e, const char *ifname, FlowRecord *out, int max) nogil
    int engine_stats(CEngine *e, const char *ifname, EngineStats *out) nogil
    int engine_list(CEngine *e, EngineStats *out, int max) nogil
    int engine_ring_name(CEngine *e, const char *ifname, char *out, size_t size) nogil
    int engine_ignore_add(CEngine *e, const char *ip, int which) nogil
    int engine_ignore_remove(CEngine *e, const char *ip, int which) nogil
    int engine_ignore_contains(CEngine *e, const char *ip, int which) nogil
    uint32_t engine_ignore_count(CEngine *e, int which) nogil
    int engine_rules_set_enabled(CEngine *e, int rule, int enabled) nogil
    int engine_rules_set_threshold(CEngine *e, int rule, uint32_t threshold) nogil
    int engine_rules_get(CEngine *e, int rule, int *enabled, uint32_t *threshold) nogil


class EngineError(RuntimeError):
    """Une erreur renvoyée par le moteur C (le message vient de engine_last_error)."""


STATES = {0: "libre", 1: "en cours", 2: "arrêtée", 3: "en erreur"}
END_REASONS = {1: "inactif", 2: "tcp-fini", 3: "chassé", 4: "arrêt", 5: "durée-max", 6: "bloqué"}
IGNORE = {"src": IGNORE_SRC, "dst": IGNORE_DST, "both": IGNORE_BOTH}

# Un flux dans le ring = 176 octets. Les positions viennent de sizeof / offsetof mesurés sur flow.h et flow_table.h.
# Pour une clé, un en-tête v4 ou v6 : on garde les octets bruts (key, hdr) ; flow_addresses() les décode.
FLOW_DTYPE = np.dtype({
    "names": [
        "key", "v4", "hdr", "start_time", "end_time",
        "rst", "syn", "ack", "fin", "urg", "cwr", "ece", "psh",
        "n_pkt_ltr", "n_pkt_rtl", "octets_ltr", "octets_rtl", "proto", "verdict", "reason"
    ],
    "formats": [
        "(44,)u1", "u1", "(36,)u1", "<u8", "<u8",
        "<u4", "<u4", "<u4", "<u4", "<u4", "<u4", "<u4", "<u4",
        "<u4", "<u4", "<u8", "<u8", "u1", "<u4", "<u4"
    ],
    "offsets": [
        0, 48, 49, 88, 96,
        104, 108, 112, 116, 120, 124, 128, 132,
        136, 140, 144, 152, 160, 164, 168
    ],
    "itemsize": 176,
})

# rule_reason : la règle qui a donné le verdict (octet 161, dans le remplissage : la taille reste 176)
import numpy as _np_rule
if "rule_reason" not in FLOW_DTYPE.names:
    _fields = [(_n, FLOW_DTYPE.fields[_n][0], FLOW_DTYPE.fields[_n][1]) for _n in FLOW_DTYPE.names]
    _fields.append(("rule_reason", _np_rule.dtype("u1"), 161))
    _fields.sort(key=lambda _f: _f[2])
    FLOW_DTYPE = _np_rule.dtype({
        "names": [_f[0] for _f in _fields],
        "formats": [_f[1] for _f in _fields],
        "offsets": [_f[2] for _f in _fields],
        "itemsize": FLOW_DTYPE.itemsize,
    })


def _b(text):
    return text.encode() if isinstance(text, str) else bytes(text)


def _check(rc):
    if rc < 0:
        raise EngineError(engine_last_error().decode(errors="replace"))
    return rc


def flow_addresses(rec):
    """(initiateur, port, receveur, port) d'UN flux (une ligne du tableau) sous forme de texte et d'entiers."""
    hdr = bytes(rec["hdr"])
    if rec["v4"]:
        ini, pi, rec_ip, pr = hdr[0:4], hdr[4:6], hdr[6:10], hdr[10:12]
        make = ipaddress.IPv4Address
    else:
        ini, pi, rec_ip, pr = hdr[0:16], hdr[16:18], hdr[18:34], hdr[34:36]
        make = ipaddress.IPv6Address
    return (str(make(ini)), int.from_bytes(pi, "big"), str(make(rec_ip)), int.from_bytes(pr, "big"))


# ───── réglages des règles (à chaud) ─────
RULE_IDS = {
    "port_scan": 1, 
    "null_scan": 2, 
    "xmas_scan": 3, 
    "fin_scan": 4, 
    "flood": 5
}
RULE_NAMES = {
    0: "none",
    1: "port_scan",
    2: "null_scan", 
    3: "xmas_scan", 
    4: "fin_scan",
    5: "flood"
}   # valeur de FlowData.rule_reason

def _rule_id(rule):
    if isinstance(rule, str):
        if rule not in RULE_IDS:
            raise ValueError("règle inconnue : %r (attendu : %s)" % (rule, ", ".join(RULE_IDS)))
        return RULE_IDS[rule]
    return int(rule)

cdef str _rules_last_error():
    cdef const char *msg = engine_last_error()
    if msg == NULL:
        return "erreur inconnue"
    return msg.decode("utf-8", "replace")

cdef class Engine:
    """Le moteur. Une interface = une thread de capture = un ring. Plusieurs threads Python peuvent l'utiliser."""
    cdef CEngine *_e

    def __cinit__(self):
        if engine_record_size() != FLOW_DTYPE.itemsize:
            raise EngineError(
                "FLOW_DTYPE (%d octets) ne correspond plus à FlowRecord (%d octets) : le .pyx est à mettre à jour"
                % (FLOW_DTYPE.itemsize, engine_record_size())
            )
        self._e = engine_create()
        if self._e == NULL:
            raise EngineError(engine_last_error().decode(errors="replace"))

    def __dealloc__(self):
        if self._e != NULL:
            with nogil:
                engine_destroy(self._e)
            self._e = NULL

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        """Arrête toutes les captures et supprime tous les rings."""
        if self._e != NULL:
            with nogil:
                engine_destroy(self._e)
            self._e = NULL

    cdef void _alive(self) except *:
        if self._e == NULL:
            raise EngineError("le moteur est fermé")

    def start(
        self, 
        ifname, 
        *, 
        ring_prefix="ids",
        use_mmsg=True, promisc=False, 
        buffer_mb=16, table_size=65536,
        idle_ms=30000, max_ms=300000,
        close_on_tcp_end=True, scan_rule=True,
        ring_size=16 << 20,
        batch_size=64, max_turns=16, poll_ms=200
    ):
        """Démarre la capture d'une interface. Les erreurs (droits, interface inconnue...) sont levées ICI."""
        self._alive()
        cdef EngineConfig cfg
        cdef bytes b_if = _b(ifname)
        cdef bytes b_pre = _b(ring_prefix)
        engine_config_default(&cfg)
        cfg.ifname = b_if
        cfg.ring_prefix = b_pre
        cfg.use_mmsg = 1 if use_mmsg else 0
        cfg.promisc = 1 if promisc else 0
        cfg.buffer_mb = buffer_mb
        cfg.table_size = table_size
        cfg.idle_ms = idle_ms
        cfg.max_ms = max_ms
        cfg.close_on_tcp_end = 1 if close_on_tcp_end else 0
        cfg.scan_rule = 1 if scan_rule else 0
        cfg.ring_size = ring_size
        cfg.batch_size = batch_size
        cfg.max_turns = max_turns
        cfg.poll_ms = poll_ms
        cdef int rc
        with nogil:
            rc = engine_start(self._e, &cfg)
        _check(rc)

    def stop(self, ifname):
        """Arrête la capture ; les flux restants sont envoyés au ring, qui reste lisible."""
        self._alive()
        cdef bytes b = _b(ifname)
        cdef const char *cname = b
        cdef int rc
        with nogil:                                  # peut attendre jusqu'à poll_ms : on libère Python pendant ce temps
            rc = engine_stop(self._e, cname)
        _check(rc)

    def release(self, ifname):
        """Ferme et SUPPRIME le ring d'une capture arrêtée."""
        self._alive()
        cdef bytes b = _b(ifname)
        cdef const char *cname = b
        cdef int rc
        with nogil:
            rc = engine_release(self._e, cname)
        _check(rc)

    def read(self, ifname, max=4096):
        """Lit au plus `max` flux dans le ring : tableau numpy de dtype FLOW_DTYPE (vide s'il n'y a rien)."""
        self._alive()
        cdef bytes b = _b(ifname)
        if max < 0:
            raise ValueError("max doit être >= 0")
        arr = np.empty(max, dtype=FLOW_DTYPE)
        cdef unsigned char[::1] raw = arr.view(np.uint8) if max > 0 else np.empty(1, dtype=np.uint8)
        cdef const char *cname = b
        cdef int n
        cdef int cmax = max
        with nogil:
            n = engine_read(self._e, cname, <FlowRecord *>&raw[0], cmax)
        _check(n)
        return arr[:n].copy() if n < max else arr

    def stats(self, ifname):
        """Un dictionnaire de compteurs pour une interface."""
        self._alive()
        cdef bytes b = _b(ifname)
        cdef EngineStats st
        cdef const char *cname = b
        cdef int rc
        with nogil:
            rc = engine_stats(self._e, cname, &st)
        _check(rc)
        return _stats_dict(&st)

    def list(self):
        """La liste des captures présentes (un dictionnaire de compteurs chacune)."""
        self._alive()
        cdef EngineStats buf[16]
        cdef int n
        with nogil:
            n = engine_list(self._e, buf, 16)
        _check(n)
        return [_stats_dict(&buf[i]) for i in range(min(n, 16))]

    def ring_name(self, ifname):
        """Le nom du segment dans /dev/shm (pour lire le ring soi-même)."""
        self._alive()
        cdef bytes b = _b(ifname)
        cdef char out[64]
        _check(engine_ring_name(self._e, b, out, 64))
        return out.decode()

    def ignore_add(self, ip, which="both"):
        """Ne plus suivre cette IP. which : "src", "dst" ou "both"."""
        self._alive()
        ip = str(ipaddress.ip_address(ip))           # valide et normalise le texte
        cdef bytes b = _b(ip)
        _check(engine_ignore_add(self._e, b, IGNORE[which]))

    def ignore_remove(self, ip, which="both"):
        self._alive()
        ip = str(ipaddress.ip_address(ip))
        cdef bytes b = _b(ip)
        _check(engine_ignore_remove(self._e, b, IGNORE[which]))

    def ignore_contains(self, ip, which="both"):
        self._alive()
        cdef bytes b = _b(str(ipaddress.ip_address(ip)))
        return engine_ignore_contains(self._e, b, IGNORE[which]) == 1

    def ignore_count(self, which="src"):
        self._alive()
        return engine_ignore_count(self._e, IGNORE[which])

    def rules_set(self, rule, enabled=None, threshold=None):
        """Change une règle À CHAUD : effet au paquet suivant, la capture continue.
        rule : nom ("port_scan", "null_scan", "xmas_scan", "fin_scan", "flood") ou numéro (1 à 5).
        enabled : True / False · threshold : port_scan = nombre de ports distincts, flood = paquets par seconde
        (les autres règles n'ont pas de seuil). ValueError si la règle est inconnue, sans seuil, ou si le seuil est < 1.
        Désactiver une règle ne débloque pas les IP qu'elle a déjà bloquées."""
        cdef int r
        cdef int rc
        cdef uint32_t th
        if self._e == NULL:
            raise RuntimeError("engine détruit")
        if enabled is None and threshold is None:
            raise ValueError("rien à changer : donne enabled et/ou threshold")
        r = _rule_id(rule)
        if threshold is not None:
            if int(threshold) < 1 or int(threshold) > 4294967295:
                raise ValueError("le seuil doit être entre 1 et 4294967295")
            th = <uint32_t>int(threshold)
            rc = engine_rules_set_threshold(self._e, r, th)
            if rc != 0:
                raise ValueError(_rules_last_error())
        if enabled is not None:
            rc = engine_rules_set_enabled(self._e, r, 1 if enabled else 0)
            if rc != 0:
                raise ValueError(_rules_last_error())

    def rules_get(self, rule=None):
        """Lit les réglages. Sans argument : {nom: {"enabled": bool, "threshold": int ou None}} pour toutes les règles.
        Avec une règle (nom ou numéro) : seulement son dict. threshold vaut None pour les règles sans seuil."""
        cdef int r
        cdef int en
        cdef uint32_t th
        if self._e == NULL:
            raise RuntimeError("engine détruit")
        if rule is None:
            out = {}
            for name in RULE_IDS:
                out[name] = self.rules_get(name)
            return out
        r = _rule_id(rule)
        en = 0
        th = 0
        if engine_rules_get(self._e, r, &en, &th) != 0:
            raise ValueError(_rules_last_error())
        return {"enabled": bool(en), "threshold": int(th) if th != 0 else None}


cdef dict _stats_dict(EngineStats *st):
    return {
        "ifname": st.ifname.decode(), "ring_name": st.ring_name.decode(),
        "state": STATES.get(st.state, "?"), "state_code": st.state,
        "frames_in": st.frames_in, "frames_ok": st.frames_ok, "frames_failed": st.frames_failed,
        "frames_ignored": st.frames_ignored, "blocked_pkts": st.blocked_pkts,
        "flows_exported": st.flows_exported, "flows_lost": st.flows_lost, "flows_evicted": st.flows_evicted,
        "kernel_recv": st.kernel_recv, "kernel_drop": st.kernel_drop, "active_flows": st.active_flows,
        "ring_size": st.ring_size, "ring_used": st.ring_used, "ring_free": st.ring_free,
        "ring_n_read": st.ring_n_read, "ring_n_write": st.ring_n_write, "ring_dropped": st.ring_dropped, "blocked_flows": st.blocked_flows,
    }
