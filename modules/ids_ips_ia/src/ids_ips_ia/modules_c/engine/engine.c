#define _GNU_SOURCE
#include "engine.h"
#include "../capture/capture.h"
#include "../mmap_ring/mmap_ring.h"
#include "../ipset/ipset.h"
#include "../parser/parser.h"
#include "../flows/flow_table.h"
#include "../rules/rules.h"
#include "../utils/utils.h"
#include <arpa/inet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═════════════════════ erreurs : une phrase par thread ═════════════════════ */

static _Thread_local char g_err[256];

static int _fail(const char *fmt, ...){                 /* note le message et retourne -1 : « return _fail(...); » */
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof(g_err), fmt, ap); // comme snprintf mais prend un va_list(args variadiques)
    va_end(ap);
    return -1;
}

const char *engine_last_error(void){
    return g_err;
}

/* ═════════════════════ les structures internes ═════════════════════ */

struct Counters{                                        /* écrits par la thread de capture, lus par Python : donc atomiques */
    _Atomic uint64_t frames_in, frames_ok, frames_failed, frames_ignored, blocked_pkts, blocked_flows;
    _Atomic uint64_t flows_exported, flows_lost, flows_evicted, active_flows;
    _Atomic uint64_t kernel_recv, kernel_drop;
};

struct Slot{                                            /* une capture = une case du tableau de l'Engine */
    int state;                                          /* ENGINE_SLOT_FREE / RUNNING / STOPPED, sous le verrou de l'Engine */
    Engine *eng;
    struct EngineConfig cfg;                            /* copie : Python peut libérer ses chaînes dès le retour de engine_start */
    char ifname[ENGINE_IFNAME_MAX];
    char prefix[16];
    char ring_name[ENGINE_RING_NAME_MAX];
    Capture *cap;
    FlowTable *ft;
    Ring *ring;
    pthread_t thread;
    _Atomic uint8_t stop;                               /* levé par engine_stop ; lu par la boucle de capture */
    _Atomic int failed;                                 /* 1 = la thread s'est arrêtée toute seule sur une erreur */
    struct Counters c;
};

struct Engine{
    pthread_mutex_t lock;                               /* protège le tableau des captures (démarrer, arrêter, lire, stats) */
    IpSet *ign_src, *ign_dst;                           /* partagées : la thread de capture ne fait que les LIRE, sans verrou */
    struct RulesConfig rules;                           /* partagés : champs atomiques, Python les change à chaud, les captures les lisent */
    struct Slot slots[ENGINE_MAX_CAPTURES];
};

/* Le filtre BPF : IPv4, IPv6, ARP, VLAN, QinQ. Le noyau jette le reste sans réveiller le programme. */
/*static struct sock_filter FILTER[] = {
    BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86DD, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0806, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8100, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88A8, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, 0),
    BPF_STMT(BPF_RET | BPF_K, 0x40000),
};*/

static struct sock_filter FILTER[] = {          // tcpdump -dd "tcp or udp or icmp or icmp6"
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 4, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 10, 0, 0x00000006 },
    { 0x15, 9, 0, 0x00000011 },
    { 0x15, 8, 9, 0x00000001 },
    { 0x15, 0, 8, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 5, 0, 0x00000006 },
    { 0x15, 0, 2, 0x0000002c },
    { 0x30, 0, 0, 0x00000036 },
    { 0x15, 2, 0, 0x00000006 },
    { 0x15, 1, 0, 0x00000011 },
    { 0x15, 0, 1, 0x0000003a },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

static inline void _bump(_Atomic uint64_t *c){
    atomic_fetch_add_explicit(c, 1, memory_order_relaxed);
}

static inline void _set(_Atomic uint64_t *c, uint64_t v){
    atomic_store_explicit(c, v, memory_order_relaxed);
}

static inline uint64_t _get(_Atomic uint64_t *c){
    return atomic_load_explicit(c, memory_order_relaxed);
}

/* ═════════════════════ ce que fait la thread de capture ═════════════════════ */

/* Copie dans des compteurs atomiques ce que seule cette thread a le droit de lire dans la table de flux */
static void _refresh(struct Slot *s){
    _set(&s -> c.active_flows, s -> ft -> nbr_elements);
    _set(&s -> c.flows_evicted, s -> ft -> n_evicted);
    _set(&s -> c.blocked_pkts, s -> ft -> n_blocked_pkts);
    _set(&s -> c.blocked_flows, s -> ft -> n_blocked_flows);
}

/* Appelée pour chaque trame : octets → fiche → (ignorée ?) → table de flux */
static void _on_frame(const uint8_t *frame, int len, void *ctx){
    struct Slot *s = ctx;
    _bump(&s -> c.frames_in);
    ParserResult pr = parse(frame, len);

    PacketTuple t;
    if (pr.code == (uint8_t)SUCCES && pr_tuple(&pr, &t) == 0){
        Engine *e = s -> eng;
        if (ipset_contains(e -> ign_src, t.src_ip, t.v4) || ipset_contains(e -> ign_dst, t.dst_ip, t.v4)){
            _bump(&s -> c.frames_ignored);              /* l'admin ne veut pas suivre cette IP */
            return;
        }
    }
    if (ft_process(s -> ft, &pr, realtime_ms()) == 0) _bump(&s -> c.frames_ok);
    else _bump(&s -> c.frames_failed);
    if ((_get(&s -> c.frames_in) & 1023) == 0) _refresh(s);   /* de temps en temps, pendant le trafic */
}

/* Appelée quand rien n'arrive (et régulièrement pendant le trafic) : le ménage de la table */
static void _on_idle(void *ctx){
    struct Slot *s = ctx;
    ft_expire(s -> ft, realtime_ms());
    _refresh(s);
}

/* Le sink : un flux quitte la table, on en écrit une copie à plat (176 octets) dans le ring */
static void _ring_sink(const FlowRecord *rec, void *ctx){
    struct Slot *s = ctx;
    if (ring_write(s -> ring, rec, sizeof(FlowRecord)) == 0) _bump(&s -> c.flows_exported);
    else _bump(&s -> c.flows_lost);                     /* ring plein : on perd ce flux, on ne bloque JAMAIS la capture */
}

static void *_worker(void *arg){
    struct Slot *s = arg;
    long long r;
    if (s -> cfg.use_mmsg){
        r = cap_recv_mmsg(
            s -> cap, CAP_MAX_FRAME, s -> cfg.poll_ms, 
            _on_frame, _on_idle, 10, s, &s -> stop,
            s -> cfg.batch_size, (uint16_t)s -> cfg.max_turns
        );
    } else {
        uint8_t *buf = malloc(CAP_MAX_FRAME);
        r = buf != NULL
            ? cap_recv(
                    s -> cap, buf, CAP_MAX_FRAME, s -> cfg.poll_ms, 
                    _on_frame, _on_idle, 10, s, &s -> stop
                )
            : -1;
        free(buf);
    }
    if (r < 0) atomic_store_explicit(&s -> failed, 1, memory_order_release);   /* la capture a rendu une erreur */
    return NULL;
}

/* ═════════════════════ outils ═════════════════════ */

static int _valid_name(const char *name, size_t max_len){   /* lettres, chiffres, . _ - : sûrs pour une interface ET pour un nom de segment */
    if (name == NULL || name[0] == '\0' || strlen(name) >= max_len) return 0;
    for (const char *p = name; *p; p++){
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              *p == '.' || *p == '_' || *p == '-')) return 0;
    }
    return 1;
}

static struct Slot *_find(Engine *e, const char *ifname){
    if (ifname == NULL) return NULL;
    for (int i = 0; i < ENGINE_MAX_CAPTURES; i++){
        if (e -> slots[i].state != ENGINE_SLOT_FREE && strcmp(e -> slots[i].ifname, ifname) == 0) return &e -> slots[i];
    }
    return NULL;
}

static int _state_of(struct Slot *s){
    if (s -> state == ENGINE_RUNNING && atomic_load_explicit(&s -> failed, memory_order_acquire)) return ENGINE_FAILED;
    return s -> state;
}

/* Lit, puis remet à zéro, les compteurs du noyau, et les additionne aux nôtres (le noyau les remet à 0 à chaque lecture) */
static void _collect_kernel(struct Slot *s){
    uint64_t r = 0, d = 0;
    if (s -> cap != NULL && cap_stats(s -> cap, &r, &d) == 0){
        _set(&s -> c.kernel_recv, _get(&s -> c.kernel_recv) + r);
        _set(&s -> c.kernel_drop, _get(&s -> c.kernel_drop) + d);
    }
}

static void _fill_stats(struct Slot *s, struct EngineStats *out){
    memset(out, 0, sizeof(*out));
    snprintf(out -> ifname, sizeof(out -> ifname), "%s", s -> ifname);
    snprintf(out -> ring_name, sizeof(out -> ring_name), "%s", s -> ring_name);
    out -> state = _state_of(s);
    if (s -> state == ENGINE_RUNNING) _collect_kernel(s);
    out -> frames_in = _get(&s -> c.frames_in);
    out -> frames_ok = _get(&s -> c.frames_ok);
    out -> frames_failed = _get(&s -> c.frames_failed);
    out -> frames_ignored = _get(&s -> c.frames_ignored);
    out -> blocked_pkts = _get(&s -> c.blocked_pkts);
    out -> blocked_flows = _get(&s -> c.blocked_flows);
    out -> flows_exported = _get(&s -> c.flows_exported);
    out -> flows_lost = _get(&s -> c.flows_lost);
    out -> flows_evicted = _get(&s -> c.flows_evicted);
    out -> kernel_recv = _get(&s -> c.kernel_recv);
    out -> kernel_drop = _get(&s -> c.kernel_drop);
    out -> active_flows = _get(&s -> c.active_flows);
    RingStats rs = ring_stats(s -> ring);
    if (stats_is_error(&rs) == 0){
        out -> ring_size = rs.size;
        out -> ring_used = rs.used;
        out -> ring_free = rs.free;
        out -> ring_n_write = rs.n_write;
        out -> ring_n_read = rs.n_read;
        out -> ring_dropped = rs.n_dropped;
    }
}

/* ═════════════════════ configuration, création ═════════════════════ */

void engine_config_default(struct EngineConfig *cfg){
    if (cfg == NULL) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg -> ring_prefix = "ids";
    cfg -> use_mmsg = 1;
    cfg -> buffer_mb = 16;
    cfg -> table_size = 65536;
    cfg -> idle_ms = 30000;                             /* 30 s */
    cfg -> max_ms = 300000;                             /* 5 min */
    cfg -> close_on_tcp_end = 1;
    cfg -> scan_rule = 1;
    cfg -> ring_size = 16u << 20;                       /* 16 Mio : environ 95 000 flux en attente */
    cfg -> batch_size = 64;
    cfg -> max_turns = 16;
    cfg -> poll_ms = 200;
}

uint32_t engine_record_size(void){
    return (uint32_t)sizeof(FlowRecord);
}

Engine *engine_create(void){
    Engine *e = calloc(1, sizeof(Engine));
    if (e == NULL){ _fail("mémoire insuffisante"); return NULL; }
    e -> ign_src = ipset_create(65536);
    e -> ign_dst = ipset_create(65536);
    if (e -> ign_src == NULL || e -> ign_dst == NULL){
        ipset_destroy(e -> ign_src);
        ipset_destroy(e -> ign_dst);
        free(e);
        _fail("mémoire insuffisante (listes d'IP)");
        return NULL;
    }
    rules_config_default(&e -> rules);
    pthread_mutex_init(&e -> lock, NULL);
    return e;
}

/* ═════════════════════ démarrer ═════════════════════ */

static void _free_resources(struct Slot *s){             /* défait ce que engine_start a construit (dans l'ordre inverse) */
    if (s -> cap != NULL){ cap_close(s -> cap); s -> cap = NULL; }
    if (s -> ft != NULL){ ft_destroy(s -> ft); s -> ft = NULL; }
    if (s -> ring != NULL){ ring_close(s -> ring); ring_destroy(s -> ring_name); s -> ring = NULL; }
}

int engine_start(Engine *e, const struct EngineConfig *cfg){
    if (e == NULL || cfg == NULL) return _fail("engine_start : argument NULL");
    if (!_valid_name(cfg -> ifname, ENGINE_IFNAME_MAX)) return _fail("nom d'interface invalide (lettres, chiffres, . _ - ; 31 caractères max)");
    const char *prefix = cfg -> ring_prefix != NULL ? cfg -> ring_prefix : "ids";
    if (!_valid_name(prefix, 16)) return _fail("ring_prefix invalide (lettres, chiffres, . _ - ; 15 caractères max)");
    if (if_nametoindex(cfg -> ifname) == 0) return _fail("l'interface '%s' n'existe pas", cfg -> ifname);
    if (cfg -> table_size < 16) return _fail("table_size trop petit (minimum 16)");
    if (cfg -> poll_ms < 1) return _fail("poll_ms doit être >= 1");
    if (cfg -> use_mmsg && (cfg -> batch_size == 0 || cfg -> max_turns == 0 || cfg -> max_turns > 65535))
        return _fail("batch_size et max_turns doivent être > 0 (max_turns <= 65535)");
    if (cfg -> buffer_mb == 0 || cfg -> buffer_mb > 2048) return _fail("buffer_mb doit être entre 1 et 2048");

    pthread_mutex_lock(&e -> lock);
    if (_find(e, cfg -> ifname) != NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("'%s' a déjà une capture (arrêtée ? appelle engine_release d'abord)", cfg -> ifname);
    }
    struct Slot *s = NULL;
    for (int i = 0; i < ENGINE_MAX_CAPTURES && s == NULL; i++){
        if (e -> slots[i].state == ENGINE_SLOT_FREE) s = &e -> slots[i];
    }
    if (s == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("trop de captures en même temps (maximum %d)", ENGINE_MAX_CAPTURES);
    }

    memset(s, 0, sizeof(*s));
    s -> eng = e;
    s -> cfg = *cfg;
    snprintf(s -> ifname, sizeof(s -> ifname), "%s", cfg -> ifname);
    snprintf(s -> prefix, sizeof(s -> prefix), "%s", prefix);
    s -> cfg.ifname = s -> ifname;                       /* nos propres copies : Python peut libérer les siennes */
    s -> cfg.ring_prefix = s -> prefix;
    snprintf(s -> ring_name, sizeof(s -> ring_name), "/%s_%s", s -> prefix, s -> ifname);

    /* 1) le ring. S'il en reste un d'un lancement précédent (arrêt brutal), on le remplace une fois. */
    s -> ring = rgm_open(s -> ring_name, cfg -> ring_size, 1);
    if (s -> ring == NULL){
        ring_destroy(s -> ring_name);
        s -> ring = rgm_open(s -> ring_name, cfg -> ring_size, 1);
    }
    if (s -> ring == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("impossible de créer le ring %s (ring_size trop petit ou trop grand, /dev/shm plein ?)", s -> ring_name);
    }

    /* 2) la table de flux, avec ses réglages : un flux qui part est écrit dans CE ring */
    struct FlowHooks h = {0};
    h.idle_ms = cfg -> idle_ms;
    h.max_ms = cfg -> max_ms;
    h.close_on_tcp_end = (uint8_t)(cfg -> close_on_tcp_end != 0);
    h.check = cfg -> scan_rule ? rules_check_all : NULL;
    h.rules_cfg = &e -> rules;                           /* vit autant que l'Engine, qui détruit les tables avant de se libérer */
    h.sink = _ring_sink;
    h.ctx = s;
    s -> ft = ft_create_with(cfg -> table_size, &h);
    if (s -> ft == NULL){
        _free_resources(s);
        pthread_mutex_unlock(&e -> lock);
        return _fail("impossible de créer la table de flux (table_size = %u)", cfg -> table_size);
    }

    /* 3) la capture (socket, filtre BPF, tampon) : c'est ici que « pas root » se voit */
    s -> cap = cap_open(s -> ifname, -1, cfg -> promisc != 0, (int)(cfg -> buffer_mb * 1024u * 1024u),
                        FILTER, (int)(sizeof(FILTER) / sizeof(FILTER[0])));
    if (s -> cap == NULL){
        _free_resources(s);
        pthread_mutex_unlock(&e -> lock);
        return _fail("cap_open('%s') a échoué : il faut root ou CAP_NET_RAW", s -> ifname);
    }

    /* 4) en dernier : la thread. Tout ce qui peut échouer l'a déjà fait, et on l'a dit à l'appelant. */
    if (pthread_create(&s -> thread, NULL, _worker, s) != 0){
        _free_resources(s);
        pthread_mutex_unlock(&e -> lock);
        return _fail("pthread_create a échoué");
    }
    s -> state = ENGINE_RUNNING;
    pthread_mutex_unlock(&e -> lock);
    return 0;
}

/* ═════════════════════ arrêter, libérer ═════════════════════ */

/* À appeler SOUS le verrou, sur une capture RUNNING */
static void _stop_locked(struct Slot *s){
    atomic_store_explicit(&s -> stop, 1, memory_order_release);
    pthread_join(s -> thread, NULL);                     /* la thread voit stop au plus tard après poll_ms */
    _collect_kernel(s);                                  /* dernières statistiques du noyau */
    cap_close(s -> cap);
    s -> cap = NULL;
    _refresh(s);
    ft_destroy(s -> ft);                                 /* envoie les flux restants au ring (raison : arrêt) */
    s -> ft = NULL;
    s -> c.active_flows = 0;
    s -> state = ENGINE_STOPPED;                         /* le ring reste lisible */
}

int engine_stop(Engine *e, const char *ifname){
    if (e == NULL) return _fail("engine_stop : engine NULL");
    pthread_mutex_lock(&e -> lock);
    struct Slot *s = _find(e, ifname);
    if (s == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("aucune capture sur '%s'", ifname != NULL ? ifname : "(NULL)");
    }
    if (s -> state != ENGINE_RUNNING){
        pthread_mutex_unlock(&e -> lock);
        return _fail("la capture sur '%s' est déjà arrêtée", ifname);
    }
    _stop_locked(s);
    pthread_mutex_unlock(&e -> lock);
    return 0;
}

static void _release_locked(struct Slot *s){
    ring_close(s -> ring);
    ring_destroy(s -> ring_name);                        /* supprime le segment de /dev/shm */
    memset(s, 0, sizeof(*s));                            /* state = FREE : la case est de nouveau libre */
}

int engine_release(Engine *e, const char *ifname){
    if (e == NULL) return _fail("engine_release : engine NULL");
    pthread_mutex_lock(&e -> lock);
    struct Slot *s = _find(e, ifname);
    if (s == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("aucune capture sur '%s'", ifname != NULL ? ifname : "(NULL)");
    }
    if (s -> state != ENGINE_STOPPED){
        pthread_mutex_unlock(&e -> lock);
        return _fail("la capture sur '%s' tourne encore : engine_stop d'abord", ifname);
    }
    _release_locked(s);
    pthread_mutex_unlock(&e -> lock);
    return 0;
}

void engine_destroy(Engine *e){
    if (e == NULL) return;
    pthread_mutex_lock(&e -> lock);
    for (int i = 0; i < ENGINE_MAX_CAPTURES; i++){
        struct Slot *s = &e -> slots[i];
        if (s -> state == ENGINE_RUNNING) _stop_locked(s);
        if (s -> state == ENGINE_STOPPED) _release_locked(s);
    }
    pthread_mutex_unlock(&e -> lock);
    ipset_destroy(e -> ign_src);
    ipset_destroy(e -> ign_dst);
    pthread_mutex_destroy(&e -> lock);
    free(e);
}

/* ═════════════════════ lire, statistiques ═════════════════════ */

int engine_read(Engine *e, const char *ifname, FlowRecord *out, int max){
    if (e == NULL || out == NULL || max < 0) return _fail("engine_read : argument invalide");
    pthread_mutex_lock(&e -> lock);                      /* ce verrou garantit « un seul lecteur à la fois » : le ring n'en supporte qu'un */
    struct Slot *s = _find(e, ifname);
    if (s == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("aucune capture sur '%s'", ifname != NULL ? ifname : "(NULL)");
    }
    RingStats rs = ring_stats(s -> ring);
    if (stats_is_error(&rs)){
        pthread_mutex_unlock(&e -> lock);
        return _fail("le ring de '%s' est illisible (en-tête incohérent)", ifname);
    }
    int n = 0;
    while (n < max && ring_read(s -> ring, &out[n], sizeof(FlowRecord)) == 0) n++;
    pthread_mutex_unlock(&e -> lock);
    return n;
}

int engine_stats(Engine *e, const char *ifname, struct EngineStats *out){
    if (e == NULL || out == NULL) return _fail("engine_stats : argument invalide");
    pthread_mutex_lock(&e -> lock);
    struct Slot *s = _find(e, ifname);
    if (s == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("aucune capture sur '%s'", ifname != NULL ? ifname : "(NULL)");
    }
    _fill_stats(s, out);
    pthread_mutex_unlock(&e -> lock);
    return 0;
}

int engine_list(Engine *e, struct EngineStats *out, int max){
    if (e == NULL || (out == NULL && max > 0) || max < 0) return _fail("engine_list : argument invalide");
    pthread_mutex_lock(&e -> lock);
    int n = 0;
    for (int i = 0; i < ENGINE_MAX_CAPTURES; i++){
        if (e -> slots[i].state == ENGINE_SLOT_FREE) continue;
        if (n < max) _fill_stats(&e -> slots[i], &out[n]);
        n++;
    }
    pthread_mutex_unlock(&e -> lock);
    return n;
}

int engine_ring_name(Engine *e, const char *ifname, char *out, size_t size){
    if (e == NULL || out == NULL || size == 0) return _fail("engine_ring_name : argument invalide");
    pthread_mutex_lock(&e -> lock);
    struct Slot *s = _find(e, ifname);
    if (s == NULL){
        pthread_mutex_unlock(&e -> lock);
        return _fail("aucune capture sur '%s'", ifname != NULL ? ifname : "(NULL)");
    }
    snprintf(out, size, "%s", s -> ring_name);
    pthread_mutex_unlock(&e -> lock);
    return 0;
}

/* ═════════════════════ les réglages des règles (à chaud, sans verrou : tout est atomique) ═════════════════════ */

int engine_rules_set_enabled(Engine *e, int rule, int enabled){
    if (e == NULL) return _fail("engine_rules_set_enabled : engine NULL");
    if (rules_set_enabled(&e -> rules, rule, enabled) != 0) return _fail("règle inconnue (%d)", rule);
    return 0;
}

int engine_rules_set_threshold(Engine *e, int rule, uint32_t threshold){
    if (e == NULL) return _fail("engine_rules_set_threshold : engine NULL");
    if (rules_name(rule) == NULL) return _fail("règle inconnue (%d)", rule);
    if (!rules_has_threshold(rule)) return _fail("la règle '%s' n'a pas de seuil", rules_name(rule));
    if (rules_set_threshold(&e -> rules, rule, threshold) != 0) return _fail("le seuil de '%s' doit être >= 1", rules_name(rule));
    return 0;
}

int engine_rules_get(Engine *e, int rule, int *enabled, uint32_t *threshold){
    if (e == NULL) return _fail("engine_rules_get : engine NULL");
    if (rules_get(&e -> rules, rule, enabled, threshold) != 0) return _fail("règle inconnue (%d)", rule);
    return 0;
}

/* ═════════════════════ les listes d'IP à ignorer ═════════════════════ */

static int _parse_ip(const char *text, uint8_t *ip, int *v4){   /* "10.0.0.1" ou "2001:db8::1" ; ip doit faire 16 octets */
    if (text == NULL) return -1;
    memset(ip, 0, 16);
    if (inet_pton(AF_INET, text, ip) == 1){ *v4 = 1; return 0; }
    if (inet_pton(AF_INET6, text, ip) == 1){ *v4 = 0; return 0; }
    return -1;
}

int engine_ignore_add(Engine *e, const char *ip, int which){
    uint8_t b[16]; int v4;
    if (e == NULL || which < 1 || which > 3) return _fail("engine_ignore_add : argument invalide");
    if (_parse_ip(ip, b, &v4) != 0) return _fail("'%s' n'est pas une adresse IP", ip != NULL ? ip : "(NULL)");
    if ((which & IGNORE_SRC) && ipset_add(e -> ign_src, b, v4) != 0) return _fail("liste « source » pleine");
    if ((which & IGNORE_DST) && ipset_add(e -> ign_dst, b, v4) != 0) return _fail("liste « destination » pleine");
    return 0;
}

int engine_ignore_remove(Engine *e, const char *ip, int which){
    uint8_t b[16]; int v4;
    if (e == NULL || which < 1 || which > 3) return _fail("engine_ignore_remove : argument invalide");
    if (_parse_ip(ip, b, &v4) != 0) return _fail("'%s' n'est pas une adresse IP", ip != NULL ? ip : "(NULL)");
    int r = 0;
    if ((which & IGNORE_SRC) && ipset_remove(e -> ign_src, b, v4) != 0) r = -1;
    if ((which & IGNORE_DST) && ipset_remove(e -> ign_dst, b, v4) != 0) r = -1;
    return r == 0 ? 0 : _fail("'%s' n'était pas dans la liste", ip);
}

int engine_ignore_contains(Engine *e, const char *ip, int which){
    uint8_t b[16]; int v4;
    if (e == NULL || which < 1 || which > 3 || _parse_ip(ip, b, &v4) != 0) return 0;
    if ((which & IGNORE_SRC) && ipset_contains(e -> ign_src, b, v4)) return 1;
    if ((which & IGNORE_DST) && ipset_contains(e -> ign_dst, b, v4)) return 1;
    return 0;
}

uint32_t engine_ignore_count(Engine *e, int which){
    if (e == NULL) return 0;
    return which == IGNORE_DST ? ipset_count(e -> ign_dst) : ipset_count(e -> ign_src);
}
