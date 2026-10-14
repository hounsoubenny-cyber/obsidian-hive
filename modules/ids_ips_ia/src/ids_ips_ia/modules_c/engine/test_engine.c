/* test_engine.c : tests du moteur (engine.c). Il faut root ou CAP_NET_RAW pour les tests qui capturent (sinon : ignorés).
 * Lancer :  sudo -E ./run_tests.sh engine
 * Ils capturent « lo » (la boucle locale) en y envoyant eux-mêmes du trafic UDP. Rappel : sur lo, chaque paquet est vu 2 fois. */
#define _GNU_SOURCE
#include "../test_common.h"
#include "engine.h"
#include "../mmap_ring/mmap_ring.h"
#include "../utils/utils.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

/* ═══════════════════════════ outils ═══════════════════════════ */

static int can_capture(void) {
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { printf("      (ignoré : pas root / pas CAP_NET_RAW)\n"); return 0; }
    close(fd);
    return 1;
}

static void sleep_ms(int ms) { usleep((useconds_t)ms * 1000); }

static int udp_sink(uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close(s); return -1; }
    return s;
}

/* n datagrammes vers 127.0.0.1:dport, depuis UN socket (donc UN flux) */
static void udp_burst(uint16_t dport, int n, int payload) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to; memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_port = htons(dport); inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    uint8_t *buf = calloc(1, (size_t)payload);
    for (int i = 0; i < n; i++) sendto(s, buf, (size_t)payload, 0, (struct sockaddr *)&to, sizeof to);
    free(buf);
    close(s);
}

static int shm_exists(const char *name) {
    int fd = shm_open(name, O_RDONLY, 0);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

/* une config de test : lo, ring de 1 Mio, flux qui partent après 300 ms d'inactivité */
static void test_cfg(struct EngineConfig *c, const char *prefix, int mmsg) {
    engine_config_default(c);
    c -> ifname = "lo";
    c -> ring_prefix = prefix;
    c -> use_mmsg = mmsg;
    c -> idle_ms = 300;
    c -> max_ms = 0;
    c -> ring_size = 1u << 20;
    c -> table_size = 1024;
    c -> buffer_mb = 4;
    c -> poll_ms = 50;
}

static char g_prefix[16];
static const char *prefix(const char *tag) { snprintf(g_prefix, sizeof g_prefix, "t%d%s", (int)getpid() % 100000, tag); return g_prefix; }

/* lit le ring jusqu'à avoir `want` flux ou jusqu'à timeout_ms */
static int read_until(Engine *e, const char *ifname, FlowRecord *out, int max, int want, int timeout_ms) {
    int n = 0;
    for (int waited = 0; waited < timeout_ms && n < want; waited += 50) {
        int r = engine_read(e, ifname, out + n, max - n);
        if (r > 0) n += r;
        if (n < want) sleep_ms(50);
    }
    return n;
}

#define BOTH(name) \
    static void name##_recv(void) { name(0); } \
    static void name##_mmsg(void) { name(1); }

/* ═══════════════════════════ 1. configuration et arguments (sans root) ═══════════════════════════ */

static void t_config_par_defaut(void) {
    struct EngineConfig c;
    memset(&c, 0xAB, sizeof c);
    engine_config_default(&c);
    CHECK(c.ifname == NULL, "ifname NULL : à toi de le donner");
    CHECK(c.ring_prefix != NULL && strcmp(c.ring_prefix, "ids") == 0, "préfixe du ring : « ids »");
    CHECK_EQ(c.use_mmsg, 1, "mmsg par défaut");
    CHECK_EQ(c.promisc, 0, "pas promiscuous");
    CHECK(c.idle_ms == 30000 && c.max_ms == 300000, "30 s d'inactivité, 5 min de durée max");
    CHECK_EQ(c.close_on_tcp_end, 1, "fin TCP active");
    CHECK_EQ(c.scan_rule, 1, "règle de scan active");
    CHECK(c.ring_size == (16u << 20), "ring de 16 Mio");
    CHECK(c.table_size == 65536 && c.buffer_mb == 16 && c.batch_size == 64 && c.max_turns == 16 && c.poll_ms == 200, "autres valeurs");
    engine_config_default(NULL);
    CHECK_EQ(engine_record_size(), 176, "un flux dans le ring = 176 octets (Python vérifie la même chose)");
}

static void t_arguments_invalides(void) {
    Engine *e = engine_create();
    CHECK(e != NULL, "engine_create");
    struct EngineConfig c;
    engine_config_default(&c);
    CHECK_EQ(engine_start(NULL, &c), -1, "start(engine NULL)");
    CHECK_EQ(engine_start(e, NULL), -1, "start(cfg NULL)");
    c.ifname = NULL;
    CHECK_EQ(engine_start(e, &c), -1, "ifname NULL");
    CHECK(strlen(engine_last_error()) > 0, "engine_last_error() explique");
    c.ifname = "";
    CHECK_EQ(engine_start(e, &c), -1, "ifname vide");
    c.ifname = "a/b";
    CHECK_EQ(engine_start(e, &c), -1, "ifname avec « / »");
    c.ifname = "un_nom_d_interface_beaucoup_trop_long_pour_linux";
    CHECK_EQ(engine_start(e, &c), -1, "ifname trop long");
    c.ifname = "interface_inconnue0";
    CHECK_EQ(engine_start(e, &c), -1, "interface inexistante");
    CHECK(strstr(engine_last_error(), "interface_inconnue0") != NULL, "le message cite l'interface");
    c.ifname = "lo";
    c.table_size = 3;
    CHECK_EQ(engine_start(e, &c), -1, "table_size trop petit");
    engine_config_default(&c); c.ifname = "lo"; c.ring_prefix = "pre/fix";
    CHECK_EQ(engine_start(e, &c), -1, "ring_prefix invalide");
    engine_config_default(&c); c.ifname = "lo"; c.poll_ms = 0;
    CHECK_EQ(engine_start(e, &c), -1, "poll_ms == 0");
    engine_config_default(&c); c.ifname = "lo"; c.buffer_mb = 0;
    CHECK_EQ(engine_start(e, &c), -1, "buffer_mb == 0");
    engine_config_default(&c); c.ifname = "lo"; c.use_mmsg = 1; c.batch_size = 0;
    CHECK_EQ(engine_start(e, &c), -1, "batch_size == 0");

    CHECK_EQ(engine_stop(e, "lo"), -1, "stop d'une capture qui n'existe pas");
    CHECK_EQ(engine_release(e, "lo"), -1, "release d'une capture qui n'existe pas");
    FlowRecord r; struct EngineStats st; char name[64];
    CHECK_EQ(engine_read(e, "lo", &r, 1), -1, "read d'une capture qui n'existe pas");
    CHECK_EQ(engine_stats(e, "lo", &st), -1, "stats d'une capture qui n'existe pas");
    CHECK_EQ(engine_ring_name(e, "lo", name, sizeof name), -1, "ring_name d'une capture qui n'existe pas");
    CHECK_EQ(engine_stop(NULL, "lo"), -1, "stop(NULL)");
    CHECK_EQ(engine_read(e, "lo", NULL, 1), -1, "read(out NULL)");
    CHECK_EQ(engine_list(e, NULL, 0), 0, "list : aucune capture");
    engine_destroy(e);
    engine_destroy(NULL);
}

/* ═══════════════════════════ 2. les listes d'IP à ignorer (sans root) ═══════════════════════════ */

static void t_ignore_listes(void) {
    Engine *e = engine_create();
    CHECK_EQ(engine_ignore_count(e, IGNORE_SRC), 0, "listes vides");
    CHECK_EQ(engine_ignore_contains(e, "10.0.0.1", IGNORE_SRC), 0, "absente");
    CHECK_EQ(engine_ignore_add(e, "10.0.0.1", IGNORE_SRC), 0, "add source");
    CHECK_EQ(engine_ignore_contains(e, "10.0.0.1", IGNORE_SRC), 1, "présente côté source");
    CHECK_EQ(engine_ignore_contains(e, "10.0.0.1", IGNORE_DST), 0, "absente côté destination");
    CHECK_EQ(engine_ignore_contains(e, "10.0.0.1", IGNORE_BOTH), 1, "BOTH = dans l'une OU l'autre");
    CHECK_EQ(engine_ignore_add(e, "10.0.0.2", IGNORE_BOTH), 0, "add des deux côtés");
    CHECK_EQ(engine_ignore_count(e, IGNORE_SRC), 2, "2 en source");
    CHECK_EQ(engine_ignore_count(e, IGNORE_DST), 1, "1 en destination");
    CHECK_EQ(engine_ignore_add(e, "2001:db8::1", IGNORE_BOTH), 0, "IPv6");
    CHECK_EQ(engine_ignore_contains(e, "2001:db8::1", IGNORE_DST), 1, "IPv6 présente");
    CHECK_EQ(engine_ignore_contains(e, "2001:0db8:0:0:0:0:0:1", IGNORE_DST), 1, "même IPv6 écrite autrement");
    CHECK_EQ(engine_ignore_add(e, "pas une ip", IGNORE_BOTH), -1, "texte invalide → -1");
    CHECK(strstr(engine_last_error(), "pas une ip") != NULL, "le message cite le texte");
    CHECK_EQ(engine_ignore_add(e, NULL, IGNORE_BOTH), -1, "NULL → -1");
    CHECK_EQ(engine_ignore_add(e, "10.0.0.3", 0), -1, "which == 0 → -1");
    CHECK_EQ(engine_ignore_add(e, "10.0.0.3", 4), -1, "which == 4 → -1");
    CHECK_EQ(engine_ignore_contains(e, "pas une ip", IGNORE_SRC), 0, "question sur un texte invalide → 0");
    CHECK_EQ(engine_ignore_remove(e, "10.0.0.1", IGNORE_SRC), 0, "remove");
    CHECK_EQ(engine_ignore_contains(e, "10.0.0.1", IGNORE_SRC), 0, "retirée");
    CHECK_EQ(engine_ignore_remove(e, "10.0.0.1", IGNORE_SRC), -1, "remove d'une IP absente → -1");
    CHECK_EQ(engine_ignore_remove(e, "10.0.0.2", IGNORE_BOTH), 0, "remove des deux côtés");
    CHECK_EQ(engine_ignore_count(e, IGNORE_SRC), 1, "reste l'IPv6");
    engine_destroy(e);
}

/* ═══════════════════════════ 3. cycle de vie (root) ═══════════════════════════ */

static void t_cycle_de_vie(int mmsg) {
    if (!can_capture()) return;
    alarm(30);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, prefix("life"), mmsg);
    CHECK_EQ(engine_start(e, &c), 0, "engine_start(lo)");
    CHECK_EQ(engine_start(e, &c), -1, "une 2e capture sur la même interface → -1");
    CHECK(strstr(engine_last_error(), "déjà") != NULL, "le message dit « déjà »");

    char ring[64];
    CHECK_EQ(engine_ring_name(e, "lo", ring, sizeof ring), 0, "ring_name");
    char want[64]; snprintf(want, sizeof want, "/%s_lo", g_prefix);
    CHECK(strcmp(ring, want) == 0, "le ring s'appelle /<préfixe>_lo");
    CHECK(shm_exists(ring), "le segment existe dans /dev/shm");

    struct EngineStats st[4];
    CHECK_EQ(engine_list(e, st, 4), 1, "list : 1 capture");
    CHECK(strcmp(st[0].ifname, "lo") == 0 && st[0].state == ENGINE_RUNNING, "elle tourne");
    CHECK(st[0].ring_size == (1u << 20) - 256, "ring_size = taille du segment - 256");

    CHECK_EQ(engine_release(e, "lo"), -1, "release d'une capture qui tourne → -1");
    uint64_t t0 = monotonic_ms();
    CHECK_EQ(engine_stop(e, "lo"), 0, "engine_stop");
    CHECK(monotonic_ms() - t0 < 1000, "l'arrêt prend moins d'une seconde (poll_ms = 50)");
    CHECK_EQ(engine_stats(e, "lo", &st[0]), 0, "stats après l'arrêt");
    CHECK_EQ(st[0].state, ENGINE_STOPPED, "état : arrêtée");
    CHECK(shm_exists(ring), "le ring existe toujours (Python peut finir de le lire)");
    CHECK_EQ(engine_stop(e, "lo"), -1, "2e stop → -1");
    CHECK_EQ(engine_start(e, &c), -1, "redémarrer sans release → -1");
    CHECK_EQ(engine_release(e, "lo"), 0, "engine_release");
    CHECK(!shm_exists(ring), "le segment est supprimé");
    CHECK_EQ(engine_list(e, st, 4), 0, "plus aucune capture");
    CHECK_EQ(engine_start(e, &c), 0, "on peut relancer");
    engine_destroy(e);
    CHECK(!shm_exists(ring), "engine_destroy arrête et supprime tout");
}
BOTH(t_cycle_de_vie)

static void t_lire_des_flux(int mmsg) {
    if (!can_capture()) return;
    alarm(30);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, prefix("read"), mmsg);
    CHECK_EQ(engine_start(e, &c), 0, "start");
    int sink = udp_sink(43001);
    udp_burst(43001, 10, 20);                                     /* un flux : 10 datagrammes */
    FlowRecord out[8];
    int n = read_until(e, "lo", out, 8, 1, 4000);                 /* le flux part après 300 ms d'inactivité */
    CHECK(n >= 1, "un flux est arrivé dans le ring (envoyé après idle_ms)");
    int found = 0;
    for (int i = 0; i < n; i++) {
        const FlowData *d = &out[i].data;
        if (d -> proto == UDP && d -> v4 == 1 && port_to_u16(d -> header.ipv4_headers.receiver_port) == 43001) {
            found = 1;
            CHECK(d -> n_pkt_ltr >= 10, "au moins 10 paquets dans le sens émetteur → récepteur");
            CHECK(d -> octets_data_ltr >= 10 * 62, "octets comptés (10 trames de 62 octets au moins)");
            CHECK(d -> end_time >= d -> start_time && d -> start_time > 1700000000000ULL, "start_time et end_time : heure réelle en ms depuis 1970");
            CHECK_EQ(out[i].reason, END_IDLE, "raison : inactif");
            CHECK_MEM(d -> header.ipv4_headers.receiver_ip, ((uint8_t[]){127, 0, 0, 1}), 4, "récepteur 127.0.0.1");
        }
    }
    CHECK(found, "le flux UDP vers le port 43001 est bien dedans");
    struct EngineStats st;
    engine_stats(e, "lo", &st);
    CHECK(st.frames_in >= 10 && st.frames_ok >= 10, "les compteurs ont bougé");
    CHECK(st.flows_exported >= 1, "flows_exported >= 1");
    CHECK_EQ(st.flows_lost, 0, "aucun flux perdu");
    CHECK_EQ(engine_read(e, "lo", out, 0), 0, "read(max = 0) → 0");
    close(sink);
    engine_destroy(e);
}
BOTH(t_lire_des_flux)

static void t_arret_envoie_les_flux_restants(int mmsg) {
    if (!can_capture()) return;
    alarm(30);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, prefix("flush"), mmsg);
    c.idle_ms = 0;                                                /* aucun flux ne part tout seul */
    CHECK_EQ(engine_start(e, &c), 0, "start");
    int sink = udp_sink(43002);
    udp_burst(43002, 5, 20);
    sleep_ms(400);
    FlowRecord out[8];
    CHECK_EQ(engine_read(e, "lo", out, 8), 0, "rien dans le ring tant que le flux est vivant");
    CHECK_EQ(engine_stop(e, "lo"), 0, "stop");
    int n = engine_read(e, "lo", out, 8);
    CHECK(n >= 1, "après l'arrêt, le flux restant est dans le ring");
    if (n >= 1) CHECK_EQ(out[0].reason, END_SHUTDOWN, "raison : arrêt");
    CHECK_EQ(engine_read(e, "lo", out, 8), 0, "puis plus rien");
    CHECK_EQ(engine_release(e, "lo"), 0, "release");
    close(sink);
    engine_destroy(e);
}
BOTH(t_arret_envoie_les_flux_restants)

/* ═══════════════════════════ 4. listes d'IP : effet sur la capture ═══════════════════════════ */

static void t_ignore_pendant_la_capture(int mmsg) {
    if (!can_capture()) return;
    alarm(30);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, prefix("ign"), mmsg);
    c.idle_ms = 0;
    CHECK_EQ(engine_start(e, &c), 0, "start");
    int sink = udp_sink(43003);
    CHECK_EQ(engine_ignore_add(e, "127.0.0.1", IGNORE_SRC), 0, "127.0.0.1 ignorée en source");
    udp_burst(43003, 10, 20);
    sleep_ms(400);
    struct EngineStats st;
    engine_stats(e, "lo", &st);
    CHECK(st.frames_in >= 10, "les trames sont bien arrivées");
    CHECK(st.frames_ignored >= 10, "et ignorées");
    CHECK_EQ(st.frames_ok, 0, "aucune n'est entrée dans la table");
    CHECK_EQ(st.active_flows, 0, "aucun flux suivi");

    CHECK_EQ(engine_ignore_remove(e, "127.0.0.1", IGNORE_SRC), 0, "retirée de la liste, la capture tourne toujours");
    uint64_t avant = st.frames_ignored;
    udp_burst(43003, 10, 20);
    sleep_ms(400);
    engine_stats(e, "lo", &st);
    CHECK_EQ(st.frames_ignored, avant, "plus rien n'est ignoré après le retrait");
    CHECK(st.frames_ok >= 10, "le trafic est suivi");

    CHECK_EQ(engine_ignore_add(e, "127.0.0.1", IGNORE_DST), 0, "maintenant en destination");
    avant = st.frames_ignored;
    udp_burst(43003, 5, 20);
    sleep_ms(400);
    engine_stats(e, "lo", &st);
    CHECK(st.frames_ignored >= avant + 5, "la liste « destination » ignore aussi");

    engine_ignore_remove(e, "127.0.0.1", IGNORE_DST);
    CHECK_EQ(engine_ignore_add(e, "10.9.9.9", IGNORE_BOTH), 0, "une autre IP ignorée");
    avant = st.frames_ignored;
    udp_burst(43003, 5, 20);
    sleep_ms(400);
    engine_stats(e, "lo", &st);
    CHECK_EQ(st.frames_ignored, avant, "une IP étrangère à la capture ne change rien");
    close(sink);
    engine_destroy(e);
}
BOTH(t_ignore_pendant_la_capture)

/* ═══════════════════════════ 5. ring plein, ring d'un lancement précédent ═══════════════════════════ */

static void t_ring_plein_ne_bloque_pas(int mmsg) {
    if (!can_capture()) return;
    alarm(40);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, prefix("full"), mmsg);
    c.ring_size = 256 + 176 * 3;                                  /* la place de 3 flux seulement */
    c.idle_ms = 200;
    CHECK_EQ(engine_start(e, &c), 0, "start avec un ring minuscule");
    int sink = udp_sink(43004);
    for (int i = 0; i < 20; i++) udp_burst(43004, 2, 20);         /* 20 sockets = 20 flux */
    sleep_ms(1000);
    struct EngineStats st;
    engine_stats(e, "lo", &st);
    CHECK(st.flows_exported + st.flows_lost >= 20, "tous les flux sont sortis de la table (écrits ou perdus)");
    CHECK(st.flows_exported == 3, "3 écrits (le ring n'a de place que pour 3)");
    CHECK(st.flows_lost >= 17, "les autres sont perdus et comptés");
    CHECK_EQ(st.ring_dropped, st.flows_lost, "le ring compte les mêmes pertes");
    uint64_t in = st.frames_in;
    udp_burst(43004, 10, 20);
    sleep_ms(300);
    engine_stats(e, "lo", &st);
    CHECK(st.frames_in > in, "la capture continue de tourner : un ring plein ne la bloque jamais");
    FlowRecord out[8];
    CHECK_EQ(engine_read(e, "lo", out, 8), 3, "Python lit les 3 flux du ring");
    close(sink);
    engine_destroy(e);
}
BOTH(t_ring_plein_ne_bloque_pas)

static void t_ring_ancien_remplace(void) {
    if (!can_capture()) return;
    alarm(30);
    const char *p = prefix("stale");
    char name[64]; snprintf(name, sizeof name, "/%s_lo", p);
    Ring *old = rgm_open(name, 4096, 1);                          /* un segment resté d'un arrêt brutal, d'une autre taille */
    CHECK(old != NULL, "segment ancien créé");
    ring_close(old);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, p, 1);
    CHECK_EQ(engine_start(e, &c), 0, "start remplace le segment ancien");
    struct EngineStats st;
    engine_stats(e, "lo", &st);
    CHECK(st.ring_size == (1u << 20) - 256, "le nouveau ring a la bonne taille");
    engine_destroy(e);
}

static void t_deux_interfaces(void) {
    if (!can_capture()) return;
    alarm(30);
    char other[256] = "";                                          /* une autre interface que lo, si la machine en a une */
    DIR *d = opendir("/sys/class/net");
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL) {
        if (de -> d_name[0] != '.' && strcmp(de -> d_name, "lo") != 0 && other[0] == '\0') snprintf(other, sizeof other, "%s", de -> d_name);
    }
    if (d) closedir(d);
    if (other[0] == '\0') { printf("      (ignoré : pas d'autre interface que lo)\n"); return; }
    Engine *e = engine_create();
    struct EngineConfig a, b;
    test_cfg(&a, prefix("two"), 1);
    test_cfg(&b, g_prefix, 0);
    b.ifname = other;
    CHECK_EQ(engine_start(e, &a), 0, "capture sur lo");
    CHECK_EQ(engine_start(e, &b), 0, "capture sur une 2e interface en même temps");
    struct EngineStats st[4];
    CHECK_EQ(engine_list(e, st, 4), 2, "list : 2 captures");
    CHECK_EQ(engine_stop(e, "lo"), 0, "on arrête lo seulement");
    engine_list(e, st, 4);
    int stopped = 0, running = 0;
    for (int i = 0; i < 2; i++) { if (st[i].state == ENGINE_STOPPED) stopped++; if (st[i].state == ENGINE_RUNNING) running++; }
    CHECK(stopped == 1 && running == 1, "une arrêtée, l'autre tourne toujours");
    CHECK_EQ(engine_release(e, "lo"), 0, "release de lo");
    engine_destroy(e);
}

/* ═══════════════════════════ 6. plusieurs threads Python en même temps ═══════════════════════════ */

struct Hammer { Engine *e; _Atomic int stop; _Atomic long errors; };
static void *hammer(void *a) {
    struct Hammer *h = a;
    FlowRecord out[16]; struct EngineStats st[4];
    while (!atomic_load(&h -> stop)) {
        if (engine_stats(h -> e, "lo", &st[0]) != 0) atomic_fetch_add(&h -> errors, 1);
        if (engine_list(h -> e, st, 4) < 0) atomic_fetch_add(&h -> errors, 1);
        if (engine_read(h -> e, "lo", out, 16) < 0) atomic_fetch_add(&h -> errors, 1);
        engine_ignore_contains(h -> e, "10.1.1.1", IGNORE_BOTH);
        engine_ignore_add(h -> e, "10.1.1.1", IGNORE_BOTH);
        engine_ignore_remove(h -> e, "10.1.1.1", IGNORE_BOTH);
    }
    return NULL;
}

static void t_appels_concurrents(void) {
    if (!can_capture()) return;
    alarm(40);
    Engine *e = engine_create();
    struct EngineConfig c;
    test_cfg(&c, prefix("conc"), 1);
    c.idle_ms = 100;
    CHECK_EQ(engine_start(e, &c), 0, "start");
    int sink = udp_sink(43005);
    struct Hammer h; h.e = e; atomic_init(&h.stop, 0); atomic_init(&h.errors, 0);
    pthread_t th[4];
    for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, hammer, &h);
    for (int i = 0; i < 40; i++) { udp_burst(43005, 20, 20); sleep_ms(20); }
    atomic_store(&h.stop, 1);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    CHECK_EQ(atomic_load(&h.errors), 0, "4 threads appellent stats / list / read / ignore pendant le trafic : aucune erreur");
    CHECK_EQ(engine_stop(e, "lo"), 0, "stop");
    close(sink);
    engine_destroy(e);
}

int main(int argc, char **argv) {
    tc_begin("test_engine.c", argc, argv);

    printf("\n── 1. configuration et arguments (sans root) ──\n");
    RUN_LEAKS("config par défaut",                              t_config_par_defaut);
    RUN_LEAKS("arguments invalides",                            t_arguments_invalides);

    printf("\n── 2. listes d'IP à ignorer (sans root) ──\n");
    RUN_LEAKS("ignore : ajouter, chercher, retirer",            t_ignore_listes);

    printf("\n── 3. cycle de vie ──\n");
    RUN_LEAKS("recv : start, stop, release, destroy",           t_cycle_de_vie_recv);
    RUN_LEAKS("mmsg : start, stop, release, destroy",           t_cycle_de_vie_mmsg);
    RUN_LEAKS("recv : lire des flux dans le ring",              t_lire_des_flux_recv);
    RUN_LEAKS("mmsg : lire des flux dans le ring",              t_lire_des_flux_mmsg);
    RUN_LEAKS("recv : l'arrêt envoie les flux restants",        t_arret_envoie_les_flux_restants_recv);
    RUN_LEAKS("mmsg : l'arrêt envoie les flux restants",        t_arret_envoie_les_flux_restants_mmsg);

    printf("\n── 4. listes d'IP pendant la capture ──\n");
    RUN_LEAKS("recv : ignorer source, destination, retirer",    t_ignore_pendant_la_capture_recv);
    RUN_LEAKS("mmsg : ignorer source, destination, retirer",    t_ignore_pendant_la_capture_mmsg);

    printf("\n── 5. ring plein, segment ancien, deux interfaces ──\n");
    RUN_LEAKS("recv : ring plein ne bloque pas la capture",     t_ring_plein_ne_bloque_pas_recv);
    RUN_LEAKS("mmsg : ring plein ne bloque pas la capture",     t_ring_plein_ne_bloque_pas_mmsg);
    RUN_LEAKS("segment ancien remplacé au démarrage",           t_ring_ancien_remplace);
    RUN_LEAKS("deux interfaces en même temps",                  t_deux_interfaces);

    printf("\n── 6. plusieurs threads Python ──\n");
    RUN_LEAKS("appels concurrents pendant le trafic",           t_appels_concurrents);

    return tc_end();
}
