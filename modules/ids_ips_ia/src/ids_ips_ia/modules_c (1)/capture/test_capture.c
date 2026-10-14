/* test_capture.c : tests du module de capture (capture.c)
 *
 * Lancer (il faut root ou CAP_NET_RAW pour les tests avec un vrai socket ; sans, ils sont ignorés) :
 *     sudo -E ./run_tests.sh capture             → tout
 *     sudo -E ./run_tests.sh capture mmsg        → seulement les tests dont le titre contient « mmsg »
 *     CAP_IFACE=veth0 sudo -E ./run_tests.sh capture iface     → le test qui utilise TON interface
 *
 * Les tests « lo » sont autonomes : ils envoient eux-mêmes du trafic UDP / TCP sur la boucle locale (127.0.0.1)
 * et le capturent. Rappel : sur « lo », chaque paquet est vu DEUX fois (une fois sortant, une fois entrant).
 * Si un test se bloque, une alarme de 20 s le tue : il apparaît alors comme un plantage 💥. */
#define _GNU_SOURCE
#include "../test_common.h"
#include "capture.h"
#include "../parser/parser.h"
#include "../flows/flow_table.h"
#include "../utils/utils.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ═══════════════════════════ outils ═══════════════════════════ */

#define LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

static struct sock_filter F_ALL[]  = { BPF_STMT(BPF_RET | BPF_K, 0x40000) };      /* tout accepter */
static struct sock_filter F_NONE[] = { BPF_STMT(BPF_RET | BPF_K, 0) };            /* tout jeter */
static struct sock_filter F_IPV4[] = {                                            /* IPv4 seulement */
    BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, 0x40000),
    BPF_STMT(BPF_RET | BPF_K, 0),
};

static int can_capture(void) {                    /* a-t-on le droit d'ouvrir un socket de paquets ? */
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { printf("      (ignoré : pas root / pas CAP_NET_RAW)\n"); return 0; }
    close(fd);
    return 1;
}

static void arm_timeout(void) { alarm(20); }      /* un test qui se bloque est tué après 20 s */

static Capture *open_lo(int fanout, struct sock_filter *f, int n) {
    return cap_open("lo", fanout, 0, 4 * 1024 * 1024, f, n);
}

static void sleep_ms(int ms) { usleep((useconds_t)ms * 1000); }

/* lève le drapeau d'arrêt au bout de ms millisecondes */
struct Dog { _Atomic uint8_t *stop; int ms; };
static void *dog_thread(void *a) {
    struct Dog *d = a;
    sleep_ms(d -> ms);
    atomic_store(d -> stop, 1);
    free(d);
    return NULL;
}
static void watchdog(_Atomic uint8_t *stop, int ms) {
    struct Dog *d = malloc(sizeof(*d));
    d -> stop = stop; d -> ms = ms;
    pthread_t t;
    pthread_create(&t, NULL, dog_thread, d);
    pthread_detach(t);
}

/* ── trafic ── */
static int udp_sink(uint16_t port) {              /* un récepteur UDP : évite les « port injoignable » ICMP */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close(s); return -1; }
    return s;
}

static int udp_burst(uint16_t dport, int n, int payload, int interval_us) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to; memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_port = htons(dport); inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    uint8_t *buf = calloc(1, (size_t)(payload > 0 ? payload : 1));
    int sent = 0;
    for (int i = 0; i < n; i++) {
        if (sendto(s, buf, (size_t)payload, 0, (struct sockaddr *)&to, sizeof to) == payload) sent++;
        if (interval_us > 0) usleep((useconds_t)interval_us);
    }
    free(buf);
    close(s);
    return sent;
}

struct Traffic { uint16_t dport; int n, payload, interval_us; };
static void *traffic_thread(void *a) {
    struct Traffic *t = a;
    udp_burst(t -> dport, t -> n, t -> payload, t -> interval_us);
    return NULL;
}

/* ── ce que on_frame compte ── */
struct Cnt {
    _Atomic uint8_t *stop;
    int stop_after;                   /* 0 = ne jamais s'arrêter seul ; sinon on lève stop après ce nombre de trames UDP */
    uint16_t dport;                   /* ne compter que ce port de destination (0 = tous) */
    int expected_len;                 /* longueur attendue d'une trame UDP comptée (0 = pas de vérification) */
    int n_all, n_udp, bad_len, max_len, n_v6, n_clear;
};

static void on_frame_cnt(const uint8_t *f, int len, void *ctx) {
    struct Cnt *c = ctx;
    c -> n_all++;
    if (len > c -> max_len) c -> max_len = len;
    if (len >= 14 && f[12] == 0x86 && f[13] == 0xDD) c -> n_v6++;
    ParserResult pr = parse(f, len);
    if (pr.code == SUCCES && pr.type == IPV4 && pr.ip_data.ipv4.proto == UDP &&
        (c -> dport == 0 || port_to_u16(pr.data.udp.dst_port) == c -> dport)) {
        c -> n_udp++;
        if (c -> expected_len && len != c -> expected_len) c -> bad_len++;
    }
    if (c -> stop_after && c -> n_udp >= c -> stop_after) atomic_store(c -> stop, 1);
}
static void clear_cnt(void *ctx) { ((struct Cnt *)ctx) -> n_clear++; }

/* lance l'une des deux fonctions de réception. mode 0 = cap_recv, mode 1 = cap_recv_mmsg */
static long long run_mode(int mode, Capture *cap, struct Cnt *c, _Atomic uint8_t *stop,
                          int timeout_ms, EmptyFn clear, int clear_each) {
    long long r;
    if (mode == 0) {
        uint8_t *buf = malloc(CAP_MAX_FRAME);
        r = cap_recv(cap, buf, CAP_MAX_FRAME, timeout_ms, on_frame_cnt, clear, (uint8_t)clear_each, c, stop);
        free(buf);
    } else {
        r = cap_recv_mmsg(cap, CAP_MAX_FRAME, timeout_ms, on_frame_cnt, clear, (uint8_t)clear_each, c, stop, 8, 4);
    }
    return r;
}

/* un test écrit une fois, lancé pour les deux modes */
#define BOTH(name) \
    static void name##_recv(void) { name(0); } \
    static void name##_mmsg(void) { name(1); }

/* ═══════════════════════════ 1. arguments (sans root) ═══════════════════════════ */

static void t_args_open(void) {
    CHECK(cap_open(NULL, -1, 0, 1 << 20, F_ALL, LEN(F_ALL)) == NULL, "nom d'interface NULL → NULL");
    CHECK(cap_open("interface_qui_n_existe_pas", -1, 0, 1 << 20, F_ALL, LEN(F_ALL)) == NULL, "interface inconnue → NULL");
    CHECK(cap_open("lo", -1, 0, -5, F_ALL, LEN(F_ALL)) == NULL, "taille de tampon négative → NULL");
}

static void t_args_recv(void) {
    uint8_t buf[64];
    _Atomic uint8_t stop = 0;
    Capture fake; fake.fd = -1; fake.ifindex = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    CHECK_EQ(cap_recv(NULL, buf, sizeof buf, 10, on_frame_cnt, NULL, 0, &c, &stop), -1, "cap_recv(cap NULL) → -1");
    CHECK_EQ(cap_recv(&fake, NULL, sizeof buf, 10, on_frame_cnt, NULL, 0, &c, &stop), -1, "cap_recv(buf NULL) → -1");
    CHECK_EQ(cap_recv(&fake, buf, 0, 10, on_frame_cnt, NULL, 0, &c, &stop), -1, "cap_recv(taille 0) → -1");
    CHECK_EQ(cap_recv(&fake, buf, sizeof buf, 10, on_frame_cnt, NULL, 0, &c, NULL), -1, "cap_recv(stop NULL) → -1");
    CHECK_EQ(cap_recv(&fake, buf, sizeof buf, 10, NULL, NULL, 0, &c, &stop), -1, "cap_recv(on_frame NULL) → -1");
}

static void t_args_mmsg(void) {
    _Atomic uint8_t stop = 0;
    Capture fake; fake.fd = -1; fake.ifindex = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    CHECK_EQ(cap_recv_mmsg(NULL, 1500, 10, on_frame_cnt, NULL, 0, &c, &stop, 8, 4), -1, "mmsg(cap NULL) → -1");
    CHECK_EQ(cap_recv_mmsg(&fake, 0, 10, on_frame_cnt, NULL, 0, &c, &stop, 8, 4), -1, "mmsg(pkt_size 0) → -1");
    CHECK_EQ(cap_recv_mmsg(&fake, 1500, 10, on_frame_cnt, NULL, 0, &c, &stop, 0, 4), -1, "mmsg(batch 0) → -1");
    CHECK_EQ(cap_recv_mmsg(&fake, 1500, 10, on_frame_cnt, NULL, 0, &c, &stop, 8, 0), -1, "mmsg(max_turns 0) → -1");
    CHECK_EQ(cap_recv_mmsg(&fake, 1500, 10, on_frame_cnt, NULL, 0, &c, NULL, 8, 4), -1, "mmsg(stop NULL) → -1");
    CHECK_EQ(cap_recv_mmsg(&fake, 1500, 10, NULL, NULL, 0, &c, &stop, 8, 4), -1, "mmsg(on_frame NULL) → -1");
}

static void t_args_stats_close(void) {
    uint64_t r = 0, d = 0;
    Capture fake; fake.fd = -1; fake.ifindex = 0;
    CHECK_EQ(cap_stats(NULL, &r, &d), -1, "cap_stats(cap NULL) → -1");
    CHECK_EQ(cap_stats(&fake, NULL, &d), -1, "cap_stats(received NULL) → -1");
    CHECK_EQ(cap_stats(&fake, &r, NULL), -1, "cap_stats(dropped NULL) → -1");
    CHECK_EQ(cap_stats(&fake, &r, &d), -1, "cap_stats(fd invalide) → -1");
    cap_close(NULL);                                  /* ne doit pas planter */
    CHECK(1, "cap_close(NULL) ne plante pas");
}

/* ═══════════════════════════ 2. ouverture / fermeture (root) ═══════════════════════════ */

static int count_fds(void) {
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) return -1;
    while (readdir(d) != NULL) n++;
    closedir(d);
    return n;
}

static void t_open_close(void) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    CHECK(cap != NULL, "cap_open(lo) réussit");
    if (cap == NULL) return;
    int fd = cap -> fd;
    CHECK(fd >= 0, "fd valide");
    CHECK_EQ(cap -> ifindex, (int)if_nametoindex("lo"), "ifindex de lo");
    cap_close(cap);
    errno = 0;
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "après cap_close, le fd est fermé");
}

static void t_open_sans_filtre(void) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = cap_open("lo", -1, 0, 1 << 20, NULL, 0);
    CHECK(cap != NULL, "cap_open sans filtre (NULL, 0) réussit : tout est capturé");
    if (cap == NULL) return;
    struct Cnt c; memset(&c, 0, sizeof c);
    _Atomic uint8_t stop = 0;
    int sink = udp_sink(41090);
    udp_burst(41090, 5, 20, 0);
    c.dport = 41090; c.stop = &stop; c.stop_after = 5;
    watchdog(&stop, 2000);
    run_mode(0, cap, &c, &stop, 100, NULL, 0);
    CHECK(c.n_udp >= 5, "sans filtre, les 5 datagrammes sont vus");
    close(sink);
    cap_close(cap);
}

static void t_open_promisc_fanout(void) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *a = cap_open("lo", 77, 1, 1 << 20, F_ALL, LEN(F_ALL));
    Capture *b = cap_open("lo", 77, 1, 1 << 20, F_ALL, LEN(F_ALL));
    CHECK(a != NULL, "1er socket : promisc + fanout 77");
    CHECK(b != NULL, "2e socket : même groupe, mêmes options");
    cap_close(a);
    cap_close(b);
}

static void t_open_fanout_incompatible(void) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *a = cap_open("lo", 78, 0, 1 << 20, F_ALL, LEN(F_ALL));
    int fds_avant = count_fds();
    Capture *b = cap_open("lo", 78, 0, 1 << 20, F_ALL, LEN(F_ALL));   /* même groupe : accepté */
    CHECK(a != NULL && b != NULL, "deux sockets dans le groupe 78");
    cap_close(b);
    CHECK_EQ(count_fds(), fds_avant, "pas de descripteur perdu");
    cap_close(a);
}

static void t_pas_de_fuite_de_fd(void) {
    if (!can_capture()) return;
    arm_timeout();
    int avant = count_fds();
    for (int i = 0; i < 100; i++) {
        Capture *cap = open_lo(i % 2 ? 90 : -1, F_ALL, LEN(F_ALL));
        cap_close(cap);
    }
    CHECK_EQ(count_fds(), avant, "100 ouvertures / fermetures : aucun fd perdu");
}

/* ═══════════════════════════ 3. réception (root) ═══════════════════════════ */

static void t_recv_udp(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    int sink = udp_sink(41001);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41001; c.expected_len = 14 + 20 + 8 + 20; c.stop_after = 40;   /* 20 datagrammes, vus 2 fois */
    CHECK_EQ(udp_burst(41001, 20, 20, 0), 20, "20 datagrammes envoyés");
    watchdog(&stop, 3000);
    long long r = run_mode(mode, cap, &c, &stop, 100, NULL, 0);
    CHECK(c.n_udp >= 20, "au moins les 20 datagrammes sont vus");
    CHECK(c.n_udp <= 40, "pas plus de 2 fois chacun (sortant + entrant)");
    CHECK_EQ(c.bad_len, 0, "chaque trame fait 14 + 20 + 8 + 20 = 62 octets");
    CHECK_EQ(r, c.n_all, "valeur de retour == nombre de trames passées à on_frame");
    close(sink);
    cap_close(cap);
}
BOTH(t_recv_udp)

static void t_rafale(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    int sink = udp_sink(41002);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41002; c.expected_len = 14 + 20 + 8 + 100; c.stop_after = 400;
    int sent = udp_burst(41002, 200, 100, 0);
    CHECK_EQ(sent, 200, "200 datagrammes envoyés");
    watchdog(&stop, 4000);
    run_mode(mode, cap, &c, &stop, 100, NULL, 0);
    CHECK(c.n_udp >= 200, "aucune trame perdue dans la rafale (lots de 8, 4 tours max)");
    CHECK_EQ(c.bad_len, 0, "toutes les trames ont la bonne taille");
    uint64_t recv = 0, drop = 0;
    CHECK_EQ(cap_stats(cap, &recv, &drop), 0, "cap_stats");
    CHECK_EQ(drop, 0, "le noyau n'a rien jeté");
    close(sink);
    cap_close(cap);
}
BOTH(t_rafale)

static void t_grande_trame(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    FILE *f = fopen("/sys/class/net/lo/mtu", "r");
    int mtu = 0;
    if (f) { if (fscanf(f, "%d", &mtu) != 1) mtu = 0; fclose(f); }
    if (mtu < 61000) { printf("      (ignoré : MTU de lo = %d)\n", mtu); return; }
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    int sink = udp_sink(41003);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41003; c.expected_len = 14 + 20 + 8 + 60000; c.stop_after = 2;
    udp_burst(41003, 1, 60000, 0);
    watchdog(&stop, 3000);
    run_mode(mode, cap, &c, &stop, 100, NULL, 0);
    CHECK(c.n_udp >= 1, "la grande trame est reçue");
    CHECK_EQ(c.bad_len, 0, "entière : 60 042 octets, ni coupée ni déformée");
    close(sink);
    cap_close(cap);
}
BOTH(t_grande_trame)

/* ═══════════════════════════ 4. filtre BPF ═══════════════════════════ */

static void t_bpf_rejette_tout(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_NONE, LEN(F_NONE));
    int sink = udp_sink(41004);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop;
    udp_burst(41004, 10, 20, 0);
    watchdog(&stop, 500);
    run_mode(mode, cap, &c, &stop, 100, NULL, 0);
    CHECK_EQ(c.n_all, 0, "filtre « tout jeter » : aucune trame ne passe");
    close(sink);
    cap_close(cap);
}
BOTH(t_bpf_rejette_tout)

static void t_bpf_ipv4_seulement(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    int v6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (v6 < 0) { printf("      (ignoré : pas d'IPv6)\n"); return; }
    Capture *cap = open_lo(-1, F_IPV4, LEN(F_IPV4));
    int sink = udp_sink(41005);
    struct sockaddr_in6 to; memset(&to, 0, sizeof to);
    to.sin6_family = AF_INET6; to.sin6_port = htons(41006); inet_pton(AF_INET6, "::1", &to.sin6_addr);
    int sent6 = 0;
    for (int i = 0; i < 10; i++) if (sendto(v6, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == 1) sent6++;
    close(v6);
    udp_burst(41005, 10, 20, 0);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41005;
    watchdog(&stop, 800);
    run_mode(mode, cap, &c, &stop, 100, NULL, 0);
    CHECK(c.n_udp >= 10, "l'IPv4 passe");
    CHECK_EQ(c.n_v6, 0, "l'IPv6 est filtré par le noyau");
    if (sent6 == 0) printf("      (info : aucun paquet IPv6 n'a pu être envoyé)\n");
    close(sink);
    cap_close(cap);
}
BOTH(t_bpf_ipv4_seulement)

/* ═══════════════════════════ 5. arrêt et ménage ═══════════════════════════ */

static void t_stop_deja_leve(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    _Atomic uint8_t stop = 1;
    struct Cnt c; memset(&c, 0, sizeof c);
    uint64_t t0 = monotonic_ms();
    long long r = run_mode(mode, cap, &c, &stop, 2000, clear_cnt, 5);
    CHECK(monotonic_ms() - t0 < 500, "stop déjà levé : retour immédiat, sans attendre le délai de 2 s");
    CHECK_EQ(r, 0, "rien traité → 0");
    CHECK_EQ(c.n_all, 0, "aucune trame");
    cap_close(cap);
}
BOTH(t_stop_deja_leve)

static void t_silence_et_ctrl_c(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_NONE, LEN(F_NONE));      /* rien ne passera : silence total */
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    watchdog(&stop, 600);
    uint64_t t0 = monotonic_ms();
    long long r = run_mode(mode, cap, &c, &stop, 100, clear_cnt, 5);
    uint64_t dt = monotonic_ms() - t0;
    CHECK(dt >= 500 && dt < 1500, "retourne peu après que stop est levé (600 ms)");
    CHECK_EQ(r, 0, "aucune trame : 0");
    CHECK(c.n_clear >= 2, "pendant le silence, clear_fn (ft_expire) est appelée à chaque délai écoulé");
    cap_close(cap);
}
BOTH(t_silence_et_ctrl_c)

static void t_clear_fn_pendant_le_trafic(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    int sink = udp_sink(41007);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41007;
    struct Traffic tr = { 41007, 200, 20, 2000 };        /* 200 datagrammes, un toutes les 2 ms : ~400 ms de trafic */
    pthread_t t;
    pthread_create(&t, NULL, traffic_thread, &tr);
    watchdog(&stop, 900);
    run_mode(mode, cap, &c, &stop, 100, clear_cnt, 5);
    pthread_join(t, NULL);
    CHECK(c.n_udp >= 200, "tout le trafic est vu");
    CHECK(c.n_clear >= 1, "clear_fn est appelée périodiquement MÊME quand le trafic ne s'arrête pas");
    close(sink);
    cap_close(cap);
}
BOTH(t_clear_fn_pendant_le_trafic)

static void t_clear_fn_null(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    int sink = udp_sink(41008);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41008;
    udp_burst(41008, 10, 20, 0);
    watchdog(&stop, 500);
    run_mode(mode, cap, &c, &stop, 100, NULL, 3);          /* clear_fn NULL : ne doit pas planter */
    CHECK(c.n_udp >= 10, "ça marche sans clear_fn");
    close(sink);
    cap_close(cap);
}
BOTH(t_clear_fn_null)

/* ═══════════════════════════ 6. statistiques du noyau ═══════════════════════════ */

static void t_stats_noyau(void) {
    if (!can_capture()) return;
    arm_timeout();
    Capture *cap = open_lo(-1, F_ALL, LEN(F_ALL));
    int sink = udp_sink(41009);
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop; c.dport = 41009; c.stop_after = 30;
    udp_burst(41009, 30, 20, 0);
    watchdog(&stop, 3000);
    run_mode(0, cap, &c, &stop, 100, NULL, 0);
    uint64_t r = 0, d = 99;
    CHECK_EQ(cap_stats(cap, &r, &d), 0, "cap_stats → 0");
    CHECK(r >= 30, "le noyau a livré au moins 30 trames");
    CHECK_EQ(d, 0, "aucune perte");
    CHECK_EQ(cap_stats(cap, &r, &d), 0, "2e lecture");
    CHECK_EQ(r, 0, "la lecture remet les compteurs à zéro");
    close(sink);
    cap_close(cap);
}

/* ═══════════════════════════ 7. fanout : deux sockets, un groupe ═══════════════════════════ */

#define NFLOWS 40
struct Fan { Capture *cap; int mode; _Atomic uint8_t *stop; int seen[NFLOWS]; int total; };

static void on_frame_fan(const uint8_t *f, int len, void *ctx) {
    struct Fan *fan = ctx;
    ParserResult pr = parse(f, len);
    if (pr.code != SUCCES || pr.type != IPV4 || pr.ip_data.ipv4.proto != UDP) return;
    int sp = port_to_u16(pr.data.udp.src_port), dp = port_to_u16(pr.data.udp.dst_port);
    int lo = sp < dp ? sp : dp;
    if (lo < 42000 || lo >= 42000 + 2 * NFLOWS) return;
    fan -> seen[(lo - 42000) / 2]++;
    fan -> total++;
}
static void *fan_thread(void *a) {
    struct Fan *fan = a;
    if (fan -> mode == 0) {
        uint8_t *buf = malloc(CAP_MAX_FRAME);
        cap_recv(fan -> cap, buf, CAP_MAX_FRAME, 100, on_frame_fan, NULL, 0, fan, fan -> stop);
        free(buf);
    } else {
        cap_recv_mmsg(fan -> cap, CAP_MAX_FRAME, 100, on_frame_fan, NULL, 0, fan, fan -> stop, 8, 4);
    }
    return NULL;
}

static void t_fanout(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    _Atomic uint8_t stop = 0;
    struct Fan fans[2];
    memset(fans, 0, sizeof fans);
    pthread_t th[2];
    for (int i = 0; i < 2; i++) {
        fans[i].cap = open_lo(55, F_ALL, LEN(F_ALL));
        fans[i].mode = mode;
        fans[i].stop = &stop;
        CHECK(fans[i].cap != NULL, "socket du groupe 55 ouvert");
        if (fans[i].cap == NULL) return;
    }
    for (int i = 0; i < 2; i++) pthread_create(&th[i], NULL, fan_thread, &fans[i]);
    sleep_ms(100);

    /* NFLOWS conversations : A (port 42000+2i) <-> B (port 42001+2i), 3 datagrammes dans chaque sens */
    int sa[NFLOWS], sb[NFLOWS];
    for (int i = 0; i < NFLOWS; i++) {
        sa[i] = udp_sink((uint16_t)(42000 + 2 * i));
        sb[i] = udp_sink((uint16_t)(42001 + 2 * i));
        struct sockaddr_in a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
        a.sin_family = b.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr); inet_pton(AF_INET, "127.0.0.1", &b.sin_addr);
        a.sin_port = htons((uint16_t)(42000 + 2 * i)); b.sin_port = htons((uint16_t)(42001 + 2 * i));
        for (int k = 0; k < 3; k++) {
            sendto(sa[i], "ab", 2, 0, (struct sockaddr *)&b, sizeof b);     /* A → B */
            sendto(sb[i], "ba", 2, 0, (struct sockaddr *)&a, sizeof a);     /* B → A */
        }
    }
    sleep_ms(500);
    atomic_store(&stop, 1);
    for (int i = 0; i < 2; i++) pthread_join(th[i], NULL);

    int partages = 0, perdus = 0, chez0 = 0, chez1 = 0;
    for (int i = 0; i < NFLOWS; i++) {
        int s0 = fans[0].seen[i] > 0, s1 = fans[1].seen[i] > 0;
        if (s0 && s1) partages++;
        if (!s0 && !s1) perdus++;
        chez0 += s0; chez1 += s1;
    }
    CHECK_EQ(partages, 0, "une conversation n'est JAMAIS coupée entre les deux sockets (A→B et B→A ensemble)");
    CHECK_EQ(perdus, 0, "aucune conversation n'a disparu");
    CHECK(fans[0].total + fans[1].total >= NFLOWS * 6, "au moins 6 trames par conversation au total");
    CHECK(chez0 > 0 && chez1 > 0, "le noyau a réparti les conversations entre les deux sockets");
    printf("      · info : socket 0 = %d conversations, socket 1 = %d\n", chez0, chez1);
    for (int i = 0; i < NFLOWS; i++) { close(sa[i]); close(sb[i]); }
    for (int i = 0; i < 2; i++) cap_close(fans[i].cap);
}
BOTH(t_fanout)

/* ═══════════════════════════ 8. de bout en bout : capture → parser → table de flux ═══════════════════════════ */

/* ce que le moteur fait pour de vrai : on_frame = parse + ft_process, la fonction « vide » = ft_expire */
static void on_frame_ft(const uint8_t *frame, int len, void *ctx) {
    FnProcessCtx *c = ctx;
    ParserResult pr = parse(frame, len);
    c -> stats.ft_n_processed++;
    if (ft_process(c -> ft, &pr, realtime_ms()) == 0) c -> stats.ft_n_ok++;
    else c -> stats.ft_n_failed++;
}
static void empty_ft(void *ctx) {
    FnProcessCtx *c = ctx;
    ft_expire(c -> ft, realtime_ms());
}

struct Got { int n; FlowRecord rec[64]; };
static void sink_collect(const FlowRecord *r, void *ctx) {
    struct Got *g = ctx;
    if (g -> n < 64) g -> rec[g -> n] = *r;
    g -> n++;
}

static uint16_t g_srv_port;
static pthread_barrier_t g_ready;
static void *tcp_server(void *a) {
    (void)a;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET; inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bind(ls, (struct sockaddr *)&addr, sizeof addr);
    socklen_t l = sizeof addr;
    getsockname(ls, (struct sockaddr *)&addr, &l);
    g_srv_port = ntohs(addr.sin_port);
    listen(ls, 1);
    pthread_barrier_wait(&g_ready);
    int c = accept(ls, NULL, NULL);
    char b[16];
    if (c >= 0) { if (recv(c, b, sizeof b, 0) > 0) send(c, "pong", 4, 0); close(c); }
    close(ls);
    return NULL;
}

static void t_flux_de_bout_en_bout(int mode) {
    if (!can_capture()) return;
    arm_timeout();
    static struct Got got;
    memset(&got, 0, sizeof got);
    FnProcessCtx ctx;
    memset(&ctx, 0, sizeof ctx);
    struct FlowHooks h = {0};
    h.idle_ms = 60000; h.close_on_tcp_end = 1; h.sink = sink_collect; h.ctx = &got;
    ctx.ft = ft_create_with(1024, &h);
    Capture *cap = open_lo(-1, F_IPV4, LEN(F_IPV4));
    CHECK(ctx.ft != NULL && cap != NULL, "table et capture créées");
    if (ctx.ft == NULL || cap == NULL) return;

    _Atomic uint8_t stop = 0;
    watchdog(&stop, 1500);
    uint8_t *buf = malloc(CAP_MAX_FRAME);

    pthread_barrier_init(&g_ready, NULL, 2);
    pthread_t srv;
    pthread_create(&srv, NULL, tcp_server, NULL);
    pthread_barrier_wait(&g_ready);
    int usink = udp_sink(41010);
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to; memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_port = htons(g_srv_port); inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    CHECK_EQ(connect(cl, (struct sockaddr *)&to, sizeof to), 0, "connexion TCP locale");
    send(cl, "ping", 4, 0);
    char rep[16];
    recv(cl, rep, sizeof rep, 0);
    close(cl);
    pthread_join(srv, NULL);
    pthread_barrier_destroy(&g_ready);
    udp_burst(41010, 10, 20, 0);
    close(usink);

    /* tout est déjà dans la file du socket : on le lit maintenant */
    if (mode == 0) cap_recv(cap, buf, CAP_MAX_FRAME, 100, on_frame_ft, empty_ft, 10, &ctx, &stop);
    else cap_recv_mmsg(cap, CAP_MAX_FRAME, 100, on_frame_ft, empty_ft, 10, &ctx, &stop, 16, 8);
    free(buf);

    CHECK(ctx.stats.ft_n_processed > 0, "des trames ont été traitées");
    CHECK_EQ(ctx.stats.ft_n_ok + ctx.stats.ft_n_failed, ctx.stats.ft_n_processed, "ok + échecs == traitées");
    CHECK(ctx.stats.ft_n_ok > 0, "ft_process a accepté des paquets");
    ft_destroy(ctx.ft);                       /* envoie les flux restants au sink */

    int tcp = 0, udp = 0, syn_vu = 0;
    uint64_t udp_octets = 0;
    for (int i = 0; i < got.n && i < 64; i++) {
        const FlowData *d = &got.rec[i].data;
        if (d -> proto == TCP) {
            tcp++;
            if (d -> flag_count.syn > 0) syn_vu = 1;
        }
        if (d -> proto == UDP) {
            udp++;
            udp_octets += d -> octets_data_ltr + d -> octets_data_rtl;
        }
    }
    CHECK(tcp >= 1, "au moins un flux TCP est arrivé jusqu'au sink");
    CHECK(syn_vu, "le SYN de la connexion est compté dans un flux");
    CHECK(udp >= 1, "le flux UDP est arrivé jusqu'au sink");
    CHECK(udp_octets >= 10 * 62, "octets UDP comptés (au moins 10 trames de 62 octets)");
    cap_close(cap);
}
BOTH(t_flux_de_bout_en_bout)

/* ═══════════════════════════ 9. TON interface (CAP_IFACE) ═══════════════════════════ */

static void t_iface_utilisateur(void) {
    if (!can_capture()) return;
    arm_timeout();
    const char *name = getenv("CAP_IFACE");
    if (name == NULL || *name == '\0') name = "lo";
    Capture *cap = cap_open(name, -1, 0, 4 * 1024 * 1024, F_ALL, LEN(F_ALL));
    CHECK(cap != NULL, "cap_open sur l'interface choisie");
    if (cap == NULL) { printf("      (interface testée : %s)\n", name); return; }
    _Atomic uint8_t stop = 0;
    struct Cnt c; memset(&c, 0, sizeof c);
    c.stop = &stop;
    watchdog(&stop, 3000);
    printf("      (interface %s : lance du trafic maintenant, capture pendant 3 s)\n", name);
    long long r = run_mode(1, cap, &c, &stop, 100, clear_cnt, 10);
    uint64_t rec = 0, drop = 0;
    CHECK_EQ(cap_stats(cap, &rec, &drop), 0, "cap_stats");
    printf("      · info : %d trames vues, retour %lld, noyau : reçues %llu, perdues %llu\n",
           c.n_all, r, (unsigned long long)rec, (unsigned long long)drop);
    cap_close(cap);
}

/* ═══════════════════════════ main ═══════════════════════════ */

int main(int argc, char **argv) {
    tc_begin("test_capture.c", argc, argv);

    printf("\n── 1. arguments (sans root) ──\n");
    RUN_LEAKS("arguments : cap_open",                 t_args_open);
    RUN_LEAKS("arguments : cap_recv",                 t_args_recv);
    RUN_LEAKS("arguments : cap_recv_mmsg",            t_args_mmsg);
    RUN_LEAKS("arguments : cap_stats et cap_close",   t_args_stats_close);

    printf("\n── 2. ouverture / fermeture ──\n");
    RUN_LEAKS("open : ouvrir et fermer lo",           t_open_close);
    RUN_LEAKS("open : sans filtre (NULL, 0)",         t_open_sans_filtre);
    RUN_LEAKS("open : promisc + fanout",              t_open_promisc_fanout);
    RUN_LEAKS("open : deux sockets, même groupe",     t_open_fanout_incompatible);
    RUN_LEAKS("open : aucun fd perdu (100 cycles)",   t_pas_de_fuite_de_fd);

    printf("\n── 3. réception ──\n");
    RUN_LEAKS("recv : datagrammes UDP sur lo",        t_recv_udp_recv);
    RUN_LEAKS("mmsg : datagrammes UDP sur lo",        t_recv_udp_mmsg);
    RUN_LEAKS("recv : rafale de 200",                 t_rafale_recv);
    RUN_LEAKS("mmsg : rafale de 200 (lots de 8)",     t_rafale_mmsg);
    RUN_LEAKS("recv : grande trame (60 Ko)",          t_grande_trame_recv);
    RUN_LEAKS("mmsg : grande trame (60 Ko)",          t_grande_trame_mmsg);

    printf("\n── 4. filtre BPF ──\n");
    RUN_LEAKS("recv : BPF qui jette tout",            t_bpf_rejette_tout_recv);
    RUN_LEAKS("mmsg : BPF qui jette tout",            t_bpf_rejette_tout_mmsg);
    RUN_LEAKS("recv : BPF IPv4 seulement",            t_bpf_ipv4_seulement_recv);
    RUN_LEAKS("mmsg : BPF IPv4 seulement",            t_bpf_ipv4_seulement_mmsg);

    printf("\n── 5. arrêt et ménage ──\n");
    RUN_LEAKS("recv : stop déjà levé",                t_stop_deja_leve_recv);
    RUN_LEAKS("mmsg : stop déjà levé",                t_stop_deja_leve_mmsg);
    RUN_LEAKS("recv : silence, puis Ctrl-C",          t_silence_et_ctrl_c_recv);
    RUN_LEAKS("mmsg : silence, puis Ctrl-C",          t_silence_et_ctrl_c_mmsg);
    RUN_LEAKS("recv : clear_fn pendant le trafic",    t_clear_fn_pendant_le_trafic_recv);
    RUN_LEAKS("mmsg : clear_fn pendant le trafic",    t_clear_fn_pendant_le_trafic_mmsg);
    RUN_LEAKS("recv : clear_fn NULL",                 t_clear_fn_null_recv);
    RUN_LEAKS("mmsg : clear_fn NULL",                 t_clear_fn_null_mmsg);

    printf("\n── 6. statistiques du noyau ──\n");
    RUN_LEAKS("stats : reçues, perdues, remise à zéro", t_stats_noyau);

    printf("\n── 7. fanout ──\n");
    RUN_LEAKS("recv : fanout, 2 sockets, 40 conversations", t_fanout_recv);
    RUN_LEAKS("mmsg : fanout, 2 sockets, 40 conversations", t_fanout_mmsg);

    printf("\n── 8. de bout en bout (capture → parser → table) ──\n");
    RUN_LEAKS("recv : TCP + UDP jusqu'au sink",       t_flux_de_bout_en_bout_recv);
    RUN_LEAKS("mmsg : TCP + UDP jusqu'au sink",       t_flux_de_bout_en_bout_mmsg);

    printf("\n── 9. ton interface (CAP_IFACE) ──\n");
    RUN("iface : ouvrir, capturer 3 s, stats",        t_iface_utilisateur);

    return tc_end();
}
