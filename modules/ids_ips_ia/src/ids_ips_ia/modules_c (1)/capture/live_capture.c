/* live_capture.c : test « en vrai » du module de capture sur UNE interface que tu choisis.
 *
 * Compiler (depuis modules_c/) :
 *   gcc -std=gnu11 -O2 -Wall -Wextra -pthread capture/capture.c capture/live_capture.c parser/parser.c \
 *       flows/flow.c flows/flow_table.c dict/dict.c dchained_list/dchained_list.c portmap/portmap.c \
 *       utils/utils.c rules/rules.c -o build/live_capture
 *
 * Lancer (root ou CAP_NET_RAW) :
 *   sudo build/live_capture <interface> [-t threads] [-m recv|mmsg] [-d secondes] [-b Mo] [-g groupe] [-p]
 *     -t  nombre de threads (une Capture + une table de flux chacune ; fanout si > 1)     défaut 1
 *     -m  recv = cap_recv (1 trame par appel) · mmsg = cap_recv_mmsg (lots)                défaut mmsg
 *     -d  durée en secondes (0 = jusqu'à Ctrl-C)                                           défaut 0
 *     -b  taille du tampon du noyau en Mo                                                  défaut 16
 *     -g  numéro du groupe fanout                                                          défaut 42
 *     -p  mode promiscuous
 * Exemple :  sudo build/live_capture veth0 -t 2 -m mmsg -d 30
 * Le trafic, c'est toi qui le lances (ping, curl, nmap, iperf3, un script...). */
#include <arpa/inet.h>
#include <linux/filter.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "capture.h"
#include "../parser/parser.h"
#include "../flows/flow_table.h"
#include "../utils/utils.h"

#define MAX_THREADS 16

static _Atomic uint8_t g_stop = 0;                      /* levé par Ctrl-C ou par -d ; lu par toutes les threads */
static void on_signal(int sig){ (void)sig; atomic_store(&g_stop, 1); }

/* Filtre BPF : IPv4, IPv6, ARP, VLAN, QinQ. Le noyau jette le reste (LLDP, STP...). */
static struct sock_filter FILTER[] = {
    BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86DD, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0806, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8100, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88A8, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, 0),
    BPF_STMT(BPF_RET | BPF_K, 0x40000),
};

struct Config {
    const char *ifname;
    int n_threads, use_mmsg, duration_s, buffer_mb, group, promisc;
};

struct Worker {
    pthread_t thread;
    int id;
    const struct Config *cfg;
    FnProcessCtx ctx;                                    /* la table de flux + les compteurs de CETTE thread */
    int failed;
};

/* ce que fait la capture pour chaque trame : octets → fiche → table de flux */
static void on_frame(const uint8_t *frame, int len, void *ctx){
    FnProcessCtx *c = ctx;
    ParserResult pr = parse(frame, len);
    c -> stats.ft_n_processed++;
    if (ft_process(c -> ft, &pr, realtime_ms()) == 0) c -> stats.ft_n_ok++;
    else c -> stats.ft_n_failed++;
}

/* la fonction « vide » : appelée quand rien n'arrive, et régulièrement pendant le trafic → ménage de la table */
static void on_idle(void *ctx){
    FnProcessCtx *c = ctx;
    ft_expire(c -> ft, realtime_ms());
}

/* le sink : un flux qui part de la table. Ici on l'affiche ; plus tard on le copiera dans le ring. */
static void print_flow(const FlowRecord *rec, void *ctx){
    static const char *reasons[] = {"?", "inactif", "tcp-fini", "chasse", "arret", "duree-max"};
    const int *id = ctx;
    const FlowData *d = &rec -> data;
    char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
    int fam = d -> v4 ? AF_INET : AF_INET6;
    const uint8_t *ip_a = d -> v4 ? d -> header.ipv4_headers.initiator_ip : d -> header.ipv6_headers.initiator_ip;
    const uint8_t *ip_b = d -> v4 ? d -> header.ipv4_headers.receiver_ip  : d -> header.ipv6_headers.receiver_ip;
    const uint8_t *pt_a = d -> v4 ? d -> header.ipv4_headers.initiator_port : d -> header.ipv6_headers.initiator_port;
    const uint8_t *pt_b = d -> v4 ? d -> header.ipv4_headers.receiver_port  : d -> header.ipv6_headers.receiver_port;
    inet_ntop(fam, ip_a, a, sizeof(a));
    inet_ntop(fam, ip_b, b, sizeof(b));
    printf("[t%d] proto %-3u %s:%u -> %s:%u  paquets %u/%u  octets %llu/%llu  verdict %d  (%s)\n",
           *id, d -> proto, a, port_to_u16(pt_a), b, port_to_u16(pt_b), d -> n_pkt_ltr, d -> n_pkt_rtl,
           (unsigned long long)d -> octets_data_ltr, (unsigned long long)d -> octets_data_rtl,
           (int)d -> verdict, reasons[rec -> reason <= 5 ? rec -> reason : 0]);
}

static void *worker(void *arg){
    struct Worker *w = arg;
    const struct Config *cfg = w -> cfg;

    Capture *cap = cap_open(cfg -> ifname, cfg -> n_threads > 1 ? cfg -> group : -1, cfg -> promisc,
                            cfg -> buffer_mb * 1024 * 1024, FILTER, (int)(sizeof(FILTER) / sizeof(FILTER[0])));
    if (cap == NULL){
        fprintf(stderr, "[t%d] cap_open(%s) a échoué (root ? interface ?)\n", w -> id, cfg -> ifname);
        w -> failed = 1;
        return NULL;
    }
    struct FlowHooks h = {0};
    h.idle_ms = 30000;                                   /* 30 s sans paquet : le flux part */
    h.max_ms = 300000;                                   /* 5 min : instantané, puis il repart de zéro */
    h.close_on_tcp_end = 1;
    h.check = rule_port_scan;
    h.sink = print_flow;
    h.ctx = &w -> id;
    w -> ctx.ft = ft_create_with(65536, &h);
    if (w -> ctx.ft == NULL){
        fprintf(stderr, "[t%d] ft_create_with a échoué\n", w -> id);
        w -> failed = 1;
        cap_close(cap);
        return NULL;
    }

    long long r;
    if (cfg -> use_mmsg){
        r = cap_recv_mmsg(cap, CAP_MAX_FRAME, 1000, on_frame, on_idle, 10, &w -> ctx, &g_stop, 64, 16);
    } else {
        uint8_t *buf = malloc(CAP_MAX_FRAME);
        r = buf ? cap_recv(cap, buf, CAP_MAX_FRAME, 1000, on_frame, on_idle, 10, &w -> ctx, &g_stop) : -1;
        free(buf);
    }
    if (r < 0) fprintf(stderr, "[t%d] la réception s'est terminée sur une erreur (%lld)\n", w -> id, r);

    uint64_t kr = 0, kd = 0;
    if (cap_stats(cap, &kr, &kd) == 0){ w -> ctx.stats.kernel_recv = kr; w -> ctx.stats.kernel_drop = kd; }
    ft_destroy(w -> ctx.ft);                             /* envoie les flux restants au sink (raison : arret) */
    cap_close(cap);
    return NULL;
}

static void usage(const char *prog){
    fprintf(stderr, "usage : %s <interface> [-t threads] [-m recv|mmsg] [-d secondes] [-b Mo] [-g groupe] [-p]\n", prog);
}

int main(int argc, char **argv){
    if (argc < 2){ usage(argv[0]); return 1; }
    struct Config cfg = { argv[1], 1, 1, 0, 16, 42, 0 };
    for (int i = 2; i < argc; i++){
        if (!strcmp(argv[i], "-p")) cfg.promisc = 1;
        else if (i + 1 < argc && !strcmp(argv[i], "-t")) cfg.n_threads = atoi(argv[++i]);
        else if (i + 1 < argc && !strcmp(argv[i], "-d")) cfg.duration_s = atoi(argv[++i]);
        else if (i + 1 < argc && !strcmp(argv[i], "-b")) cfg.buffer_mb = atoi(argv[++i]);
        else if (i + 1 < argc && !strcmp(argv[i], "-g")) cfg.group = atoi(argv[++i]);
        else if (i + 1 < argc && !strcmp(argv[i], "-m")) cfg.use_mmsg = !strcmp(argv[++i], "mmsg");
        else { usage(argv[0]); return 1; }
    }
    if (cfg.n_threads < 1 || cfg.n_threads > MAX_THREADS) cfg.n_threads = 1;
    if (cfg.buffer_mb < 1) cfg.buffer_mb = 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;                           /* sans SA_RESTART : poll() est interrompu et rend la main */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("capture sur %s : %d thread(s), mode %s, tampon %d Mo, groupe fanout %d%s. Ctrl-C pour arrêter.\n",
           cfg.ifname, cfg.n_threads, cfg.use_mmsg ? "mmsg" : "recv", cfg.buffer_mb, cfg.group,
           cfg.n_threads > 1 ? "" : " (ignoré : 1 seule thread)");

    static struct Worker workers[MAX_THREADS];
    memset(workers, 0, sizeof(workers));
    for (int i = 0; i < cfg.n_threads; i++){
        workers[i].id = i;
        workers[i].cfg = &cfg;
        pthread_create(&workers[i].thread, NULL, worker, &workers[i]);
    }

    /* le thread principal affiche un point de situation toutes les 2 s (lecture approximative : sans verrou) */
    for (int s = 0; !atomic_load(&g_stop); s++){
        sleep(1);
        if (cfg.duration_s > 0 && s + 1 >= cfg.duration_s) atomic_store(&g_stop, 1);
        if (s % 2 == 1){
            unsigned long long ok = 0, ko = 0;
            for (int i = 0; i < cfg.n_threads; i++){ ok += workers[i].ctx.stats.ft_n_ok; ko += workers[i].ctx.stats.ft_n_failed; }
            printf("[%3ds] trames acceptées %llu · refusées %llu\n", s + 1, ok, ko);
        }
    }
    for (int i = 0; i < cfg.n_threads; i++) pthread_join(workers[i].thread, NULL);

    printf("\n── bilan ──\n");
    for (int i = 0; i < cfg.n_threads; i++){
        const CapStats *s = &workers[i].ctx.stats;
        printf("[t%d] traitées %llu · ft_process ok %llu, refusées %llu · noyau : reçues %llu, perdues %llu\n", i,
               (unsigned long long)s -> ft_n_processed, (unsigned long long)s -> ft_n_ok, (unsigned long long)s -> ft_n_failed,
               (unsigned long long)s -> kernel_recv, (unsigned long long)s -> kernel_drop);
    }
    return 0;
}
