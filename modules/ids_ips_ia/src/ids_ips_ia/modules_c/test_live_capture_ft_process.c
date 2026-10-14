/* live.c — version complète : 3 moteurs, durée flottante, vitesse, stats. */
#include <fcntl.h>
#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "capture/capture.h"
#include "parser/parser.h"
#include "flows/flow_table.h"
#include "utils/utils.h"

static _Atomic uint8_t g_stop = 0;
static _Atomic uint64_t g_n_flows = 0;   /* compteur de flux vus au sink */

static uint16_t port_of(const uint8_t p[2]){ return (uint16_t)((p[0]<<8)|p[1]); }

static const char *proto_name(uint8_t p){
    switch (p){ case 1: return "ICMP"; case 6: return "TCP"; case 17: return "UDP";
                case 58: return "ICMPv6"; default: return "?"; }
}

static void print_flow(const FlowRecord *rec, void *ctx){
    (void)ctx;
    g_n_flows++;
    /*const FlowData *d = &rec->data;
    char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
    int fam = d->v4 ? AF_INET : AF_INET6;
    const uint8_t *ia = d->v4 ? d->header.ipv4_headers.initiator_ip : d->header.ipv6_headers.initiator_ip;
    const uint8_t *ib = d->v4 ? d->header.ipv4_headers.receiver_ip  : d->header.ipv6_headers.receiver_ip;
    const uint8_t *pa = d->v4 ? d->header.ipv4_headers.initiator_port : d->header.ipv6_headers.initiator_port;
    const uint8_t *pb = d->v4 ? d->header.ipv4_headers.receiver_port  : d->header.ipv6_headers.receiver_port;
    inet_ntop(fam, ia, a, sizeof a);
    inet_ntop(fam, ib, b, sizeof b);
    printf("  FLUX  %-6s  %s:%u -> %s:%u  pkt=%u/%u  oct=%llu/%llu  syn=%u ack=%u fin=%u rst=%u\n",
           proto_name(d->proto), a, port_of(pa), b, port_of(pb),
           d->n_pkt_ltr, d->n_pkt_rtl,
           (unsigned long long)d->octets_data_ltr,
           (unsigned long long)d->octets_data_rtl,
           d->flag_count.syn, d->flag_count.ack,
           d->flag_count.fin, d->flag_count.rst);
    fflush(stdout);*/
}

struct Ctx { FlowTable *ft; uint64_t n_ok, n_fail; };

/*static void on_frame(const uint8_t *frame, int len, void *ctx){
    struct Ctx *c = ctx;
    ParserResult pr = parse(frame, len);
    c->n_ok++;
}*/

static void on_frame(const uint8_t *frame, int len, void *ctx){
    struct Ctx *c = ctx;
    ParserResult pr = parse(frame, len);
    int r = ft_process(c->ft, &pr, realtime_ms());
    if (r == 0) c->n_ok++;
    else        c->n_fail++;
}


static void on_empty(void *ctx){
    struct Ctx *c = ctx;
    ft_expire(c->ft, realtime_ms());
}

/* ─── arrêt avec durée flottante ─── */
struct StopArg { _Atomic uint8_t *stop; double sec; };

static void *stop_thread(void *arg){
    struct StopArg *a = arg;
    struct timespec ts;
    ts.tv_sec  = (time_t)a->sec;
    ts.tv_nsec = (long)((a->sec - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
    atomic_store_explicit(a->stop, 1, memory_order_release);
    return NULL;
}

/* ─── affichage final ─── */
static void report(const char *engine, long long n_cb, uint64_t ft_ok, uint64_t ft_fail,
                   uint64_t krecv, uint64_t kdrop, uint64_t dt_ms){
    double sec = (double)dt_ms / 1000.0;
    double rate = (sec > 0) ? (double)n_cb / sec : 0.0;
    printf("\n── Résumé %s ──\n", engine);
    printf("  durée        : %.3f s\n", sec);
    printf("  callback     : %lld paquets\n", n_cb);
    printf("  vitesse      : %.0f paquets/s\n", rate);
    printf("  ft_ok        : %llu\n", (unsigned long long)ft_ok);
    printf("  ft_fail      : %llu\n", (unsigned long long)ft_fail);
    printf("  flux (sink)  : %llu\n", (unsigned long long)g_n_flows);
    printf("  noyau        : reçus=%llu  perdus=%llu\n",
           (unsigned long long)krecv, (unsigned long long)kdrop);
    fflush(stdout);
}

/* ─── 3 moteurs ─── */
static void run_af_recv(const char *iface, double dur){
    Capture *cap = cap_open(iface, -1, 1, 256 << 20, NULL, 0);
    if (cap == NULL){ fprintf(stderr, "❌ cap_open(%s)\n", iface); return; }

    struct FlowHooks h = {0};
    h.idle_ms = 5000; h.max_ms = 60000; h.close_on_tcp_end = 1;
    h.sink = print_flow;

    struct Ctx ctx = {0};
    ctx.ft = ft_create_with(4096, &h);
    if (ctx.ft == NULL){ cap_close(cap); return; }

    uint8_t *buf = malloc(CAP_MAX_FRAME);
    if (buf == NULL){ ft_destroy(ctx.ft); cap_close(cap); return; }

    struct StopArg sa = { &g_stop, dur };
    pthread_t th; pthread_create(&th, NULL, stop_thread, &sa);

    uint64_t t0 = monotonic_ms();
    long long n = cap_recv(cap, buf, CAP_MAX_FRAME, 100,
                           on_frame, on_empty, 1, &ctx, &g_stop);
    uint64_t dt = monotonic_ms() - t0;

    pthread_join(th, NULL); free(buf);

    uint64_t rec = 0, drop = 0;
    cap_stats(cap, &rec, &drop);
    ft_destroy(ctx.ft);             /* flush les flux restants au sink */
    cap_close(cap);

    report("AF_PACKET + recv", n, ctx.n_ok, ctx.n_fail, rec, drop, dt);
}

static void run_af_mmsg(const char *iface, double dur){
    Capture *cap = cap_open(iface, -1, 1, 256 << 20, NULL, 0);
    if (cap == NULL){ fprintf(stderr, "❌ cap_open(%s)\n", iface); return; }

    struct FlowHooks h = {0};
    h.idle_ms = 5000; h.max_ms = 60000; h.close_on_tcp_end = 1;
    h.sink = print_flow;

    struct Ctx ctx = {0};
    ctx.ft = ft_create_with(4096, &h);
    if (ctx.ft == NULL){ cap_close(cap); return; }

    struct StopArg sa = { &g_stop, dur };
    pthread_t th; pthread_create(&th, NULL, stop_thread, &sa);

    uint64_t t0 = monotonic_ms();
    long long n = cap_recv_mmsg(cap, CAP_MAX_FRAME, 100,
                                on_frame, on_empty, 1, &ctx, &g_stop, 32, 8);
    uint64_t dt = monotonic_ms() - t0;

    pthread_join(th, NULL);

    uint64_t rec = 0, drop = 0;
    cap_stats(cap, &rec, &drop);
    ft_destroy(ctx.ft);
    cap_close(cap);

    report("AF_PACKET + recvmmsg", n, ctx.n_ok, ctx.n_fail, rec, drop, dt);
}

static void run_pcap(const char *iface, double dur, const char *filter){
    CapturePcap *cp = cap_pcap_open_live(iface, filter, 65535, 0, 100, 256 << 20);
    if (cp == NULL){ fprintf(stderr, "❌ cap_pcap_open_live(%s, \"%s\")\n", iface, filter); return; }

    struct FlowHooks h = {0};
    h.idle_ms = 5000; h.max_ms = 60000; h.close_on_tcp_end = 1;
    h.sink = print_flow;

    struct Ctx ctx = {0};
    ctx.ft = ft_create_with(4096, &h);
    if (ctx.ft == NULL){ cap_pcap_close(cp); return; }

    struct StopArg sa = { &g_stop, dur };
    pthread_t th; pthread_create(&th, NULL, stop_thread, &sa);

    uint64_t t0 = monotonic_ms();
    long long n = cap_pcap_recv(cp, on_frame, on_empty, 10, &ctx, &g_stop);
    uint64_t dt = monotonic_ms() - t0;

    pthread_join(th, NULL);

    uint64_t rec = 0, drop = 0;
    cap_pcap_stats(cp, &rec, &drop);
    ft_destroy(ctx.ft);
    cap_pcap_close(cp);

    report("pcap", n, ctx.n_ok, ctx.n_fail, rec, drop, dt);
}

int main(int argc, char **argv){
    if (argc < 4){
        fprintf(stderr, "usage : %s <iface> <moteur> <durée_s> [filtre]\n", argv[0]);
        fprintf(stderr, "  moteurs : af_recv | af_mmsg | pcap\n");
        fprintf(stderr, "  durée   : entier ou flottant (ex: 1.5)\n");
        fprintf(stderr, "  ex      : %s lo af_recv 15\n", argv[0]);
        fprintf(stderr, "  ex      : %s lo pcap 5.5 \"ip or ip6\"\n", argv[0]);
        return 1;
    }
    const char *iface  = argv[1];
    const char *engine = argv[2];
    char *end;
    errno = 0;
    double dur = strtod(argv[3], &end);
    if (end == argv[3] || *end != '\0' || errno != 0 || dur <= 0){
        fprintf(stderr, "durée invalide : %s\n", argv[3]);
        return 1;
    }
    const char *filter = (argc > 4) ? argv[4] : "ip or ip6";
    if (dur <= 0) dur = 10.0;

    printf("═══════════════════════════════════════════════\n");
    printf(" moteur=%s  iface=%s  durée=%.3f s\n", engine, iface, dur);
    if (strcmp(engine, "pcap") == 0) printf(" filtre=\"%s\"\n", filter);
    printf("═══════════════════════════════════════════════\n");
    printf(" Génère du trafic dans un autre terminal :\n");
    printf("   ping 127.0.0.1\n");
    printf("   curl http://127.0.0.1\n");
    printf("═══════════════════════════════════════════════\n\n");
    fflush(stdout);

    if      (strcmp(engine, "af_recv") == 0) run_af_recv(iface, dur);
    else if (strcmp(engine, "af_mmsg") == 0) run_af_mmsg(iface, dur);
    else if (strcmp(engine, "pcap")    == 0) run_pcap(iface, dur, filter);
    else { fprintf(stderr, "❌ moteur inconnu : %s\n", engine); return 1; }
    return 0;
}