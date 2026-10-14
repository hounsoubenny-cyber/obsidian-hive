#ifndef CAPTURE_C_H
#define CAPTURE_C_H
#include "../flows/flow_table.h"
#include <stdint.h>
#include <stddef.h>
#include <linux/filter.h>

#define CAP_MAX_FRAME 65600

/* ─────────── AF_PACKET ─────────── */
struct Capture{
    int fd;
    int ifindex;
};
typedef struct Capture Capture;

/* ─────────── pcap ─────────── */
struct CapturePcap{
    void *handle;        /* pcap_t*, void* pour ne pas inclure pcap.h ici */
    int  is_live;        /* 1 = live, 0 = fichier .pcap */
    char ifname[64];
};
typedef struct CapturePcap CapturePcap;

struct CapStats{
    uint64_t ft_n_ok;
    uint64_t ft_n_failed;
    uint64_t ft_n_processed;
    uint64_t kernel_recv;
    uint64_t kernel_drop;
};
typedef struct CapStats CapStats;

struct FnProcessCtx{
    FlowTable *ft;
    CapStats stats;
};
typedef struct FnProcessCtx FnProcessCtx;

typedef void (*FrameFn)(const uint8_t *frame, int len, void *ctx);
typedef void (*EmptyFn)(void *ctx);

/* ─────────── AF_PACKET : ouverture / réception ─────────── */
Capture *cap_open(
    const char *ifname, int fanout_group, int promisc, int buffer_size,
    struct sock_filter *bpf_filter, uint32_t bpf_len
);

long long int cap_recv(
    Capture *cap, uint8_t *buf, size_t size, int timeout_ms,
    FrameFn on_frame, EmptyFn clear_fn, uint8_t call_clear_fn_each,
    void *ctx, _Atomic uint8_t *stop
);

long long int cap_recv_mmsg(
    Capture *cap, uint64_t pkt_size, int timeout_ms,
    FrameFn on_frame, EmptyFn clear_fn, uint8_t call_clear_fn_each,
    void *ctx, _Atomic uint8_t *stop, uint32_t batch_size, uint16_t max_turns
);

int  cap_stats(Capture *cap, uint64_t *received, uint64_t *dropped);
void cap_close(Capture *cap);

/* ─────────── pcap : live et fichier ─────────── */

/* Live : capture sur une interface. `filter` = string BPF ("tcp or udp").
 * Retourne NULL si pcap indisponible ou erreur. */
CapturePcap *cap_pcap_open_live(
    const char *ifname, const char *filter,
    int snaplen, int promisc, int timeout_ms, int buffer_size
);

/* Fichier : lit un .pcap. `filter` peut être NULL. */
CapturePcap *cap_pcap_open_file(
    const char *path, const char *filter
);

/* Boucle pcap : lit les paquets, appelle on_frame.
 * Note : pcap_loop() ne respecte pas stop à l'intérieur d'un callback,
 * donc on utilise pcap_next_ex() dans une boucle manuelle.
 * Retourne le nombre de paquets traités, ou -1 sur erreur. */
long long int cap_pcap_recv(
    CapturePcap *cp,
    FrameFn on_frame, EmptyFn clear_fn, uint8_t call_clear_fn_each,
    void *ctx, _Atomic uint8_t *stop
);

int  cap_pcap_stats(CapturePcap *cp, uint64_t *received, uint64_t *dropped);
void cap_pcap_close(CapturePcap *cp);

#endif