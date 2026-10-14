#ifndef CAPTURE_C_H
#define CAPTURE_C_H
#include "../flows/flow_table.h"
#include <stdint.h>
#include <stddef.h>
#include <linux/filter.h>

// Taille du buffer à fournir à cap_receive : Ethernet (14) + 2 tags VLAN (8) + IP max (65535), avec une marge
#define CAP_MAX_FRAME 65600

// Une « oreille » collée à UNE interface réseau (Linux, AF_PACKET). Il faut être root ou avoir CAP_NET_RAW.
// Une Capture par thread : chacune a son socket, sa table de flux, et le noyau répartit les paquets entre elles (fanout).
struct Capture{
    int fd;                     // le socket
    int ifindex;                // numéro de l'interface (eth0 = 2, par exemple)
};
typedef struct Capture Capture;

struct CapStats{
    uint64_t ft_n_ok;
    uint64_t ft_n_failed;
    uint64_t ft_n_processed;
    uint64_t kernel_recv;
    uint64_t kernel_drop;
};
typedef struct CapStats CapStats;

// ce que on frame reçoit
struct FnProcessCtx{
    FlowTable *ft;
    CapStats stats;
};
typedef struct FnProcessCtx FnProcessCtx;

// Les caractérisqtique d'un on frame valable
typedef void (*FrameFn)(const uint8_t *frame, int len, void *ctx);
typedef void (*EmptyFn)(void *ctx);

// ifname        : "eth0", "lo"...
// fanout_group  : -1 = pas de fanout ; sinon un numéro (0..65535) COMMUN à tous les threads de cette interface
// promisc       : 1 = voir aussi les trames qui ne sont pas pour cette machine
Capture *cap_open(
    const char *ifname, int fanout_group, int promisc, int buffer_size, 
    struct sock_filter *bpf_filter, int bpf_len
);   // NULL si échec

// Attend une trame au plus timeout_ms (comme read) :
//   > 0 = taille de la trame copiée dans buf · 0 = rien reçu (délai, ou signal) · -1 = erreur
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

// Compteurs du noyau DEPUIS LA DERNIÈRE LECTURE (la lecture les remet à zéro). 0 = ok, -1 = échec
// dropped = trames que le noyau a jetées parce que ton programme était trop lent
int cap_stats(Capture *cap, uint64_t *received, uint64_t *dropped);

void cap_close(Capture *cap);

#endif