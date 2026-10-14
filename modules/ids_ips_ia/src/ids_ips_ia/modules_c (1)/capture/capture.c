#define _GNU_SOURCE
#include "capture.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

// Filtre BPF
static int _attach_filter(int fd, struct sock_filter *code, int len){
    struct sock_fprog prog = { .len = len, .filter = code };
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0 ? 0 : -1;
}

// Fanout : tous les sockets du même groupe (même interface) se partagent le trafic.
// HASH = le noyau calcule un hash SYMÉTRIQUE (IP et ports) : A→B et B→A tombent chez le MÊME socket,
// donc chaque thread voit des flux entiers et sa table de flux reste cohérente. À faire APRÈS le bind.
static int _fanout(int fd, int group){
    int arg = (group & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
    return setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) == 0 ? 0 : -1;
}

// Lie le socket à l'interface : à partir d'ici, les trames (filtrées) arrivent
static int _bind(int fd, int ifindex){
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex;
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 ? 0 : -1;
}

static int _promisc(int fd, int ifindex){
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    return setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == 0 ? 0 : -1;
}


/* Rend le socket non-bloquant. Retourne 0 si OK, -1 si erreur. */
static int _set_nonblocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

/* Demande un tampon de réception de `size` octets. Retourne la taille
 * réellement accordée par le noyau (peut être plus petite si plafonnée).
 * En cas d'erreur, retourne -1. */
static int _set_rcvbuf(int fd, int size){
    /* SO_RCVBUFFORCE : dépasse net.core.rmem_max, mais exige CAP_NET_ADMIN.
     * Si refusé, on retombe sur SO_RCVBUF (soumis au plafond). */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0){
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0){
            return -1;
        }
    }
    int actual = 0;
    socklen_t len = sizeof(actual);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &len) < 0){
        return -1;
    }
    return actual;
}

/*
1. socket(AF_PACKET, SOCK_RAW, 0)          ← proto 0, muet
2. set_rcvbuf(fd, 64 Mo)                    ← tampon prêt
3. attach_bpf(fd, prog)                     ← filtre en place
4. bind(fd, {ifindex, protocol=ETH_P_ALL})  ← là ça reçoit
5. promiscuité                              ← si tu veux
6. non-bloquant
*/
Capture *cap_open(
    const char *ifname, int fanout_group, int promisc, int buffer_size, 
    struct sock_filter *bpf_filter, int bpf_len
){
    if (ifname == NULL || buffer_size < 0) return NULL;
    int ifindex = (int)if_nametoindex(ifname);
    if (ifindex == 0) return NULL;                        // interface inconnue
    
    // step 1
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) return NULL;                              // souvent : pas root / pas CAP_NET_RAW
    int size = _set_rcvbuf(fd, buffer_size);
    if (size < 0) {
        close(fd);
        return NULL;
    }
    printf("[INFO] Kernel buffer size %d, wanted %d", size, buffer_size);
    if (_attach_filter(fd, bpf_filter, bpf_len) != 0) {
        printf("[INFO] Filtre non attaché");
    }
    if (_bind(fd, ifindex) != 0){
        printf("[INFO] Socket non attaché");
        close(fd);
        return NULL;
    }

    if ((promisc && _promisc(fd, ifindex) != 0) ||
        (fanout_group >= 0 && _fanout(fd, fanout_group) != 0)){
        close(fd);
        return NULL;
    }

    Capture *cap = (Capture *)calloc(1, sizeof(Capture));
    if (cap == NULL){
        close(fd);
        return NULL;
    }
    cap -> fd = fd;
    cap -> ifindex = ifindex;
    return cap;
}

void cap_close(Capture *cap){
    if (cap == NULL) return;
    close(cap -> fd);
    free(cap);
}

int cap_stats(Capture *cap, uint64_t *received, uint64_t *dropped){
    if (cap == NULL || received == NULL || dropped == NULL) return -1;
    struct tpacket_stats st;
    socklen_t len = sizeof(st);
    if (getsockopt(cap -> fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) != 0) return -1;
    *received = st.tp_packets;                            // reçues par le socket (les jetées comprises)
    *dropped = st.tp_drops;
    return 0;
}

// -2 pour controle c
static int _cap_recv(
    Capture *cap, uint8_t *buf, size_t size, struct pollfd *p, 
    int timeout_ms, FrameFn on_frame, void *ctx
){
    int r = poll(p, 1, timeout_ms);                      // dort jusqu'à une trame, ou jusqu'au délai
    if (r == 0) return 0;                                 // délai écoulé : l'appelant en profite pour faire son ménage
    if (r < 0) return errno == EINTR ? -2 : -1;            // EINTR = un signal (Ctrl-C) : l'appelant regarde son drapeau d'arrêt
    ssize_t n = recv(cap -> fd, buf, size, MSG_DONTWAIT);
    if (n > 0){
        on_frame(buf, n, ctx);
    }
    return n;
}

long long int cap_recv(
    Capture *cap, uint8_t *buf, size_t size, int timeout_ms, 
    FrameFn on_frame, EmptyFn clear_fn, uint8_t call_clear_fn_each,
    void *ctx, _Atomic uint8_t *stop
){
    if (cap == NULL || buf == NULL || size == 0) return -1;
    struct pollfd p = { .fd = cap -> fd, .events = POLLIN };
    ssize_t n_pkt = 0;
    int turns = 0;
    while (atomic_load_explicit(stop, memory_order_acquire) != 1) {
        ssize_t n = _cap_recv(
            cap, buf, size, &p, timeout_ms, on_frame, ctx
        );
        if (n == -2) break;
        if (n > 0) n_pkt += n;
        if (turns >= call_clear_fn_each && clear_fn != NULL) {clear_fn(ctx); turns = 0;}
        else if (n == 0 && clear_fn != NULL) clear_fn(ctx);   // 1 s sans trame : ménage
        turns += 1;
    }
    return (long long int)n_pkt;
}

// -2 pour controle c
static int _cap_recv_mmsg(
    Capture *cap, uint8_t **bufs, struct mmsghdr *msgs, struct pollfd *p, 
    int timeout_ms, FrameFn on_frame, void *ctx, uint16_t max_turns,
    uint32_t batch_size
){
    int r = poll(p, 1, timeout_ms);                      // dort jusqu'à une trame, ou jusqu'au délai
    if (r == 0) return 0;                                 // délai écoulé : l'appelant en profite pour faire son ménage
    if (r < 0) return errno == EINTR ? -2 : -1;            // EINTR = un signal (Ctrl-C) : l'appelant regarde son drapeau d'arrêt
    int total = 0;
    for (int i = 0; i < max_turns; i++){   // max_turns tours maximum par appel pour eviter de bloquer
        int n = recvmmsg(cap -> fd, msgs, batch_size, MSG_DONTWAIT, NULL);
        if (n < 0){
            if (errno == EAGAIN ) break;   // plus rien à lire : fini
            if (errno == EINTR) return -2;
            return -1;
        }
        for (int j = 0; j < n; j++)
            on_frame(bufs[j], msgs[j].msg_len, ctx);
        total += n;
        if (n == 0) break;   // implicite au bas, mas explicite
        if (n < batch_size) break;                         // lot incomplet : la file est vide
    }
    return total;
}

long long int cap_recv_mmsg(
    Capture *cap, uint64_t pkt_size, int timeout_ms, 
    FrameFn on_frame, EmptyFn clear_fn, uint8_t call_clear_fn_each,
    void *ctx, _Atomic uint8_t *stop, uint32_t batch_size, uint16_t max_turns
){
    if (cap == NULL || pkt_size == 0 || batch_size == 0 || max_turns == 0) return -1;

    struct pollfd p = { .fd = cap -> fd, .events = POLLIN };
    long long int n_pkt = 0;

    struct mmsghdr *msgs = (struct mmsghdr *)calloc(batch_size, sizeof(struct mmsghdr));
    if (msgs == NULL) return -1;

    struct iovec *iovs = (struct iovec *)calloc(batch_size, sizeof(struct iovec));
    if (iovs == NULL){
        free(msgs);
        return -1;
    }

    uint8_t **bufs = calloc(batch_size, sizeof(uint8_t *));
    if (bufs == NULL){
        free(msgs);
        free(iovs);
        return -1;
    }

    for (int i = 0; i < batch_size; i++) {
        bufs[i] = malloc(pkt_size);
        if (bufs[i] == NULL) {
            /* libérer ce qui a déjà été alloué */
            for (int j = 0; j < i; j++) free(bufs[j]);
            free(bufs);
            free(msgs);
            free(iovs);
            return -1;
        }
    }

    memset(msgs, 0, sizeof(struct mmsghdr));

    for (int i = 0; i < batch_size; i++) {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_len  = pkt_size;
        msgs[i].msg_hdr.msg_iov    = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    int turns = 0;
    while (atomic_load_explicit(stop, memory_order_acquire) != 1) {
        int n = _cap_recv_mmsg(
            cap, bufs, msgs, &p, timeout_ms, on_frame, ctx, max_turns, batch_size
        );
        if (n == -2) break;
        if (n > 0) n_pkt += n;
        if (turns >= call_clear_fn_each && clear_fn != NULL) {clear_fn(ctx); turns = 0;}
        else if (n == 0 && clear_fn != NULL) clear_fn(ctx);   // 1 s sans trame : ménage
        turns += 1;
    }
    for (int i = 0; i < batch_size; i++) free(bufs[i]);
    free(bufs);
    free(msgs);
    free(iovs);
    return n_pkt;
}