/* test_parser.c : tests "utilisateur fou" pour parse()
 *
 * Compiler (depuis modules_c/parser/) :
 *   gcc -std=gnu11 -g -O1 -Wall -Wextra -fsanitize=address,undefined \
 *       test_parser.c parser.c -o test_parser && ./test_parser
 *
 * Principes :
 *  - chaque test tourne dans un process enfant : un plantage = un test rouge, pas la fin de tout ;
 *  - le paquet est copié dans un tampon de la TAILLE EXACTE (malloc) : une lecture 1 octet
 *    trop loin est attrapée par ASan ;
 *  - les paquets sont écrits en hexadécimal, comme dans le doc.
 */
#define _GNU_SOURCE
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "parser.h"

/* ───────────── outils ───────────── */
typedef struct { uint8_t b[4096]; int n; } Pkt;

static void put(Pkt *p, const char *hex) {            /* ajoute des octets écrits "00 1A ff" */
    int hi = -1;
    for (; hex && *hex; hex++) {
        int v, c = *hex;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else continue;
        if (hi < 0) hi = v; else { p->b[p->n++] = (uint8_t)(hi * 16 + v); hi = -1; }
    }
}
static Pkt mk(const char *a, const char *b, const char *c, int pad_to) {
    Pkt p; memset(&p, 0, sizeof p);
    put(&p, a); put(&p, b); put(&p, c);
    while (p.n < pad_to) p.b[p.n++] = 0;               /* bourrage Ethernet */
    return p;
}
static ParserResult run(const Pkt *p, int n) {          /* tampon de taille EXACTE */
    uint8_t *h = malloc(n > 0 ? (size_t)n : 1);
    if (n > 0) memcpy(h, p->b, (size_t)n);
    ParserResult r = parse(h, n);
    free(h);
    return r;
}
#define CHECK(cond, ...) do { if (!(cond)) { fprintf(stderr, "FAIL: " __VA_ARGS__); \
    fprintf(stderr, "\n"); exit(1); } } while (0)
#define IS(r, c) CHECK((r).code == (c), "code=%d, attendu %d", (r).code, (c))
#define NOT_OK(r) CHECK((r).code != SUCCES, "SUCCES alors que le paquet est invalide/incomplet")
#define PORTS(r, s, d) CHECK(!memcmp((r).data.tcp.src_port, s, 2) && !memcmp((r).data.tcp.dst_port, d, 2), \
    "ports lus : %02x%02x -> %02x%02x", (r).data.tcp.src_port[0], (r).data.tcp.src_port[1], \
    (r).data.tcp.dst_port[0], (r).data.tcp.dst_port[1])

/* ───────────── paquets de base ───────────── */
static const char *MACS   = "00 1A 2B 3C 4D 5E  00 11 22 33 44 55";
static const char *IP4TCP = "45 00 00 28 1C 46 40 00 40 06 00 00 C0 A8 01 0A 0A 00 00 09 "
                            "C7 38 01 BB 00 00 00 01 00 00 00 00 50 02 FF FF 00 00 00 00";
static const char *TCP20  = "C7 38 01 BB 00 00 00 01 00 00 00 00 50 02 FF FF 00 00 00 00";
static const char *SRC6   = "20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01";
static const char *DST6   = "20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02";

static Pkt syn4(void)  { return mk(MACS, "08 00", IP4TCP, 60); }
static Pkt udp4(void)  { return mk(MACS, "08 00 45 00 00 1C 1C 47 00 00 40 11 00 00 C0 A8 01 0A 08 08 08 08",
                                   "C7 38 00 35 00 08 00 00", 60); }
static Pkt icmp4(void) { return mk(MACS, "08 00 45 00 00 1C 1C 48 00 00 40 01 00 00 C0 A8 01 0A 08 08 08 08",
                                   "08 00 00 00 00 01 00 01", 60); }
static Pkt v6(int nh, const char *ext, const char *l4) {    /* Ethernet + IPv6 + [extensions] + couche 4 */
    Pkt p = mk(MACS, "86 DD 60 00 00 00 00 00", NULL, 0);
    char s[16]; snprintf(s, sizeof s, "%02X 40", nh);
    put(&p, s); put(&p, SRC6); put(&p, DST6); put(&p, ext); put(&p, l4);
    int pl = p.n - 54; p.b[18] = (uint8_t)(pl >> 8); p.b[19] = (uint8_t)pl;   /* longueur charge utile IPv6 */
    return p;
}
static Pkt syn6(void)  { return v6(6, "", TCP20); }
static Pkt vlan1(void) { return mk(MACS, "81 00 00 64 08 00", IP4TCP, 0); }

/* ───────────── 1) paquets VALIDES : la fiche est-elle bonne ? ───────────── */
static void t_syn4(void) {
    Pkt p = syn4(); ParserResult r = run(&p, 60);
    IS(r, SUCCES);
    CHECK(r.version == 4 && r.ihl == 5 && r.ip_start == 14 && r.n_vlan == 0 && r.type == 0x0800, "en-tête");
    CHECK(!memcmp(r.src_mac, "\x00\x11\x22\x33\x44\x55", 6) && !memcmp(r.dst_mac, "\x00\x1A\x2B\x3C\x4D\x5E", 6), "MAC");
    CHECK(!memcmp(r.ip_data.ipv4.src_ip, "\xC0\xA8\x01\x0A", 4) && !memcmp(r.ip_data.ipv4.dst_ip, "\x0A\x00\x00\x09", 4), "IP");
    CHECK(r.ip_data.ipv4.proto == 6, "proto");
    PORTS(r, "\xC7\x38", "\x01\xBB");
    CHECK(r.data.tcp.flags == SYN, "flags=%02x", r.data.tcp.flags);
}
static void t_udp4(void) { Pkt p = udp4(); ParserResult r = run(&p, 60); IS(r, SUCCES);
    CHECK(!memcmp(r.data.udp.dst_port, "\x00\x35", 2), "port 53"); }
static void t_icmp4(void) { Pkt p = icmp4(); ParserResult r = run(&p, 60); IS(r, SUCCES);
    CHECK(r.data.icmp.type == 8 && r.data.icmp.code == 0, "type ICMP=%d", r.data.icmp.type); }
static void t_syn6(void) {
    Pkt p = syn6(); ParserResult r = run(&p, p.n); IS(r, SUCCES);
    CHECK(r.version == 6 && r.ip_start == 14 && r.ip_data.ipv6.next_header == 6, "en-tête v6");
    CHECK(r.ip_data.ipv6.src_ip[15] == 1 && r.ip_data.ipv6.dst_ip[15] == 2, "IPv6 src/dst");
    PORTS(r, "\xC7\x38", "\x01\xBB");
}
static void t_udp6(void) { Pkt p = v6(17, "", "C7 38 00 35 00 08 00 00"); ParserResult r = run(&p, p.n); IS(r, SUCCES); }
static void t_icmpv6(void) {                      /* ping IPv6 : prochain en-tête = 58 */
    Pkt p = v6(58, "", "80 00 00 00 00 01 00 01"); ParserResult r = run(&p, p.n);
    IS(r, SUCCES); CHECK(r.data.icmp.type == 128, "type ICMPv6=%d", r.data.icmp.type);
}
static void t_ihl6(void) {                        /* options IP : le TCP est décalé de 4 octets */
    Pkt p = mk(MACS, "08 00 46 00 00 2C 1C 46 40 00 40 06 00 00 C0 A8 01 0A 0A 00 00 09 01 01 01 00", TCP20, 0);
    ParserResult r = run(&p, p.n); IS(r, SUCCES); PORTS(r, "\xC7\x38", "\x01\xBB");
}
static void t_vlan1(void) { Pkt p = vlan1(); ParserResult r = run(&p, p.n); IS(r, SUCCES);
    CHECK(r.n_vlan == 1 && r.ip_start == 18, "n_vlan=%d ip_start=%d", r.n_vlan, r.ip_start); PORTS(r, "\xC7\x38", "\x01\xBB"); }
static void t_qinq(void) { Pkt p = mk(MACS, "81 00 00 64 81 00 00 C8 08 00", IP4TCP, 0); ParserResult r = run(&p, p.n);
    IS(r, SUCCES); CHECK(r.n_vlan == 2 && r.ip_start == 22, "n_vlan=%d ip_start=%d", r.n_vlan, r.ip_start); }
static void t_88a8(void) { Pkt p = mk(MACS, "88 A8 00 64 81 00 00 C8 08 00", IP4TCP, 0); ParserResult r = run(&p, p.n); IS(r, SUCCES); }
static void t_ext_hbh8(void) { Pkt p = v6(0, "06 00 00 00 00 00 00 00", TCP20); ParserResult r = run(&p, p.n);
    IS(r, SUCCES); PORTS(r, "\xC7\x38", "\x01\xBB"); }
static void t_ext_hbh16_frag(void) {              /* hop-by-hop de 16 octets, puis fragment (offset 0), puis TCP */
    Pkt p = v6(0, "2C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  06 00 00 00 00 00 00 01", TCP20);
    ParserResult r = run(&p, p.n); IS(r, SUCCES); PORTS(r, "\xC7\x38", "\x01\xBB");
}
static void t_ext_frag_reserve(void) {            /* l'octet "réservé" du fragment est libre : un menteur y met 3 */
    Pkt p = v6(44, "06 03 00 00 00 00 00 01", TCP20); ParserResult r = run(&p, p.n);
    IS(r, SUCCES); PORTS(r, "\xC7\x38", "\x01\xBB");
}
static void t_proto_inconnu(void) { Pkt p = syn4(); p.b[23] = 50; ParserResult r = run(&p, 60); IS(r, NOT_HANDLE); }
static void sweep(Pkt p, int full);
static Pkt arpreq(void) { return mk("FF FF FF FF FF FF 00 11 22 33 44 55", "08 06",
    "00 01 08 00 06 04 00 01 00 11 22 33 44 55 C0 A8 01 0A 00 00 00 00 00 00 C0 A8 01 01", 60); }
static void t_arp(void) {
    Pkt p = arpreq(); ParserResult r = run(&p, 60); IS(r, SUCCES);
    CHECK(r.type == ARP && r.data.arp.op == 1 && r.version == 0 && r.ihl == 0, "en-tête ARP");
    CHECK(!memcmp(r.data.arp.sender_ip, "\xC0\xA8\x01\x0A", 4) && !memcmp(r.data.arp.target_ip, "\xC0\xA8\x01\x01", 4), "IP ARP");
    CHECK(!memcmp(r.data.arp.sender_mac, "\x00\x11\x22\x33\x44\x55", 6), "MAC ARP");
}
static void t_arp_reply(void) { Pkt p = arpreq(); p.b[21] = 2; ParserResult r = run(&p, 60); IS(r, SUCCES); CHECK(r.data.arp.op == 2, "op"); }
static void t_arp_op_inconnue(void) { Pkt p = arpreq(); p.b[21] = 3; ParserResult r = run(&p, 60); IS(r, NOT_HANDLE); }
static void t_arp_taille_menteuse(void) { Pkt p = arpreq(); p.b[18] = 8; ParserResult r = run(&p, 60); IS(r, INCOHERENCE); }
static void t_arp_materiel(void) { Pkt p = arpreq(); p.b[15] = 6; ParserResult r = run(&p, 60); IS(r, NOT_HANDLE); }
static void t_arp_vlan(void) { Pkt p = mk("FF FF FF FF FF FF 00 11 22 33 44 55", "81 00 00 64 08 06",
    "00 01 08 00 06 04 00 01 00 11 22 33 44 55 C0 A8 01 0A 00 00 00 00 00 00 C0 A8 01 01", 60);
    ParserResult r = run(&p, 60); IS(r, SUCCES); CHECK(r.n_vlan == 1 && r.ip_start == 18, "vlan+arp"); }
static void t_sweep_arp(void) { sweep(arpreq(), 42); }
static void t_type_inconnu_45(void) { Pkt p = mk(MACS, "88 CC 45 00 00 00", NULL, 60); ParserResult r = run(&p, 60); IS(r, NOT_HANDLE); }
static void t_court_non_ip(void) { Pkt p = mk(MACS, "88 CC", NULL, 30); ParserResult r = run(&p, 30); IS(r, NOT_HANDLE); }
static void t_code_trop_court(void) {             /* trop court = TOO_LITTLE, quelle que soit la couche */
    Pkt p = syn4();
    for (int n = 14; n < 34; n++) { ParserResult r = run(&p, n); CHECK(r.code == TOO_LITTLE, "n=%d code=%d", n, r.code); }
}

/* ───────────── 2) MENTEURS et incohérences ───────────── */
static void t_ihl4(void)  { Pkt p = syn4(); p.b[14] = 0x44; ParserResult r = run(&p, 60); NOT_OK(r); }
static void t_ihl15_court(void) { Pkt p = syn4(); p.b[14] = 0x4F; ParserResult r = run(&p, 40); NOT_OK(r); }
static void t_version_type(void) {
    Pkt p = syn4(); p.b[14] = 0x65; ParserResult r = run(&p, 60); IS(r, INCOHERENCE);
    p = syn4(); p.b[12] = 0x86; p.b[13] = 0xDD; r = run(&p, 60); IS(r, INCOHERENCE);
}
static void t_version_5_et_0(void) {
    Pkt p = syn4(); p.b[14] = 0x55; ParserResult r = run(&p, 60); IS(r, NOT_HANDLE);
    p = syn4(); p.b[14] = 0x05; r = run(&p, 60); IS(r, NOT_HANDLE);
}
static void t_longueur_ip_vs_bourrage(void) {     /* l'IP dit "20 octets au total" : il n'y a PAS de TCP, juste du bourrage */
    Pkt p = syn4(); p.b[16] = 0; p.b[17] = 20; ParserResult r = run(&p, 60); NOT_OK(r);
}
static void t_longueur_ip_trop_petite(void) { Pkt p = syn4(); p.b[17] = 10; ParserResult r = run(&p, 60); NOT_OK(r); }
static void t_fragment_suivant(void) {            /* décalage de fragment = 8 : pas d'en-tête TCP dans ce paquet */
    Pkt p = syn4(); p.b[20] = 0x00; p.b[21] = 0x08; ParserResult r = run(&p, 60); IS(r, FRAGMENT);
}
static void t_fragment_premier(void) { Pkt p = syn4(); p.b[20] = 0x20; p.b[21] = 0x00; ParserResult r = run(&p, 60); IS(r, SUCCES); }
static void t_tcp_offset_petit(void) { Pkt p = syn4(); p.b[46] = 0x10; ParserResult r = run(&p, 60); NOT_OK(r); }
static void t_tcp_offset_grand(void) { Pkt p = syn4(); p.b[46] = 0xF0; ParserResult r = run(&p, 60); NOT_OK(r); }
static void t_flags_fous(void) { Pkt p = syn4(); p.b[47] = 0x07; ParserResult r = run(&p, 60);
    IS(r, SUCCES); CHECK(r.data.tcp.flags == 0x07, "flags"); }
static void t_frag_ipv6_suivant(void) {          /* fragment IPv6 dont le décalage vaut 8 : pas de TCP dedans */
    Pkt p = v6(44, "06 00 00 08 00 00 00 01", TCP20); ParserResult r = run(&p, p.n); IS(r, FRAGMENT); }
static void t_longueur_ipv6_vs_bourrage(void) {  /* la charge utile annonce 5 octets, mais 20 octets de "TCP" traînent derrière */
    Pkt p = syn6(); p.b[18] = 0; p.b[19] = 5; ParserResult r = run(&p, p.n); NOT_OK(r); }
static void t_ihl_ipv6_zero(void) { Pkt p = v6(59, "", TCP20); p.b[14] = 0x6F; ParserResult r = run(&p, p.n);
    IS(r, NOT_HANDLE); CHECK(r.ihl == 0, "ihl=%d : l'IHL n'existe pas en IPv6", r.ihl); }

/* ───────────── 3) ROBUSTESSE : aucun crash, aucune lecture hors paquet ───────────── */
static void sweep(Pkt p, int full) {                 /* coupe le paquet à TOUTES les longueurs plus courtes */
    for (int n = 0; n < full; n++) {
        fprintf(stderr, "CTX: len=%d\n", n);
        ParserResult r = run(&p, n);
        CHECK(r.code != SUCCES, "len=%d : SUCCES sur un paquet tronqué", n);
    }
}
static void t_sweep_syn4(void)  { sweep(syn4(), 54); }
static void t_sweep_udp4(void)  { sweep(udp4(), 42); }
static void t_sweep_icmp4(void) { sweep(icmp4(), 42); }
static void t_sweep_syn6(void)  { Pkt p = syn6(); sweep(p, p.n); }
static void t_sweep_vlan(void)  { Pkt p = vlan1(); sweep(p, p.n); }
static void t_sweep_ext(void)   { Pkt p = v6(0, "2C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  06 00 00 00 00 00 00 01", TCP20); sweep(p, p.n); }
static void t_null(void)  { ParserResult r = parse(NULL, 100); NOT_OK(r); }
static void t_len_negatif(void) { uint8_t b[64] = {0}; ParserResult r = parse(b, -1); IS(r, TOO_LITTLE);
    r = parse(b, INT_MIN); IS(r, TOO_LITTLE); }
static void t_pile_de_vlan(void) {                /* 1000 tags VLAN empilés, sans fin */
    Pkt p = mk(MACS, "81 00", NULL, 0);
    for (int i = 0; i < 1000; i++) put(&p, "00 64 81 00");
    ParserResult r = run(&p, p.n); NOT_OK(r);
}
static void t_chaine_ext_sans_fin(void) {         /* 100 en-têtes d'extension qui s'enchaînent, aucun TCP à la fin */
    Pkt p = v6(0, "", NULL);
    for (int i = 0; i < 100; i++) put(&p, "00 00 00 00 00 00 00 00");
    ParserResult r = run(&p, p.n); NOT_OK(r);
}
static void t_ext_tronquee(void) { Pkt p = v6(0, "06", NULL); ParserResult r = run(&p, p.n); NOT_OK(r); }
static void t_ext_longueur_255(void) { Pkt p = v6(0, "06 FF 00 00 00 00 00 00", TCP20); ParserResult r = run(&p, p.n); NOT_OK(r); }
static void poison(void) __attribute__((noinline));
static void poison(void) { volatile uint8_t junk[16384]; for (size_t i = 0; i < sizeof junk; i++) junk[i] = 0xAA; }
static void t_determinisme(void) {                /* même paquet, pile "sale" entre les deux : mêmes octets en sortie ? */
    Pkt p = syn4(); ParserResult a = run(&p, 60); poison(); ParserResult b = run(&p, 60);
    CHECK(!memcmp(&a, &b, sizeof a), "deux résultats différents (octets de remplissage non initialisés)");
}

/* ───────────── 4) FUZZING : mutations aléatoires + coupures ───────────── */
static struct { volatile long it; volatile int n; uint8_t b[512]; } *g_sh;   /* mémoire partagée : dernier paquet testé */
static uint32_t rs = 2463534242u;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }
static void t_fuzz(void) {
    Pkt base[9] = { arpreq(), syn4(), udp4(), icmp4(), syn6(), vlan1(),
        v6(0, "2C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  06 00 00 00 00 00 00 01", TCP20),
        v6(58, "", "80 00 00 00 00 01 00 01"), mk(MACS, "81 00 00 64 81 00 00 C8 08 00", IP4TCP, 0) };
    static const uint8_t spicy[] = {0x00, 0x01, 0xFF, 0x45, 0x46, 0x4F, 0x60, 0x0F, 0xF0, 0x81, 0x2C, 0x3A};
    for (long it = 0; it < 300000; it++) {
        Pkt p = base[rnd() % 9];
        int k = 1 + (int)(rnd() % 4);
        for (int j = 0; j < k; j++) p.b[rnd() % (uint32_t)p.n] = (rnd() & 1) ? spicy[rnd() % sizeof spicy] : (uint8_t)rnd();
        int n = (rnd() % 3 == 0) ? (int)(rnd() % (uint32_t)(p.n + 1)) : p.n;
        g_sh->it = it; g_sh->n = n; memcpy((void *)g_sh->b, p.b, (size_t)n);
        ParserResult r = run(&p, n);
        CHECK(r.code <= FRAGMENT, "code hors enum : %d", r.code);
    }
}

/* ───────────── lanceur ───────────── */
typedef struct { const char *grp, *name; void (*fn)(void); } Test;
#define T(g, f) { g, #f + 2, f }
static const Test tests[] = {
 T("VALIDES", t_syn4), T("VALIDES", t_udp4), T("VALIDES", t_icmp4), T("VALIDES", t_syn6), T("VALIDES", t_udp6),
 T("VALIDES", t_icmpv6), T("VALIDES", t_ihl6), T("VALIDES", t_vlan1), T("VALIDES", t_qinq), T("VALIDES", t_88a8),
 T("VALIDES", t_ext_hbh8), T("VALIDES", t_ext_hbh16_frag), T("VALIDES", t_ext_frag_reserve), T("VALIDES", t_proto_inconnu),
 T("VALIDES", t_arp), T("VALIDES", t_arp_reply), T("VALIDES", t_arp_op_inconnue), T("VALIDES", t_arp_taille_menteuse), T("VALIDES", t_arp_materiel), T("VALIDES", t_arp_vlan), T("VALIDES", t_type_inconnu_45), T("VALIDES", t_court_non_ip), T("VALIDES", t_code_trop_court),
 T("MENTEURS", t_ihl4), T("MENTEURS", t_ihl15_court), T("MENTEURS", t_version_type), T("MENTEURS", t_version_5_et_0),
 T("MENTEURS", t_longueur_ip_vs_bourrage), T("MENTEURS", t_longueur_ip_trop_petite), T("MENTEURS", t_fragment_suivant),
 T("MENTEURS", t_fragment_premier), T("MENTEURS", t_tcp_offset_petit), T("MENTEURS", t_tcp_offset_grand),
 T("MENTEURS", t_flags_fous), T("MENTEURS", t_ihl_ipv6_zero), T("MENTEURS", t_frag_ipv6_suivant), T("MENTEURS", t_longueur_ipv6_vs_bourrage),
 T("ROBUSTESSE", t_sweep_syn4), T("ROBUSTESSE", t_sweep_udp4), T("ROBUSTESSE", t_sweep_icmp4), T("ROBUSTESSE", t_sweep_syn6),
 T("ROBUSTESSE", t_sweep_vlan), T("ROBUSTESSE", t_sweep_ext), T("ROBUSTESSE", t_sweep_arp), T("ROBUSTESSE", t_null), T("ROBUSTESSE", t_len_negatif),
 T("ROBUSTESSE", t_pile_de_vlan), T("ROBUSTESSE", t_chaine_ext_sans_fin), T("ROBUSTESSE", t_ext_tronquee),
 T("ROBUSTESSE", t_ext_longueur_255), T("ROBUSTESSE", t_determinisme), T("FUZZ", t_fuzz),
};

static void report(FILE *f, int sig, int code) {
    char line[512], first[512] = "", ctx[128] = "", sum[512] = "";
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "FAIL:", 5) && !*first) strcpy(first, line + 6);
        if (!strncmp(line, "SUMMARY:", 8) && !*sum) strcpy(sum, line + 9);
        if (!strncmp(line, "CTX:", 4)) strcpy(ctx, line + 5);
    }
    if (*sum)        printf("   💥 PLANTAGE : %.110s %s\n", sum, ctx);
    else if (*first) printf("   ↳ %.120s\n", first);
    else             printf("   💥 fin anormale (signal %d, code %d) %s\n", sig, code, ctx);
}

int main(void) {
    g_sh = mmap(NULL, sizeof *g_sh, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    setenv("ASAN_OPTIONS", "detect_leaks=0", 1);
    int ok = 0, total = (int)(sizeof tests / sizeof tests[0]);
    const char *grp = "";
    for (int i = 0; i < total; i++) {
        if (strcmp(grp, tests[i].grp)) { grp = tests[i].grp; printf("\n── %s ──\n", grp); }
        char path[] = "/tmp/tpXXXXXX"; int fd = mkstemp(path);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) { dup2(fd, 2); tests[i].fn(); _exit(0); }
        int st; waitpid(pid, &st, 0);
        int good = WIFEXITED(st) && WEXITSTATUS(st) == 0;
        printf("%s %s\n", good ? "✅" : "❌", tests[i].name);
        if (good) ok++;
        else {
            FILE *f = fdopen(fd, "r"); rewind(f);
            report(f, WIFSIGNALED(st) ? WTERMSIG(st) : 0, WIFEXITED(st) ? WEXITSTATUS(st) : 0);
            if (!strcmp(tests[i].grp, "FUZZ") && g_sh->n > 0) {
                printf("   paquet fautif (itération %ld, %d octets) :", g_sh->it, g_sh->n);
                for (int j = 0; j < g_sh->n && j < 80; j++) printf(" %02X", g_sh->b[j]);
                printf("\n");
            }
            fclose(f);
        }
        close(fd); unlink(path);
    }
    printf("\n%d/%d tests OK\n", ok, total);
    return ok == total ? 0 : 1;
}