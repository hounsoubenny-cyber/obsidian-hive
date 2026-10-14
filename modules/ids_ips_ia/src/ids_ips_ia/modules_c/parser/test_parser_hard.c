#include <stdio.h>
#include <string.h>
#include "parser.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(int cond, const char *msg) {
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; }
    else      { printf("  [FAIL] %s\n", msg); g_fail++; }
}

static uint16_t be16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }

static const char *code_str(uint8_t c) {
    switch (c) {
        case SUCCES:      return "SUCCES";
        case ERROR:       return "ERROR";
        case TOO_LITTLE:  return "TOO_LITTLE";
        case INCOHERENCE: return "INCOHERENCE";
        case NOT_HANDLE:  return "NOT_HANDLE";
        default:          return "???";
    }
}

static void print_hex(const char *label, const uint8_t *data, int len) {
    printf("  %-18s (%2d) : ", label, len);
    for (int i = 0; i < len; i++) printf("%02X ", data[i]);
    printf("\n");
}

static void print_result(const ParserResult *r) {
    printf("  code        = %u (%s)\n", r->code, code_str(r->code));
    printf("  n_vlan      = %d\n", r->n_vlan);
    printf("  ip_start    = %d\n", r->ip_start);
    printf("  type        = 0x%04X\n", r->type);
    printf("  version     = %u\n", r->version);
    printf("  ihl         = %u\n", r->ihl);
    print_hex("src_mac", r->src_mac, 6);
    print_hex("dst_mac", r->dst_mac, 6);

    if (r->version == 4) {
        print_hex("ipv4.src_ip", r->ip_data.ipv4.src_ip, 4);
        print_hex("ipv4.dst_ip", r->ip_data.ipv4.dst_ip, 4);
        printf("  ipv4.proto  = %u\n", r->ip_data.ipv4.proto);
        uint8_t p = r->ip_data.ipv4.proto;
        if (p == TCP) {
            print_hex("tcp.src_port", r->data.tcp.src_port, 2);
            print_hex("tcp.dst_port", r->data.tcp.dst_port, 2);
            printf("  tcp.flags   = 0x%02X\n", r->data.tcp.flags);
        } else if (p == UDP) {
            print_hex("udp.src_port", r->data.udp.src_port, 2);
            print_hex("udp.dst_port", r->data.udp.dst_port, 2);
        } else if (p == ICMP) {
            printf("  icmp.type   = %d\n", r->data.icmp.type);
            printf("  icmp.code   = %d\n", r->data.icmp.code);
        }
    } else if (r->version == 6) {
        print_hex("ipv6.src_ip", r->ip_data.ipv6.src_ip, 16);
        print_hex("ipv6.dst_ip", r->ip_data.ipv6.dst_ip, 16);
        printf("  ipv6.nh     = %u\n", r->ip_data.ipv6.next_header);
        uint8_t nh = r->ip_data.ipv6.next_header;
        if (nh == TCP) {
            print_hex("tcp.src_port", r->data.tcp.src_port, 2);
            print_hex("tcp.dst_port", r->data.tcp.dst_port, 2);
            printf("  tcp.flags   = 0x%02X\n", r->data.tcp.flags);
        } else if (nh == UDP) {
            print_hex("udp.src_port", r->data.udp.src_port, 2);
            print_hex("udp.dst_port", r->data.udp.dst_port, 2);
        } else if (nh == ICMP) {
            printf("  icmp.type   = %d\n", r->data.icmp.type);
            printf("  icmp.code   = %d\n", r->data.icmp.code);
        }
    }
}

static ParserResult mk_expected(void) {
    ParserResult r;
    memset(&r, 0, sizeof(r));
    /* MAC par défaut : celles du paquet Ethernet standard (dst = 1ers octets, src = suivants) */
    uint8_t sm[] = {0x66,0x77,0x88,0x99,0xAA,0xBB};
    uint8_t dm[] = {0x00,0x11,0x22,0x33,0x44,0x55};
    memcpy(r.src_mac, sm, 6);
    memcpy(r.dst_mac, dm, 6);
    return r;
}

static ParserResult run_test(const char *name,
                             const uint8_t *pkt, int len,
                             const ParserResult *expected) {
    printf("\n=====================================================\n");
    printf("TEST : %s\n", name);
    printf("=====================================================\n");
    printf("  --- INPUT ---\n");
    printf("  Packet (%d octets) :\n", len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("    %04X : ", i);
        printf("%02X ", pkt[i]);
        if (i % 16 == 15 || i == len - 1) printf("\n");
    }

    ParserResult actual = parse(pkt, len);

    printf("  --- EXPECTED (ce que la fonction DOIT produire) ---\n");
    print_result(expected);
    printf("  --- ACTUAL (ce que la fonction produit) ---\n");
    print_result(&actual);

    printf("  --- CHECKS ---\n");
    return actual;
}

int main(void) {

    /* ================================================================
     * TEST A : IPv4 avec options (IHL=6)
     * ----------------------------------------------------------------
     * But : vérifier que start = ip_start + ihl*4 fonctionne quand IHL > 5.
     * IHL = 6 → en-tête IP = 24 octets. TCP commence à 14+24 = 38.
     * ================================================================ */
    const uint8_t pktA[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x46,0x00,0x00,0x2C, 0x00,0x00,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x01,0x01,0x00,0x00,             /* 4 octets d'options */
        0x1F,0x90,0x00,0x50,
        0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x02,
        0x50,0x02,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV4; exp.version = 4; exp.ihl = 6;
        exp.ip_start = 14; exp.n_vlan = 0;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);
        exp.ip_data.ipv4.proto = TCP;
        exp.data.tcp.src_port[0] = 0x1F; exp.data.tcp.src_port[1] = 0x90;
        exp.data.tcp.dst_port[0] = 0x00; exp.data.tcp.dst_port[1] = 0x50;
        exp.data.tcp.flags = 0x02;

        ParserResult r = run_test("A. IPv4 + options (IHL=6) + TCP", pktA, sizeof(pktA), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.ihl == 6,                          "ihl == 6");
        check(r.version == 4,                      "version == 4");
        check(r.type == IPV4,                      "type == IPV4");
        check(be16(r.data.tcp.src_port) == 8080,   "src_port == 8080");
        check(be16(r.data.tcp.dst_port) == 80,     "dst_port == 80");
        check(r.data.tcp.flags == 0x02,            "tcp.flags == SYN");
    }

    /* ================================================================
     * TEST B : Double VLAN (QinQ)
     * ----------------------------------------------------------------
     * But : la boucle VLAN doit tourner 2 fois.
     * Layout : 81 00 | TCI | 81 00 | TCI | 08 00 | IPv4
     * n_vlan = 2, ip_start = 22
     * ================================================================ */
    const uint8_t pktB[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x81,0x00, 0x00,0x64,
        0x81,0x00, 0x00,0x65,
        0x08,0x00,
        0x45,0x00,0x00,0x28, 0x00,0x00,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x1F,0x90,0x00,0x50,
        0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x02,
        0x50,0x02,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.n_vlan = 2; exp.ip_start = 22;
        exp.type = IPV4; exp.version = 4; exp.ihl = 5;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);
        exp.ip_data.ipv4.proto = TCP;
        exp.data.tcp.src_port[0] = 0x1F; exp.data.tcp.src_port[1] = 0x90;
        exp.data.tcp.dst_port[0] = 0x00; exp.data.tcp.dst_port[1] = 0x50;
        exp.data.tcp.flags = 0x02;

        ParserResult r = run_test("B. Double VLAN (QinQ) + IPv4 + TCP", pktB, sizeof(pktB), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.n_vlan == 2,                       "n_vlan == 2");
        check(r.ip_start == 22,                    "ip_start == 22");
        check(r.type == IPV4,                      "type == IPV4");
        check(be16(r.data.tcp.src_port) == 8080,   "src_port == 8080");
        check(r.data.tcp.flags == 0x02,            "tcp.flags == SYN");
    }

    /* ================================================================
     * TEST C : IPv6 + Fragment + TCP
     * ----------------------------------------------------------------
     * But : sauter un Fragment Header (8 octets fixes) avant TCP.
     * Layout : IPv6 (NH=44) | Fragment (8 o, NH=6) | TCP
     * next_header final = 6 (TCP), ports 8080 -> 80.
     * ================================================================ */
    const uint8_t pktC[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x1C,                       /* payload = 28 = 8 frag + 20 tcp */
        0x2C,                            /* NH = 44 (Fragment) */
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x06,0x00,0x00,0x01, 0xDE,0xAD,0xBE,0xEF,  /* Fragment */
        0x1F,0x90,0x00,0x50,                          /* TCP */
        0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x02,
        0x50,0x12,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV6; exp.version = 6; exp.ip_start = 14;
        exp.ip_data.ipv6.src_ip[0]=0x20; exp.ip_data.ipv6.src_ip[1]=0x01;
        exp.ip_data.ipv6.src_ip[2]=0x0D; exp.ip_data.ipv6.src_ip[3]=0xB8;
        exp.ip_data.ipv6.src_ip[15]=0x01;
        exp.ip_data.ipv6.dst_ip[0]=0x20; exp.ip_data.ipv6.dst_ip[1]=0x01;
        exp.ip_data.ipv6.dst_ip[2]=0x0D; exp.ip_data.ipv6.dst_ip[3]=0xB8;
        exp.ip_data.ipv6.dst_ip[15]=0x02;
        exp.ip_data.ipv6.next_header = TCP;
        exp.data.tcp.src_port[0]=0x1F; exp.data.tcp.src_port[1]=0x90;
        exp.data.tcp.dst_port[0]=0x00; exp.data.tcp.dst_port[1]=0x50;
        exp.data.tcp.flags = 0x12;

        ParserResult r = run_test("C. IPv6 + Fragment + TCP", pktC, sizeof(pktC), &exp);
        check(r.code == SUCCES,                       "code == SUCCES");
        check(r.type == IPV6,                         "type == IPV6");
        check(r.ip_data.ipv6.next_header == TCP,      "next_header == TCP");
        check(be16(r.data.tcp.src_port) == 8080,      "src_port == 8080");
        check(be16(r.data.tcp.dst_port) == 80,        "dst_port == 80");
        check(r.data.tcp.flags == 0x12,               "tcp.flags == SYN+ACK");
    }

    /* ================================================================
     * TEST D : IPv6 + Hop-by-Hop + Dest Opts + UDP
     * ----------------------------------------------------------------
     * But : chaîner 2 extensions de taille variable.
     * Layout : IPv6 (NH=0) | HBH (8o, NH=60) | DstOpts (16o, NH=17) | UDP
     * ================================================================ */
    const uint8_t pktD[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x20,                       /* payload = 32 = 8 + 16 + 8 */
        0x00,                            /* NH = 0 (Hop-by-Hop) */
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x3C,0x00, 0x01,0x04,0x00,0x00,0x00,0x00,   /* HBH (8 o) */
        0x11,0x01, 0x01,0x0A,                          /* DestOpts (16 o) */
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x35,0x30,0x39,0x00,0x08,0x00,0x00,     /* UDP */
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV6; exp.version = 6; exp.ip_start = 14;
        exp.ip_data.ipv6.src_ip[0]=0x20; exp.ip_data.ipv6.src_ip[1]=0x01;
        exp.ip_data.ipv6.src_ip[2]=0x0D; exp.ip_data.ipv6.src_ip[3]=0xB8;
        exp.ip_data.ipv6.src_ip[15]=0x01;
        exp.ip_data.ipv6.dst_ip[0]=0x20; exp.ip_data.ipv6.dst_ip[1]=0x01;
        exp.ip_data.ipv6.dst_ip[2]=0x0D; exp.ip_data.ipv6.dst_ip[3]=0xB8;
        exp.ip_data.ipv6.dst_ip[15]=0x02;
        exp.ip_data.ipv6.next_header = UDP;
        exp.data.udp.src_port[0]=0x00; exp.data.udp.src_port[1]=0x35;
        exp.data.udp.dst_port[0]=0x30; exp.data.udp.dst_port[1]=0x39;

        ParserResult r = run_test("D. IPv6 + Hop-by-Hop + Dest Opts + UDP", pktD, sizeof(pktD), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.ip_data.ipv6.next_header == UDP,   "next_header == UDP");
        check(be16(r.data.udp.src_port) == 53,     "src_port == 53");
        check(be16(r.data.udp.dst_port) == 12345,  "dst_port == 12345");
    }

    /* ================================================================
     * TEST E : IPv4 fragmenté (frag offset != 0)
     * ----------------------------------------------------------------
     * But : un fragment IPv4 qui n'est pas le premier (offset != 0) n'a PAS d'en-tête TCP.
     * Le parser doit répondre FRAGMENT et ne lire aucun port (sinon il inventerait 0xAABB...).
     * ================================================================ */
    const uint8_t pktE[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x45,0x00,0x00,0x1C, 0x12,0x34,0x20,0xB9,   /* MF=1, frag offset=185 */
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,    /* 8 octets (pas un vrai TCP) */
    };
    {
        ParserResult exp = mk_expected();
        exp.code = FRAGMENT;   /* fragment (offset != 0) : pas d'en-tête TCP, donc pas de ports */
        exp.type = IPV4; exp.version = 4; exp.ihl = 5; exp.ip_start = 14;
        exp.ip_data.ipv4.proto = TCP;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);

        ParserResult r = run_test("E. IPv4 fragmenté (frag offset != 0)", pktE, sizeof(pktE), &exp);
        check(r.code == FRAGMENT,                  "code == FRAGMENT");
        check(be16(r.data.tcp.src_port) == 0,      "src_port == 0 (rien n'a été lu dans le fragment)");
        check(be16(r.data.tcp.dst_port) == 0,      "dst_port == 0 (rien n'a été lu dans le fragment)");
    }

    /* ================================================================
     * TEST F : IHL = 4 (invalide, doit être rejeté)
     * ----------------------------------------------------------------
     * But : la RFC 791 impose IHL >= 5 (20 octets min).
     * Un IHL < 5 doit être rejeté.
     * ================================================================ */
    const uint8_t pktF[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x44,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00,   /* IHL = 4 → invalide */
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = ERROR;
        exp.type = IPV4; exp.version = 4; exp.ihl = 4; exp.ip_start = 14;

        ParserResult r = run_test("F. IPv4 avec IHL=4 (invalide)", pktF, sizeof(pktF), &exp);
        check(r.code == ERROR || r.code == INCOHERENCE,
              "code == ERROR ou INCOHERENCE (IHL < 5 rejeté)");
    }

    /* ================================================================
     * TEST G : IPv6 next_header = 255 (inconnu)
     * ----------------------------------------------------------------
     * But : un next_header non géré doit produire une erreur propre.
     * Ton parser retourne ERROR (il ne connaît ni TCP/UDP/ICMP).
     * ================================================================ */
    const uint8_t pktG[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x08,
        0xFF,                            /* NH = 255 (réservé) */
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = ERROR;
        exp.type = IPV6; exp.version = 6; exp.ip_start = 14;
        exp.ip_data.ipv6.src_ip[0]=0x20; exp.ip_data.ipv6.src_ip[1]=0x01;
        exp.ip_data.ipv6.src_ip[2]=0x0D; exp.ip_data.ipv6.src_ip[3]=0xB8;
        exp.ip_data.ipv6.src_ip[15]=0x01;
        exp.ip_data.ipv6.dst_ip[0]=0x20; exp.ip_data.ipv6.dst_ip[1]=0x01;
        exp.ip_data.ipv6.dst_ip[2]=0x0D; exp.ip_data.ipv6.dst_ip[3]=0xB8;
        exp.ip_data.ipv6.dst_ip[15]=0x02;
        exp.ip_data.ipv6.next_header = 255;

        ParserResult r = run_test("G. IPv6 next_header=255 (inconnu)", pktG, sizeof(pktG), &exp);
        check(r.code == ERROR || r.code == NOT_HANDLE,
              "code == ERROR ou NOT_HANDLE");
    }

    /* ================================================================
     * TEST H : TCP tronqué (3 octets sur 20)
     * ----------------------------------------------------------------
     * But : le parser doit vérifier que l'en-tête TCP COMPLET (20 octets min)
     * tient dans le paquet avant de le lire.
     * ================================================================ */
    const uint8_t pktH[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x45,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x1F,0x90,0x00,                    /* TCP : 3 octets sur 20 */
    };
    {
        ParserResult exp = mk_expected();
        exp.code = TOO_LITTLE;
        exp.type = IPV4; exp.version = 4; exp.ihl = 5; exp.ip_start = 14;
        exp.ip_data.ipv4.proto = TCP;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);

        ParserResult r = run_test("H. TCP tronqué en plein milieu", pktH, sizeof(pktH), &exp);
        check(r.code == TOO_LITTLE,
              "code == TOO_LITTLE (TCP < 20 octets)");
    }

    /* ================================================================
     * TEST I : VLAN + IPv4 tronqué
     * ----------------------------------------------------------------
     * But : la vérification de taille doit se faire APRÈS avoir sauté le VLAN.
     * Le paquet fait 20 octets, IPv4 tronqué à 2 octets.
     * ================================================================ */
    const uint8_t pktI[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x81,0x00, 0x00,0x64,
        0x08,0x00,
        0x45,0x00,                        /* IPv4 tronqué : 2 octets */
    };
    {
        ParserResult exp = mk_expected();
        exp.code = TOO_LITTLE;
        exp.n_vlan = 1; exp.ip_start = 18; exp.type = IPV4;

        ParserResult r = run_test("I. VLAN + IPv4 tronqué", pktI, sizeof(pktI), &exp);
        check(r.code == TOO_LITTLE, "code == TOO_LITTLE");
        check(r.n_vlan == 1,        "n_vlan == 1");
    }

    /* ================================================================
     * TEST J : Ethernet seul (14 octets)
     * ----------------------------------------------------------------
     * But : le paquet s'arrête juste après l'EtherType.
     * Il n'y a aucune IP derrière → TOO_LITTLE.
     * ================================================================ */
    const uint8_t pktJ[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = TOO_LITTLE;
        exp.type = IPV4;
        exp.ip_start = 14;

        ParserResult r = run_test("J. Ethernet seul (14 octets)", pktJ, sizeof(pktJ), &exp);
        check(r.code == TOO_LITTLE, "code == TOO_LITTLE");
    }

    /* ================================================================
     * TEST K : IPv4 complet, TCP absent
     * ----------------------------------------------------------------
     * But : l'IP est complète (20 octets), mais il n'y a rien après.
     * Le parser ne doit PAS dire SUCCES.
     * ================================================================ */
    const uint8_t pktK[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x45,0x00,0x00,0x14, 0x00,0x00,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = TOO_LITTLE;
        exp.type = IPV4; exp.version = 4; exp.ihl = 5; exp.ip_start = 14;
        exp.ip_data.ipv4.proto = TCP;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);

        ParserResult r = run_test("K. IPv4 complet, TCP absent", pktK, sizeof(pktK), &exp);
        check(r.code == TOO_LITTLE,
              "code == TOO_LITTLE (pas de TCP après l'IP)");
    }

    /* ================================================================
     * TEST L : IPv6 + double Fragment + TCP
     * ----------------------------------------------------------------
     * But : la boucle d'extensions doit gérer PLUSIEURS Fragment Headers.
     * Layout : IPv6 (NH=44) | Frag1 (NH=44) | Frag2 (NH=6) | TCP
     * ================================================================ */
    const uint8_t pktL[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x24,                       /* payload = 36 = 8 + 8 + 20 */
        0x2C,                            /* NH = 44 (Fragment) */
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x2C,0x00,0x00,0x00, 0xDE,0xAD,0xBE,0xEF,  /* Frag1 (NH=44) */
        0x06,0x00,0x00,0x00, 0xCA,0xFE,0xBA,0xBE,  /* Frag2 (NH=6)  */
        0x1F,0x90,0x00,0x50,                          /* TCP */
        0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x02,
        0x50,0x12,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV6; exp.version = 6; exp.ip_start = 14;
        exp.ip_data.ipv6.src_ip[0]=0x20; exp.ip_data.ipv6.src_ip[1]=0x01;
        exp.ip_data.ipv6.src_ip[2]=0x0D; exp.ip_data.ipv6.src_ip[3]=0xB8;
        exp.ip_data.ipv6.src_ip[15]=0x01;
        exp.ip_data.ipv6.dst_ip[0]=0x20; exp.ip_data.ipv6.dst_ip[1]=0x01;
        exp.ip_data.ipv6.dst_ip[2]=0x0D; exp.ip_data.ipv6.dst_ip[3]=0xB8;
        exp.ip_data.ipv6.dst_ip[15]=0x02;
        exp.ip_data.ipv6.next_header = TCP;
        exp.data.tcp.src_port[0]=0x1F; exp.data.tcp.src_port[1]=0x90;
        exp.data.tcp.dst_port[0]=0x00; exp.data.tcp.dst_port[1]=0x50;
        exp.data.tcp.flags = 0x12;

        ParserResult r = run_test("L. IPv6 + double Fragment + TCP", pktL, sizeof(pktL), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.ip_data.ipv6.next_header == TCP,   "next_header == TCP");
        check(be16(r.data.tcp.src_port) == 8080,   "src_port == 8080");
        check(r.data.tcp.flags == 0x12,            "tcp.flags == SYN+ACK");
    }

    /* ================================================================
     * RESUME
     * ================================================================ */
    printf("\n=====================================================\n");
    printf("RESUME\n");
    printf("=====================================================\n");
    int total = g_pass + g_fail;
    printf("  Total checks : %d\n", total);
    printf("  PASS         : %d\n", g_pass);
    printf("  FAIL         : %d\n", g_fail);
    printf("  Taux         : %.1f%%\n", total ? (100.0 * g_pass / total) : 0.0);
    printf("=====================================================\n");
    return g_fail == 0 ? 0 : 1;
}