#include <stdio.h>
#include <string.h>
#include "parser.h"

/* ---------------- Compteurs globaux ---------------- */
static int g_pass = 0;
static int g_fail = 0;

static void check(int cond, const char *msg) {
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; }
    else      { printf("  [FAIL] %s\n", msg); g_fail++; }
}

/* ---------------- Helpers ---------------- */

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

static uint16_t be16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }

static void print_hex(const char *label, const uint8_t *data, int len) {
    printf("  %-18s (%2d) : ", label, len);
    for (int i = 0; i < len; i++) printf("%02X ", data[i]);
    printf("\n");
}

static void print_packet(const uint8_t *pkt, int len) {
    printf("  Packet (%d octets) :\n", len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("    %04X : ", i);
        printf("%02X ", pkt[i]);
        if (i % 16 == 15 || i == len - 1) printf("\n");
    }
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

/* Affiche EXPECTED / ACTUAL côte à côte */
static void compare_show(const ParserResult *exp, const ParserResult *act) {
    printf("  --- EXPECTED (ce que la fonction DOIT produire) ---\n");
    print_result(exp);
    printf("  --- ACTUAL (ce que la fonction produit) ---\n");
    print_result(act);
}

/* Construit un ParserResult attendu "vide" par défaut */
static ParserResult mk_expected(void) {
    ParserResult r;
    memset(&r, 0, sizeof(r));
    return r;
}

/* ---------------- run_test ---------------- */

static ParserResult run_test(const char *name,
                             const uint8_t *pkt, int len,
                             const ParserResult *expected) {
    printf("\n=====================================================\n");
    printf("TEST : %s\n", name);
    printf("=====================================================\n");
    printf("  --- INPUT ---\n");
    print_packet(pkt, len);

    ParserResult actual = parse(pkt, len);
    compare_show(expected, &actual);

    printf("  --- CHECKS ---\n");
    return actual;
}

/* ---------------- Main ---------------- */

int main(void) {

    /* ========== Test 1 : IPv4 + TCP ========== */
    const uint8_t pkt1[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x45,0x00,0x00,0x28, 0x00,0x00,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x1F,0x90, 0x00,0x50,
        0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x02,
        0x50,0x02,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.n_vlan = 0; exp.ip_start = 14;
        exp.type = IPV4; exp.version = 4; exp.ihl = 5;
        uint8_t sm[] = {0x66,0x77,0x88,0x99,0xAA,0xBB};
        uint8_t dm[] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(exp.src_mac, sm, 6); memcpy(exp.dst_mac, dm, 6);
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);
        exp.ip_data.ipv4.proto = TCP;
        exp.data.tcp.src_port[0] = 0x1F; exp.data.tcp.src_port[1] = 0x90;
        exp.data.tcp.dst_port[0] = 0x00; exp.data.tcp.dst_port[1] = 0x50;
        exp.data.tcp.flags = 0x02;

        ParserResult r = run_test("IPv4 + TCP (SYN)", pkt1, sizeof(pkt1), &exp);
        check(r.code == exp.code,                            "code == SUCCES");
        check(r.version == 4,                                "version == 4");
        check(r.type == IPV4,                                "type == IPV4");
        check(r.n_vlan == 0,                                 "n_vlan == 0");
        check(r.ihl == 5,                                    "ihl == 5");
        check(r.ip_data.ipv4.proto == TCP,                   "proto == TCP");
        check(be16(r.data.tcp.src_port) == 8080,             "tcp.src_port == 8080");
        check(be16(r.data.tcp.dst_port) == 80,               "tcp.dst_port == 80");
        check(r.data.tcp.flags == 0x02,                      "tcp.flags == SYN");
    }

    /* ========== Test 2 : IPv4 + UDP ========== */
    const uint8_t pkt2[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x45,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00,
        0x40,0x11,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x00,0x35, 0x30,0x39, 0x00,0x08, 0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV4; exp.version = 4; exp.ihl = 5;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);
        exp.ip_data.ipv4.proto = UDP;
        exp.data.udp.src_port[0] = 0x00; exp.data.udp.src_port[1] = 0x35;
        exp.data.udp.dst_port[0] = 0x30; exp.data.udp.dst_port[1] = 0x39;

        ParserResult r = run_test("IPv4 + UDP", pkt2, sizeof(pkt2), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.version == 4,                      "version == 4");
        check(r.type == IPV4,                      "type == IPV4");
        check(r.ip_data.ipv4.proto == UDP,         "proto == UDP");
        check(be16(r.data.udp.src_port) == 53,     "udp.src_port == 53");
        check(be16(r.data.udp.dst_port) == 12345,  "udp.dst_port == 12345");
    }

    /* ========== Test 3 : IPv4 + ICMP ========== */
    const uint8_t pkt3[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x08,0x00,
        0x45,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00,
        0x40,0x01,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x08, 0x00, 0x00,0x00, 0x00,0x01, 0x00,0x01,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV4; exp.version = 4; exp.ihl = 5;
        uint8_t s4[] = {0xC0,0xA8,0x00,0x01};
        uint8_t d4[] = {0xC0,0xA8,0x00,0x02};
        memcpy(exp.ip_data.ipv4.src_ip, s4, 4);
        memcpy(exp.ip_data.ipv4.dst_ip, d4, 4);
        exp.ip_data.ipv4.proto = ICMP;
        exp.data.icmp.type = 8;
        exp.data.icmp.code = 0;

        ParserResult r = run_test("IPv4 + ICMP (echo request)", pkt3, sizeof(pkt3), &exp);
        check(r.code == SUCCES,               "code == SUCCES");
        check(r.version == 4,                 "version == 4");
        check(r.ip_data.ipv4.proto == ICMP,   "proto == ICMP");
        check(r.data.icmp.type == 8,          "icmp.type == 8");
        check(r.data.icmp.code == 0,          "icmp.code == 0");
    }

    /* ========== Test 4 : IPv6 + TCP ========== */
    const uint8_t pkt4[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x14,
        0x06,
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x1F,0x90,0x00,0x50,
        0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x02,
        0x50,0x12,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV6; exp.version = 6;
        exp.ip_data.ipv6.src_ip[0]  = 0x20; exp.ip_data.ipv6.src_ip[1]  = 0x01;
        exp.ip_data.ipv6.src_ip[2]  = 0x0D; exp.ip_data.ipv6.src_ip[3]  = 0xB8;
        exp.ip_data.ipv6.src_ip[15] = 0x01;
        exp.ip_data.ipv6.dst_ip[0]  = 0x20; exp.ip_data.ipv6.dst_ip[1]  = 0x01;
        exp.ip_data.ipv6.dst_ip[2]  = 0x0D; exp.ip_data.ipv6.dst_ip[3]  = 0xB8;
        exp.ip_data.ipv6.dst_ip[15] = 0x02;
        exp.ip_data.ipv6.next_header = TCP;
        exp.data.tcp.src_port[0] = 0x1F; exp.data.tcp.src_port[1] = 0x90;
        exp.data.tcp.dst_port[0] = 0x00; exp.data.tcp.dst_port[1] = 0x50;
        exp.data.tcp.flags = 0x12;

        ParserResult r = run_test("IPv6 + TCP (SYN+ACK)", pkt4, sizeof(pkt4), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.version == 6,                      "version == 6");
        check(r.type == IPV6,                      "type == IPV6");
        check(r.ip_data.ipv6.next_header == TCP,   "next_header == TCP");
        check(be16(r.data.tcp.src_port) == 8080,   "tcp.src_port == 8080");
        check(be16(r.data.tcp.dst_port) == 80,     "tcp.dst_port == 80");
        check(r.data.tcp.flags == 0x12,            "tcp.flags == SYN+ACK");
    }

    /* ========== Test 5 : IPv6 + UDP ========== */
    const uint8_t pkt5[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x08,
        0x11,
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x00,0x35,0x30,0x39,0x00,0x08,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV6; exp.version = 6;
        exp.ip_data.ipv6.next_header = UDP;
        exp.data.udp.src_port[0] = 0x00; exp.data.udp.src_port[1] = 0x35;
        exp.data.udp.dst_port[0] = 0x30; exp.data.udp.dst_port[1] = 0x39;

        ParserResult r = run_test("IPv6 + UDP", pkt5, sizeof(pkt5), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.version == 6,                      "version == 6");
        check(r.ip_data.ipv6.next_header == UDP,   "next_header == UDP");
        check(be16(r.data.udp.src_port) == 53,     "udp.src_port == 53");
        check(be16(r.data.udp.dst_port) == 12345,  "udp.dst_port == 12345");
    }

    /* ========== Test 6 : IPv6 + ICMP ========== */
    const uint8_t pkt6[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
        0x00,0x08,
        0x3A,   /* 58 = ICMPv6 (le ping d'IPv6 ; 1 = ICMP, c'est pour IPv4) */
        0x40,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x80,0x00,0x00,0x00,0x00,0x01,0x00,0x01,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.type = IPV6; exp.version = 6;
        exp.ip_data.ipv6.next_header = ICMPV6;
        exp.data.icmp.type = 128;
        exp.data.icmp.code = 0;

        ParserResult r = run_test("IPv6 + ICMP", pkt6, sizeof(pkt6), &exp);
        check(r.code == SUCCES,                    "code == SUCCES");
        check(r.version == 6,                      "version == 6");
        check(r.ip_data.ipv6.next_header == ICMPV6, "next_header == ICMPV6 (58)");
        check(r.data.icmp.type == 128,             "icmp.type == 128");
        check(r.data.icmp.code == 0,               "icmp.code == 0");
    }

    /* ========== Test 7 : VLAN + IPv4 + TCP ========== */
    const uint8_t pkt7[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x81,0x00,
        0x00,0x64,
        0x08,0x00,
        0x45,0x00,0x00,0x28, 0x00,0x00,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xC0,0xA8,0x00,0x01,
        0xC0,0xA8,0x00,0x02,
        0x1F,0x90,0x00,0x50,
        0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x02,
        0x50,0x02,0xFF,0xFF,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = SUCCES; exp.n_vlan = 1; exp.type = IPV4;
        exp.version = 4; exp.ihl = 5;
        exp.ip_data.ipv4.proto = TCP;
        exp.data.tcp.src_port[0] = 0x1F; exp.data.tcp.src_port[1] = 0x90;
        exp.data.tcp.dst_port[0] = 0x00; exp.data.tcp.dst_port[1] = 0x50;
        exp.data.tcp.flags = 0x02;

        ParserResult r = run_test("VLAN + IPv4 + TCP", pkt7, sizeof(pkt7), &exp);
        check(r.code == SUCCES,                "code == SUCCES");
        check(r.n_vlan == 1,                   "n_vlan == 1");
        check(r.type == IPV4,                  "type == IPV4");
        check(r.version == 4,                  "version == 4");
        check(r.ip_data.ipv4.proto == TCP,     "proto == TCP");
        check(be16(r.data.tcp.src_port) == 8080, "tcp.src_port == 8080");
        check(be16(r.data.tcp.dst_port) == 80,   "tcp.dst_port == 80");
    }

    /* ========== Test 8 : paquet trop court ========== */
    const uint8_t pkt8[] = { 0x00,0x11,0x22,0x33,0x44 };
    {
        ParserResult exp = mk_expected();
        exp.code = TOO_LITTLE;

        ParserResult r = run_test("Paquet trop court (5 octets)", pkt8, sizeof(pkt8), &exp);
        check(r.code == TOO_LITTLE, "code == TOO_LITTLE");
    }

    /* ========== Test 9 : ethertype inconnu ========== */
    const uint8_t pkt9[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99,0xAA,0xBB,
        0x12,0x34,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    {
        ParserResult exp = mk_expected();
        exp.code = NOT_HANDLE;
        exp.type = 0x1234;

        ParserResult r = run_test("Ethertype inconnu (0x1234)", pkt9, sizeof(pkt9), &exp);
        check(r.code == NOT_HANDLE, "code == NOT_HANDLE");
    }

    /* ========== Résumé ========== */
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