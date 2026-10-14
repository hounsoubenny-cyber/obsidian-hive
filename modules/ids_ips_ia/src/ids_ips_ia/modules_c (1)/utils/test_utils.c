/* test_utils.c : tests de ipv4_to_u32 et port_to_u16
 *
 * Compiler (depuis modules_c/) :
 *   gcc -std=gnu11 -g -O0 -Wall -Wextra -fsanitize=address,undefined \
 *       utils/test_utils.c utils/utils.c -o build/test_utils && ./build/test_utils
 * Ou simplement : ./run_tests.sh utils
 */
#include <arpa/inet.h>
#include "../test_common.h"
#include "utils.h"

/* ── ipv4_to_u32 ── */

static void t_ipv4_valeurs_classiques(void) {
    uint8_t a[4] = {192, 168, 1, 10};
    CHECK_EQ_HEX(ipv4_to_u32(a), 0xC0A8010A, "192.168.1.10");
    uint8_t b[4] = {10, 0, 0, 1};
    CHECK_EQ_HEX(ipv4_to_u32(b), 0x0A000001, "10.0.0.1");
    uint8_t c[4] = {1, 2, 3, 4};
    CHECK_EQ_HEX(ipv4_to_u32(c), 0x01020304, "1.2.3.4");
    uint8_t d[4] = {127, 0, 0, 1};
    CHECK_EQ_HEX(ipv4_to_u32(d), 0x7F000001, "127.0.0.1");
}

static void t_ipv4_bornes(void) {
    uint8_t zero[4] = {0, 0, 0, 0};
    CHECK_EQ_HEX(ipv4_to_u32(zero), 0, "0.0.0.0");
    uint8_t full[4] = {255, 255, 255, 255};
    CHECK_EQ_HEX(ipv4_to_u32(full), 0xFFFFFFFFu, "255.255.255.255");
}

static void t_ipv4_chaque_octet_a_sa_place(void) {
    uint8_t a[4] = {1, 0, 0, 0}, b[4] = {0, 1, 0, 0}, c[4] = {0, 0, 1, 0}, d[4] = {0, 0, 0, 1};
    CHECK_EQ_HEX(ipv4_to_u32(a), 0x01000000, "octet 0 = poids fort");
    CHECK_EQ_HEX(ipv4_to_u32(b), 0x00010000, "octet 1");
    CHECK_EQ_HEX(ipv4_to_u32(c), 0x00000100, "octet 2");
    CHECK_EQ_HEX(ipv4_to_u32(d), 0x00000001, "octet 3 = poids faible");
}

static void t_ipv4_bit_de_signe(void) {
    /* un premier octet >= 128 ne doit PAS produire un nombre négatif / étendu sur 64 bits */
    uint8_t a[4] = {128, 0, 0, 1};
    uint32_t v = ipv4_to_u32(a);
    CHECK_EQ_HEX(v, 0x80000001u, "128.0.0.1");
    CHECK(v > 0x7FFFFFFFu, "le bit de poids fort est bien conservé");
    uint8_t b[4] = {200, 200, 200, 200};
    CHECK_EQ_HEX(ipv4_to_u32(b), 0xC8C8C8C8u, "200.200.200.200");
}

static void t_ipv4_coherent_avec_ntohl(void) {
    /* sur le fil, l'IP est en ordre réseau : ntohl(octets) doit donner la même chose */
    uint8_t ips[5][4] = {{1, 2, 3, 4}, {192, 168, 0, 255}, {255, 0, 0, 0}, {0, 0, 0, 255}, {172, 16, 254, 3}};
    for (int i = 0; i < 5; i++) {
        uint32_t raw;
        memcpy(&raw, ips[i], 4);
        CHECK_EQ_HEX(ipv4_to_u32(ips[i]), ntohl(raw), "ipv4_to_u32 == ntohl");
    }
}

static void t_ipv4_ne_modifie_pas_l_entree(void) {
    uint8_t a[4] = {9, 8, 7, 6}, copie[4] = {9, 8, 7, 6};
    (void)ipv4_to_u32(a);
    CHECK_MEM(a, copie, 4, "le tableau d'entrée est intact");
}

/* ── port_to_u16 ── */

static void t_port_valeurs_classiques(void) {
    uint8_t http[2] = {0x00, 0x50};
    CHECK_EQ(port_to_u16(http), 80, "80");
    uint8_t https[2] = {0x01, 0xBB};
    CHECK_EQ(port_to_u16(https), 443, "443");
    uint8_t haut[2] = {0xC7, 0x38};
    CHECK_EQ(port_to_u16(haut), 51000, "51000");
    uint8_t ssh[2] = {0x00, 0x16};
    CHECK_EQ(port_to_u16(ssh), 22, "22");
}

static void t_port_bornes(void) {
    uint8_t zero[2] = {0, 0};
    CHECK_EQ(port_to_u16(zero), 0, "port 0");
    uint8_t max[2] = {0xFF, 0xFF};
    CHECK_EQ(port_to_u16(max), 65535, "port 65535");
    uint8_t mid[2] = {0x80, 0x00};
    CHECK_EQ(port_to_u16(mid), 32768, "port 32768 (bit de poids fort seul)");
    uint8_t bas[2] = {0x00, 0xFF};
    CHECK_EQ(port_to_u16(bas), 255, "0x00FF");
    uint8_t fort[2] = {0xFF, 0x00};
    CHECK_EQ(port_to_u16(fort), 65280, "0xFF00");
}

static void t_port_exhaustif(void) {
    /* les 65536 valeurs possibles, sans exception */
    int mauvais = 0;
    for (int v = 0; v < 65536; v++) {
        uint8_t p[2] = {(uint8_t)(v >> 8), (uint8_t)(v & 0xFF)};
        if (port_to_u16(p) != (uint16_t)v) mauvais++;
    }
    CHECK_EQ(mauvais, 0, "nombre de ports mal convertis (sur 65536)");
}

static void t_port_coherent_avec_ntohs(void) {
    for (int v = 0; v < 65536; v += 257) {
        uint8_t p[2] = {(uint8_t)(v >> 8), (uint8_t)(v & 0xFF)};
        uint16_t raw;
        memcpy(&raw, p, 2);
        if (port_to_u16(p) != ntohs(raw)) { CHECK(0, "port_to_u16 != ntohs"); return; }
    }
    CHECK(1, "port_to_u16 == ntohs sur un échantillon");
}

int main(int argc, char **argv) {
    tc_begin("test_utils.c — utils", argc, argv);

    RUN("ipv4_to_u32 : valeurs classiques",              t_ipv4_valeurs_classiques);
    RUN("ipv4_to_u32 : 0.0.0.0 et 255.255.255.255",      t_ipv4_bornes);
    RUN("ipv4_to_u32 : chaque octet à sa place",         t_ipv4_chaque_octet_a_sa_place);
    RUN("ipv4_to_u32 : premier octet >= 128 (signe)",    t_ipv4_bit_de_signe);
    RUN("ipv4_to_u32 : cohérent avec ntohl",             t_ipv4_coherent_avec_ntohl);
    RUN("ipv4_to_u32 : n'écrit pas dans l'entrée",       t_ipv4_ne_modifie_pas_l_entree);

    RUN("port_to_u16 : valeurs classiques",              t_port_valeurs_classiques);
    RUN("port_to_u16 : 0, 65535, bits de poids fort",    t_port_bornes);
    RUN("port_to_u16 : les 65536 valeurs",               t_port_exhaustif);
    RUN("port_to_u16 : cohérent avec ntohs",             t_port_coherent_avec_ntohs);

    return tc_end();
}
