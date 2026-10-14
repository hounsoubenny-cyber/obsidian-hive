/* test_portmap.c : tests de la bitmap de ports
 *
 * Compiler (depuis modules_c/) :
 *   gcc -std=gnu11 -g -O0 -Wall -Wextra -fsanitize=address,undefined \
 *       portmap/test_portmap.c portmap/portmap.c -o build/test_portmap && ./build/test_portmap
 * Ou simplement : ./run_tests.sh portmap
 *
 * Contrat testé :
 *   portmap_add  → 1 si le port est nouveau, 0 s'il était déjà vu ; count = nombre de ports distincts
 *   portmap_test → 1 si le port a été vu, 0 sinon
 *   portmap_init / portmap_reset → plus aucun port vu, count = 0
 *   refcount     → compteur « combien de flux utilisent cette PortMap » : init le met à 0,
 *                  add / test / reset ne le touchent pas (c'est flow_table qui le gère)
 */
#include "../test_common.h"
#include "portmap.h"

static int popcount_total(const struct PortMap *pm) {
    int n = 0;
    for (int i = 0; i < PORTMAP_WORDS; i++) n += __builtin_popcountll(pm->bits[i]);
    return n;
}

static int toute_la_bitmap_est(const struct PortMap *pm, uint64_t valeur) {
    for (int i = 0; i < PORTMAP_WORDS; i++)
        if (pm->bits[i] != valeur) return 0;
    return 1;
}

/* ── structure ── */

static void t_taille_et_constantes(void) {
    CHECK_EQ(PORTMAP_WORDS * 64, 65536, "1024 mots de 64 bits = 65536 ports");
    CHECK_EQ(sizeof(struct PortMap), 8200, "sizeof(struct PortMap) = 8192 + 2 compteurs");
}

/* ── init ── */

static void t_init_remet_tout_a_zero(void) {
    struct PortMap pm;
    memset(&pm, 0xFF, sizeof pm);            /* poubelle partout */
    portmap_init(&pm);
    CHECK(toute_la_bitmap_est(&pm, 0), "tous les bits à 0");
    CHECK_EQ(pm.count, 0, "count == 0");
    CHECK_EQ(pm.refcount, 0, "refcount == 0 (sinon valeur aléatoire sur un malloc)");
}

/* ── add / test ── */

static void t_add_nouveau_puis_deja_vu(void) {
    struct PortMap pm;
    portmap_init(&pm);
    CHECK_EQ(portmap_add(&pm, 80), 1, "premier add(80) → 1 (nouveau)");
    CHECK_EQ(pm.count, 1, "count == 1");
    CHECK_EQ(portmap_add(&pm, 80), 0, "deuxième add(80) → 0 (déjà vu)");
    CHECK_EQ(pm.count, 1, "count reste 1");
    CHECK_EQ(portmap_add(&pm, 80), 0, "troisième add(80) → 0");
    CHECK_EQ(pm.count, 1, "count reste 1");
}

static void t_test_vu_et_non_vu(void) {
    struct PortMap pm;
    portmap_init(&pm);
    CHECK_EQ(portmap_test(&pm, 80), 0, "80 pas encore vu → 0");
    portmap_add(&pm, 80);
    CHECK_EQ(portmap_test(&pm, 80), 1, "80 vu → 1");
    CHECK_EQ(portmap_test(&pm, 79), 0, "79 (voisin) → 0");
    CHECK_EQ(portmap_test(&pm, 81), 0, "81 (voisin) → 0");
    CHECK_EQ(portmap_test(&pm, 0), 0, "0 → 0");
    CHECK_EQ(portmap_test(&pm, 65535), 0, "65535 → 0");
}

static void t_test_ne_modifie_rien(void) {
    struct PortMap pm;
    portmap_init(&pm);
    portmap_add(&pm, 1234);
    struct PortMap avant = pm;
    for (int p = 0; p < 65536; p += 7) (void)portmap_test(&pm, (uint16_t)p);
    CHECK_MEM(&pm, &avant, sizeof pm, "portmap_test est en lecture seule");
}

static void t_bornes_des_mots(void) {
    struct PortMap pm;
    portmap_init(&pm);
    uint16_t ports[] = {0, 63, 64, 127, 128, 32768, 65535};
    for (size_t i = 0; i < sizeof ports / sizeof ports[0]; i++) {
        CHECK_EQ(portmap_add(&pm, ports[i]), 1, "add d'une borne de mot → 1");
        CHECK_EQ(portmap_test(&pm, ports[i]), 1, "test de cette borne → 1");
    }
    CHECK_EQ(pm.count, 7, "7 ports distincts");
    CHECK_EQ_HEX(pm.bits[0],    (1ULL << 0) | (1ULL << 63), "mot 0 : bits 0 et 63");
    CHECK_EQ_HEX(pm.bits[1],    (1ULL << 0) | (1ULL << 63), "mot 1 : ports 64 et 127");
    CHECK_EQ_HEX(pm.bits[2],    1ULL << 0,                  "mot 2 : port 128");
    CHECK_EQ_HEX(pm.bits[512],  1ULL << 0,                  "mot 512 : port 32768");
    CHECK_EQ_HEX(pm.bits[1023], 1ULL << 63,                 "mot 1023 : port 65535");
    uint16_t voisins[] = {1, 62, 65, 126, 129, 32767, 32769, 65534};
    for (size_t i = 0; i < sizeof voisins / sizeof voisins[0]; i++)
        CHECK_EQ(portmap_test(&pm, voisins[i]), 0, "voisin d'une borne → 0");
}

static void t_tous_les_ports(void) {
    struct PortMap pm;
    portmap_init(&pm);
    int mauvais = 0;
    for (int p = 0; p < 65536; p++)
        if (portmap_add(&pm, (uint16_t)p) != 1) mauvais++;
    CHECK_EQ(mauvais, 0, "tous les premiers add renvoient 1");
    CHECK_EQ(pm.count, 65536, "count == 65536");
    CHECK(toute_la_bitmap_est(&pm, ~0ULL), "tous les bits à 1");

    mauvais = 0;
    for (int p = 0; p < 65536; p++)
        if (portmap_add(&pm, (uint16_t)p) != 0) mauvais++;
    CHECK_EQ(mauvais, 0, "tous les seconds add renvoient 0");
    CHECK_EQ(pm.count, 65536, "count inchangé");
}

static void t_count_egal_nombre_de_bits(void) {
    /* 5000 ports « au hasard » (suite fixe) : count doit égaler le nombre de ports DISTINCTS
       et le nombre de bits à 1 */
    static uint8_t vus[65536];
    struct PortMap pm;
    portmap_init(&pm);
    uint32_t seed = 2026;
    int distincts = 0, mauvais_retours = 0;
    for (int i = 0; i < 5000; i++) {
        seed = seed * 1664525u + 1013904223u;
        uint16_t p = (uint16_t)(seed >> 16);
        int attendu = vus[p] ? 0 : 1;
        if (!vus[p]) { vus[p] = 1; distincts++; }
        if (portmap_add(&pm, p) != attendu) mauvais_retours++;
    }
    CHECK_EQ(mauvais_retours, 0, "valeur de retour de add correcte à chaque fois");
    CHECK_EQ(pm.count, distincts, "count == nombre de ports distincts");
    CHECK_EQ(popcount_total(&pm), distincts, "nombre de bits à 1 == nombre de ports distincts");
}

/* ── reset ── */

static void t_reset(void) {
    struct PortMap pm;
    portmap_init(&pm);
    for (int p = 1; p <= 100; p++) portmap_add(&pm, (uint16_t)(p * 600));
    CHECK_EQ(pm.count, 100, "100 ports avant reset");
    portmap_reset(&pm);
    CHECK_EQ(pm.count, 0, "count == 0 après reset");
    CHECK(toute_la_bitmap_est(&pm, 0), "tous les bits à 0 après reset");
    CHECK_EQ(portmap_test(&pm, 600), 0, "600 n'est plus vu");
    CHECK_EQ(portmap_add(&pm, 600), 1, "on peut ré-ajouter 600 → 1 (nouveau)");
    CHECK_EQ(pm.count, 1, "count == 1");
}

static void t_refcount_pas_touche(void) {
    struct PortMap pm;
    portmap_init(&pm);
    pm.refcount = 5;
    portmap_add(&pm, 22);
    portmap_add(&pm, 443);
    (void)portmap_test(&pm, 22);
    CHECK_EQ(pm.refcount, 5, "add / test ne touchent pas refcount");
    portmap_reset(&pm);
    CHECK_EQ(pm.refcount, 5, "reset ne touche pas refcount (c'est flow_table qui le gère)");
}

static void t_deux_portmaps_independantes(void) {
    struct PortMap a, b;
    portmap_init(&a);
    portmap_init(&b);
    portmap_add(&a, 80);
    CHECK_EQ(portmap_test(&b, 80), 0, "ajouter dans a ne change pas b");
    CHECK_EQ(b.count, 0, "b.count == 0");
}

int main(int argc, char **argv) {
    tc_begin("test_portmap.c — portmap", argc, argv);

    RUN("structure : taille et constantes",                 t_taille_et_constantes);
    RUN("portmap_init : remet tout à zéro (même sur poubelle)", t_init_remet_tout_a_zero);
    RUN("portmap_add : nouveau → 1, déjà vu → 0",           t_add_nouveau_puis_deja_vu);
    RUN("portmap_test : vu / non vu / voisins",             t_test_vu_et_non_vu);
    RUN("portmap_test : lecture seule",                     t_test_ne_modifie_rien);
    RUN("bornes des mots de 64 bits (0, 63, 64, 65535...)", t_bornes_des_mots);
    RUN("les 65536 ports, deux fois",                       t_tous_les_ports);
    RUN("count == bits à 1 == ports distincts (5000 ports)", t_count_egal_nombre_de_bits);
    RUN("portmap_reset",                                    t_reset);
    RUN("refcount : add / test / reset n'y touchent pas",   t_refcount_pas_touche);
    RUN("deux PortMap sont indépendantes",                  t_deux_portmaps_independantes);

    return tc_end();
}
