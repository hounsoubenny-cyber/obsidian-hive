/* test_ipset.c : tests de l'ensemble d'IP partagé (ipset.c). Lancer : ./run_tests.sh ipset */
#define _GNU_SOURCE
#include "../test_common.h"
#include "ipset.h"
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

static const uint8_t A[4] = {10, 0, 0, 1}, B[4] = {10, 0, 0, 2}, C[4] = {192, 168, 1, 1};

static void ip4(uint8_t *out, uint32_t n) { out[0] = 10; out[1] = (uint8_t)(n >> 16); out[2] = (uint8_t)(n >> 8); out[3] = (uint8_t)n; }

static void t_arguments(void) {
    CHECK(ipset_create(0) == NULL, "ipset_create(0) → NULL");
    IpSet *s = ipset_create(8);
    CHECK(s != NULL, "ipset_create(8)");
    CHECK_EQ(ipset_add(NULL, A, 1), -1, "add(NULL)");
    CHECK_EQ(ipset_add(s, NULL, 1), -1, "add(ip NULL)");
    CHECK_EQ(ipset_add(s, A, 2), -1, "add(v4 == 2)");
    CHECK_EQ(ipset_remove(NULL, A, 1), -1, "remove(NULL)");
    CHECK_EQ(ipset_remove(s, A, 1), -1, "remove d'une IP absente → -1");
    CHECK_EQ(ipset_contains(NULL, A, 1), 0, "contains(NULL) → 0");
    CHECK_EQ(ipset_contains(s, NULL, 1), 0, "contains(ip NULL) → 0");
    CHECK_EQ(ipset_count(NULL), 0, "count(NULL) → 0");
    ipset_destroy(s);
    ipset_destroy(NULL);
}

static void t_ajouter_chercher_retirer(void) {
    IpSet *s = ipset_create(8);
    CHECK_EQ(ipset_contains(s, A, 1), 0, "vide : absente");
    CHECK_EQ(ipset_add(s, A, 1), 0, "add A");
    CHECK_EQ(ipset_add(s, A, 1), 0, "add A une 2e fois : 0, sans doublon");
    CHECK_EQ(ipset_count(s), 1, "1 IP");
    CHECK_EQ(ipset_contains(s, A, 1), 1, "A présente");
    CHECK_EQ(ipset_contains(s, B, 1), 0, "B absente");
    ipset_add(s, B, 1); ipset_add(s, C, 1);
    CHECK_EQ(ipset_count(s), 3, "3 IP");
    CHECK_EQ(ipset_remove(s, B, 1), 0, "remove B");
    CHECK_EQ(ipset_contains(s, B, 1), 0, "B retirée");
    CHECK(ipset_contains(s, A, 1) == 1 && ipset_contains(s, C, 1) == 1, "A et C toujours là (la chaîne n'est pas coupée)");
    CHECK_EQ(ipset_remove(s, B, 1), -1, "remove B une 2e fois → -1");
    CHECK_EQ(ipset_count(s), 2, "2 IP");
    CHECK_EQ(ipset_add(s, B, 1), 0, "B revient (case supprimée réutilisée)");
    CHECK_EQ(ipset_contains(s, B, 1), 1, "B présente");
    ipset_destroy(s);
}

static void t_v4_et_v6_distincts(void) {
    uint8_t six[16] = {10, 0, 0, 1};                              /* mêmes 4 premiers octets que A, le reste à 0 */
    uint8_t six2[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    IpSet *s = ipset_create(8);
    ipset_add(s, A, 1);
    CHECK_EQ(ipset_contains(s, six, 0), 0, "A (v4) n'est pas la même chose que 0a00:0001:: (v6)");
    ipset_add(s, six, 0);
    CHECK_EQ(ipset_count(s), 2, "les deux coexistent");
    ipset_add(s, six2, 0);
    CHECK_EQ(ipset_contains(s, six2, 0), 1, "IPv6 2001:db8::1 présente");
    ipset_remove(s, A, 1);
    CHECK(ipset_contains(s, A, 1) == 0 && ipset_contains(s, six, 0) == 1, "retirer la v4 ne touche pas la v6");
    ipset_destroy(s);
}

static void t_collisions_et_plein(void) {
    IpSet *s = ipset_create(8);                                   /* 16 cases, 8 IP max : beaucoup de collisions */
    uint8_t ip[4];
    int added = 0;
    for (uint32_t i = 0; i < 40; i++) { ip4(ip, i); if (ipset_add(s, ip, 1) == 0) added++; }
    CHECK_EQ(added, 8, "exactement 8 IP acceptées, le reste est refusé (-1)");
    int ok = 1;
    for (uint32_t i = 0; i < 8; i++) { ip4(ip, i); if (!ipset_contains(s, ip, 1)) ok = 0; }
    CHECK(ok, "les 8 IP acceptées sont toutes retrouvées malgré les collisions et le tour de table");
    ip4(ip, 20);
    CHECK_EQ(ipset_contains(s, ip, 1), 0, "une IP refusée n'est pas là");
    ipset_destroy(s);
}

static void t_retirer_beaucoup(void) {
    IpSet *s = ipset_create(8);
    uint8_t ip[4];
    for (int round = 0; round < 3; round++) {
        for (uint32_t i = 0; i < 5; i++) { ip4(ip, i); ipset_add(s, ip, 1); }
        for (uint32_t i = 0; i < 5; i++) { ip4(ip, i); CHECK_EQ(ipset_remove(s, ip, 1), 0, "remove"); }
    }
    CHECK_EQ(ipset_count(s), 0, "vide à la fin");
    ip4(ip, 2);
    CHECK_EQ(ipset_contains(s, ip, 1), 0, "plus rien");
    ipset_destroy(s);
}

/* ───── lecteurs et écrivain en même temps ───── */
struct Shared { IpSet *s; _Atomic int stop; _Atomic long errors; int n_perm; };

static void *reader(void *a) {
    struct Shared *sh = a;
    uint8_t ip[4];
    while (!atomic_load(&sh -> stop)) {
        for (int i = 0; i < sh -> n_perm; i++) {                  /* les IP permanentes doivent TOUJOURS être trouvées */
            ip4(ip, 1000 + (uint32_t)i);
            if (!ipset_contains(sh -> s, ip, 1)) atomic_fetch_add(&sh -> errors, 1);
        }
        for (int i = 0; i < 50; i++) {                            /* les IP jamais ajoutées ne doivent JAMAIS être trouvées */
            ip4(ip, 900000 + (uint32_t)i);
            if (ipset_contains(sh -> s, ip, 1)) atomic_fetch_add(&sh -> errors, 1);
        }
    }
    return NULL;
}

static void t_lecteurs_pendant_l_ecriture(void) {
    struct Shared sh;
    sh.s = ipset_create(512);
    sh.n_perm = 50;
    atomic_init(&sh.stop, 0); atomic_init(&sh.errors, 0);
    uint8_t ip[4];
    for (int i = 0; i < sh.n_perm; i++) { ip4(ip, 1000 + (uint32_t)i); ipset_add(sh.s, ip, 1); }
    pthread_t th[4];
    for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, reader, &sh);
    for (int round = 0; round < 300; round++) {                   /* l'écrivain ajoute et retire des IP qui se mélangent aux permanentes */
        for (uint32_t i = 0; i < 100; i++) { ip4(ip, 2000 + i); ipset_add(sh.s, ip, 1); }
        for (uint32_t i = 0; i < 100; i++) { ip4(ip, 2000 + i); ipset_remove(sh.s, ip, 1); }
    }
    atomic_store(&sh.stop, 1);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    CHECK_EQ(atomic_load(&sh.errors), 0, "4 lecteurs : jamais une permanente manquante, jamais une IP fantôme (30 000 ajouts / retraits)");
    CHECK_EQ(ipset_count(sh.s), 50, "il reste les 50 permanentes");
    ipset_destroy(sh.s);
}


/* ───── cases « supprimées » (TOMB) : elles ne doivent pas faire déclarer la table pleine à tort ───── */

static void t_tomb_ne_saturent_pas(void) {
    IpSet *s = ipset_create(8);                                   /* 16 cases, 8 IP max à la fois */
    uint8_t ip[4];
    int refused = 0;
    for (uint32_t i = 0; i < 1000; i++) {                         /* 1000 IP DIFFÉRENTES, une seule présente à la fois */
        ip4(ip, 5000 + i);
        if (ipset_add(s, ip, 1) != 0) refused++;
        if (ipset_remove(s, ip, 1) != 0) refused++;
    }
    CHECK_EQ(refused, 0, "1000 IP différentes ajoutées puis retirées : aucun refus « plein »");
    CHECK_EQ(ipset_count(s), 0, "vide à la fin");
    ipset_destroy(s);
}

static void t_tomb_fenetre_glissante(void) {
    /* comme un IPS : des IP arrivent, d'autres partent, 500 présentes en même temps, 200 000 IP différentes en tout */
    IpSet *s = ipset_create(1024);
    uint8_t ip[4];
    int refused = 0;
    const uint32_t N = 200000, WIN = 500;
    for (uint32_t i = 0; i < N; i++) {
        ip4(ip, 10000 + i);
        if (ipset_add(s, ip, 1) != 0) refused++;
        if (i >= WIN) { ip4(ip, 10000 + i - WIN); if (ipset_remove(s, ip, 1) != 0) refused++; }
    }
    CHECK_EQ(refused, 0, "200 000 IP différentes, 500 présentes à la fois : aucun refus");
    CHECK_EQ(ipset_count(s), WIN, "il reste exactement 500 IP");
    int ok = 1;
    for (uint32_t i = N - WIN; i < N; i++) { ip4(ip, 10000 + i); if (!ipset_contains(s, ip, 1)) ok = 0; }
    CHECK(ok, "les 500 dernières sont toutes retrouvées");
    int ghost = 0;
    for (uint32_t i = 0; i < 2000; i++) { ip4(ip, 10000 + i); if (ipset_contains(s, ip, 1)) ghost++; }
    CHECK_EQ(ghost, 0, "aucune ancienne IP retirée n'est encore vue");
    ipset_destroy(s);
}

static uint32_t rng_next(uint32_t *st) { *st = *st * 1664525u + 1013904223u; return *st >> 8; }

/* Compare l'ensemble à un tableau de booléens (le « modèle ») sur des milliers d'opérations au hasard.
 *   cap, universe : taille demandée à ipset_create, nombre d'IP différentes possibles (<= 64)
 *   live_max      : le modèle n'essaie jamais d'avoir plus d'IP présentes que ça
 *   strict        : 1 = aucun refus « plein » toléré · 0 = un refus est toléré (les cases supprimées encore utiles comptent
 *                   dans le budget de cases : dans une table minuscule, elle peut dire « plein » avant live_max IP).
 * Dans les deux cas : contains, remove et count doivent être EXACTS à chaque opération. */
static int model_run(uint32_t cap, uint32_t universe, int live_max, int strict, uint32_t seed, int *accepted) {
    IpSet *s = ipset_create(cap);
    uint32_t st = seed * 7919u;
    int model[64] = {0}, n = 0, bad = 0;
    uint8_t ip[4];
    for (int step = 0; step < 4000; step++) {
        uint32_t k = rng_next(&st) % universe, op = rng_next(&st) % 3;
        ip4(ip, 300 + k);
        if (op == 0) {
            if (!model[k] && n >= live_max) continue;             /* le modèle ne dépasse pas live_max */
            int r = ipset_add(s, ip, 1);
            if (r == 0) { if (!model[k]) { model[k] = 1; n++; (*accepted)++; } }
            else if (strict || model[k]) bad++;                   /* refus : jamais pour une IP déjà là ; jamais en mode strict */
        } else if (op == 1) {
            int r = ipset_remove(s, ip, 1);
            if (model[k]) { if (r != 0) bad++; model[k] = 0; n--; }
            else if (r != -1) bad++;
        } else {
            if (ipset_contains(s, ip, 1) != model[k]) bad++;
        }
        if ((int)ipset_count(s) != n) bad++;
    }
    for (uint32_t k = 0; k < universe; k++) { ip4(ip, 300 + k); if (ipset_contains(s, ip, 1) != model[k]) bad++; }
    ipset_destroy(s);
    return bad;
}

static void t_modele_aleatoire_minuscule(void) {
    /* 16 cases, 12 IP possibles : collisions, chaînes et tour de table en permanence */
    int accepted = 0, bad = 0;
    for (uint32_t seed = 1; seed <= 20; seed++) bad += model_run(8, 12, 8, 0, seed, &accepted);
    CHECK_EQ(bad, 0, "20 graines, table minuscule : contains / remove / count toujours exacts");
    CHECK(accepted > 1000, "la table accepte bien des IP (elle ne refuse pas tout)");
}

static void t_modele_aleatoire_realiste(void) {
    /* 128 cases, au plus 16 IP présentes sur 40 possibles : aucun refus ne doit arriver */
    int accepted = 0, bad = 0;
    for (uint32_t seed = 1; seed <= 20; seed++) bad += model_run(64, 40, 16, 1, seed, &accepted);
    CHECK_EQ(bad, 0, "20 graines, table à l'aise : exact ET aucun refus « plein »");
}

static void *churn_thread(void *a) {
    struct Shared *sh = a; uint8_t ip[4];
    for (int round = 0; round < 4000; round++) {
        for (uint32_t i = 0; i < 30; i++) { ip4(ip, 70000 + (uint32_t)(round % 7) * 31 + i); ipset_add(sh -> s, ip, 1); }
        for (uint32_t i = 0; i < 30; i++) { ip4(ip, 70000 + (uint32_t)(round % 7) * 31 + i); ipset_remove(sh -> s, ip, 1); }
    }
    return NULL;
}

static void t_lecteurs_table_serree(void) {
    /* petite table très chargée : le nettoyage des cases supprimées se fait pendant que 4 lecteurs lisent */
    struct Shared sh;
    sh.s = ipset_create(64);                                      /* 128 cases */
    sh.n_perm = 20;
    atomic_init(&sh.stop, 0); atomic_init(&sh.errors, 0);
    uint8_t ip[4];
    for (int i = 0; i < sh.n_perm; i++) { ip4(ip, 1000 + (uint32_t)i); ipset_add(sh.s, ip, 1); }
    pthread_t th[4], w;
    for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, reader, &sh);
    pthread_create(&w, NULL, churn_thread, &sh);
    pthread_join(w, NULL);
    atomic_store(&sh.stop, 1);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    CHECK_EQ(atomic_load(&sh.errors), 0, "table serrée : jamais une permanente manquante, jamais une IP fantôme");
    CHECK_EQ(ipset_count(sh.s), 20, "il reste les 20 permanentes");
    ipset_destroy(sh.s);
}

struct W { IpSet *s; uint32_t base; };
static void *writer_thread(void *a) {
    struct W *w = a; uint8_t ip[4];
    for (uint32_t i = 0; i < 1500; i++) { ip4(ip, w -> base + i); ipset_add(w -> s, ip, 1); }
    return NULL;
}

static void t_deux_ecrivains(void) {
    /* le verrou interne : deux écrivains en même temps ne perdent aucune IP */
    IpSet *s = ipset_create(4000);
    struct W w1 = { s, 0 }, w2 = { s, 100000 };
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_thread, &w1);
    pthread_create(&t2, NULL, writer_thread, &w2);
    pthread_join(t1, NULL); pthread_join(t2, NULL);
    CHECK_EQ(ipset_count(s), 3000, "3000 IP ajoutées par 2 écrivains : aucune perdue");
    uint8_t ip[4]; int ok = 1;
    for (uint32_t i = 0; i < 1500; i++) { ip4(ip, i); if (!ipset_contains(s, ip, 1)) ok = 0; ip4(ip, 100000 + i); if (!ipset_contains(s, ip, 1)) ok = 0; }
    CHECK(ok, "toutes retrouvées");
    ipset_destroy(s);
}

int main(int argc, char **argv) {
    tc_begin("test_ipset.c", argc, argv);
    RUN_LEAKS("arguments",                              t_arguments);
    RUN_LEAKS("ajouter, chercher, retirer",             t_ajouter_chercher_retirer);
    RUN_LEAKS("IPv4 et IPv6 distinctes",                t_v4_et_v6_distincts);
    RUN_LEAKS("collisions et table pleine",             t_collisions_et_plein);
    RUN_LEAKS("beaucoup d'ajouts et de retraits",       t_retirer_beaucoup);
    RUN_LEAKS("4 lecteurs pendant l'écriture",          t_lecteurs_pendant_l_ecriture);
    RUN_LEAKS("2 écrivains en même temps",              t_deux_ecrivains);
    RUN_LEAKS("cases supprimées : pas de saturation",   t_tomb_ne_saturent_pas);
    RUN_LEAKS("200 000 IP différentes, fenêtre glissante", t_tomb_fenetre_glissante);
    RUN_LEAKS("modèle aléatoire, table minuscule",      t_modele_aleatoire_minuscule);
    RUN_LEAKS("modèle aléatoire, table à l'aise",       t_modele_aleatoire_realiste);
    RUN_LEAKS("4 lecteurs, table serrée",               t_lecteurs_table_serree);
    return tc_end();
}
