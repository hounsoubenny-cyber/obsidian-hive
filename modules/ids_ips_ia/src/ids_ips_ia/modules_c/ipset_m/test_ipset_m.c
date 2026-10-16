/* test_ipset_m.c : tests de la liste noire partagée redimensionnable (ipset_m.c). Lancer : ./run_tests.sh ipset_m
 * Sous ASan, une table libérée trop tôt ferait planter les tests de stress : c'est la preuve que la libération est sûre. */
#define _GNU_SOURCE
#include "../test_common.h"
#include "ipset_m.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#ifdef __SANITIZE_THREAD__
#define STRESS_DIV 4                    /* ThreadSanitizer ralentit de 5 à 15 fois : le harnais coupe chaque test à 5 s */
#else
#define STRESS_DIV 1
#endif

static void ip4(uint8_t *out, uint32_t n) { out[0] = 10; out[1] = (uint8_t)(n >> 16); out[2] = (uint8_t)(n >> 8); out[3] = (uint8_t)n; }

static IpSetM *new_m(uint32_t cap) {
    IpSetM *m = ipset_m_create(cap);
    CHECK(m != NULL, "création");
    return m;
}

/* ───────────── bases ───────────── */

static void t_basique(void) {
    IpSetM *m = new_m(64);
    uint8_t a[4] = {10, 0, 0, 1}, b[4] = {10, 0, 0, 2};
    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    CHECK_EQ(ipset_m_count(m), 0, "vide au départ");
    CHECK_EQ(ipset_m_is_blocked(m, a, 1), 0, "pas bloquée au départ");
    int r = ipset_m_register(m);
    CHECK(r >= 0, "inscription d'un lecteur");

    struct IpBlockMeta meta = { 2, IPM_SRC_AUTO, 1000, 0 };
    CHECK_EQ(ipset_m_add(m, a, 1, &meta), 0, "bloquer a");
    CHECK_EQ(ipset_m_is_blocked(m, a, 1), 1, "is_blocked (mutex)");
    CHECK_EQ(ipset_m_contains(m, r, a, 1), 1, "contains (sans verrou)");
    CHECK_EQ(ipset_m_contains(m, r, b, 1), 0, "b n'est pas bloquée");
    CHECK_EQ(ipset_m_contains(m, -1, a, 1), 1, "thread non inscrite : voie sûre, même réponse");
    CHECK_EQ(ipset_m_count(m), 1, "1 IP");

    struct IpBlockMeta got;
    memset(&got, 0, sizeof got);
    CHECK_EQ(ipset_m_get(m, a, 1, &got), 1, "get");
    CHECK_EQ(got.rule, 2, "règle gardée");
    CHECK_EQ(got.source, IPM_SRC_AUTO, "source gardée");
    CHECK_EQ(got.blocked_at_ms, 1000, "date gardée");

    struct IpBlockMeta manual = { 0, IPM_SRC_MANUAL, 2000, 0 };
    CHECK_EQ(ipset_m_add(m, a, 1, &manual), 0, "re-bloquer : les métadonnées sont remplacées");
    CHECK_EQ(ipset_m_count(m), 1, "toujours 1 IP");
    ipset_m_get(m, a, 1, &got);
    CHECK_EQ(got.source, IPM_SRC_MANUAL, "nouvelle source");
    CHECK_EQ(got.blocked_at_ms, 2000, "nouvelle date");

    CHECK_EQ(ipset_m_add(m, b, 1, NULL), 0, "meta NULL accepté");
    ipset_m_get(m, b, 1, &got);
    CHECK_EQ(got.source, IPM_SRC_AUTO, "meta NULL = AUTO");
    CHECK_EQ(got.until_ms, 0, "sans expiration");

    CHECK_EQ(ipset_m_add(m, v6, 0, NULL), 0, "IPv6");
    CHECK_EQ(ipset_m_contains(m, r, v6, 0), 1, "IPv6 trouvée");
    CHECK_EQ(ipset_m_count(m), 3, "3 IP");

    CHECK_EQ(ipset_m_remove(m, a, 1), 0, "débloquer a");
    CHECK_EQ(ipset_m_contains(m, r, a, 1), 0, "a n'est plus bloquée (sans verrou)");
    CHECK_EQ(ipset_m_is_blocked(m, a, 1), 0, "ni côté maître");
    CHECK_EQ(ipset_m_remove(m, a, 1), -1, "débloquer deux fois : -1");
    CHECK_EQ(ipset_m_count(m), 2, "2 IP");

    CHECK_EQ(ipset_m_add(NULL, a, 1, NULL), -1, "m NULL");
    CHECK_EQ(ipset_m_add(m, NULL, 1, NULL), -1, "ip NULL");
    CHECK_EQ(ipset_m_add(m, a, 2, NULL), -1, "v4 invalide");
    CHECK_EQ(ipset_m_remove(m, a, 2), -1, "remove : v4 invalide");
    CHECK_EQ(ipset_m_contains(NULL, 0, a, 1), 0, "contains(NULL) = 0");
    ipset_m_unregister(m, r);
    ipset_m_destroy(m);
    ipset_m_destroy(NULL);
}

static void t_liste_et_expiration(void) {
    IpSetM *m = new_m(64);
    uint8_t ip[4];
    uint64_t until[6] = {0, 0, 1000, 2000, 3000, 0};
    for (uint32_t i = 1; i <= 5; i++) {
        struct IpBlockMeta meta = { (uint8_t)i, IPM_SRC_AUTO, 10u * i, until[i] };
        ip4(ip, i);
        CHECK_EQ(ipset_m_add(m, ip, 1, &meta), 0, "ajout");
    }
    struct IpBlockInfo out[10];
    CHECK_EQ(ipset_m_list(m, out, 10), 5, "la liste a 5 lignes");
    int ok = 1;
    for (int i = 0; i < 5; i++) {
        uint32_t n = out[i].ip[3];
        if (out[i].v4 != 1 || out[i].ip[0] != 10 || n < 1 || n > 5) { ok = 0; continue; }
        if (out[i].meta.rule != n || out[i].meta.blocked_at_ms != 10u * n || out[i].meta.until_ms != until[n]) ok = 0;
    }
    CHECK(ok, "chaque ligne a la bonne IP et les bonnes métadonnées");
    CHECK_EQ(ipset_m_list(m, out, 3), 3, "max respecté");
    CHECK_EQ(ipset_m_list(m, out, 0), 0, "max = 0");
    CHECK_EQ(ipset_m_list(m, NULL, 10), 0, "out NULL");

    CHECK_EQ(ipset_m_expire(m, 999), 0, "rien n'a expiré à 999");
    CHECK_EQ(ipset_m_expire(m, 1000), 1, "une IP expire à 1000 (until_ms <= now)");
    ip4(ip, 2);
    CHECK_EQ(ipset_m_is_blocked(m, ip, 1), 0, "elle est débloquée");
    CHECK_EQ(ipset_m_count(m), 4, "4 IP");
    CHECK_EQ(ipset_m_expire(m, 5000), 2, "deux de plus à 5000");
    CHECK_EQ(ipset_m_count(m), 2, "restent les deux permanentes");
    CHECK_EQ(ipset_m_expire(m, 999999), 0, "les permanentes n'expirent jamais");
    ip4(ip, 1); CHECK_EQ(ipset_m_is_blocked(m, ip, 1), 1, "la 1 est toujours là");
    ip4(ip, 5); CHECK_EQ(ipset_m_is_blocked(m, ip, 1), 1, "la 5 aussi");
    ipset_m_destroy(m);
}

/* ───────────── la photo : toutes les IP bloquées avec leurs métadonnées ───────────── */

static void t_snapshot_vide_et_trie(void) {
    IpSetM *m = new_m(64);
    struct IpBlockInfo *list = (struct IpBlockInfo *)0x1;
    uint32_t n = 99;
    CHECK_EQ(ipset_m_snapshot(m, &list, &n), 0, "photo d'une liste vide : ok");
    CHECK(list == NULL, "aucune IP : *out vaut NULL");
    CHECK_EQ(n, 0, "aucune IP : n vaut 0");
    ipset_m_snapshot_free(list);                              /* free(NULL) : sans effet */
    ipset_m_snapshot_free(NULL);
    CHECK_EQ(ipset_m_snapshot(NULL, &list, &n), -1, "m NULL");
    CHECK_EQ(ipset_m_snapshot(m, NULL, &n), -1, "out NULL");
    CHECK_EQ(ipset_m_snapshot(m, &list, NULL), -1, "n NULL");

    uint8_t ip[4], v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
    uint64_t dates[5] = {500, 100, 900, 300, 700};
    for (uint32_t i = 0; i < 5; i++) {
        struct IpBlockMeta meta = { (uint8_t)(i + 1), IPM_SRC_AUTO, dates[i], 0 };
        ip4(ip, i + 1);
        ipset_m_add(m, ip, 1, &meta);
    }
    struct IpBlockMeta m6 = { 9, IPM_SRC_MANUAL, 900, 12345 };            /* même date que l'IP n°3 : l'ordre doit rester le même à chaque appel */
    ipset_m_add(m, v6, 0, &m6);

    CHECK_EQ(ipset_m_snapshot(m, &list, &n), 0, "photo de 6 IP");
    CHECK_EQ(n, 6, "6 lignes");
    int sorted = 1;
    for (uint32_t i = 1; i < n; i++) if (list[i - 1].meta.blocked_at_ms < list[i].meta.blocked_at_ms) sorted = 0;
    CHECK(sorted, "triée : les plus récemment bloquées d'abord");
    CHECK_EQ(list[0].meta.blocked_at_ms, 900, "la plus récente en premier");
    CHECK_EQ(list[5].meta.blocked_at_ms, 100, "la plus ancienne en dernier");
    int found6 = 0, found4 = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!list[i].v4) {
            found6 = list[i].ip[15] == 7 && list[i].meta.rule == 9 && list[i].meta.source == IPM_SRC_MANUAL && list[i].meta.until_ms == 12345;
        } else if (list[i].ip[3] >= 1 && list[i].ip[3] <= 5 && list[i].ip[0] == 10) {
            uint32_t k = list[i].ip[3] - 1;
            if (list[i].meta.rule == k + 1 && list[i].meta.blocked_at_ms == dates[k]) found4++;
        }
    }
    CHECK(found6, "l'IPv6 est là avec ses métadonnées");
    CHECK_EQ(found4, 5, "les 5 IPv4 sont là avec leurs métadonnées");

    struct IpBlockInfo *again = NULL;
    uint32_t n2 = 0;
    ipset_m_snapshot(m, &again, &n2);
    CHECK_EQ(n2, 6, "deuxième photo");
    CHECK(memcmp(list, again, sizeof(list[0]) * 6) == 0, "même ordre exactement, à chaque appel (même à date égale)");
    ipset_m_snapshot_free(list);
    ipset_m_snapshot_free(again);

    ip4(ip, 3);
    ipset_m_remove(m, ip, 1);
    ipset_m_snapshot(m, &list, &n);
    CHECK_EQ(n, 5, "après un déblocage : 5 lignes");
    int gone = 1;
    for (uint32_t i = 0; i < n; i++) if (list[i].v4 && list[i].ip[3] == 3) gone = 0;
    CHECK(gone, "l'IP débloquée n'est plus dans la photo");
    ipset_m_snapshot_free(list);
    ipset_m_destroy(m);
}

static void t_snapshot_gros(void) {
    IpSetM *m = new_m(64);
    uint8_t ip[4];
    for (uint32_t i = 0; i < 3000; i++) {
        struct IpBlockMeta meta = { (uint8_t)(i & 0xFF), IPM_SRC_AUTO, 1000 + i, 0 };
        ip4(ip, 100000 + i);
        ipset_m_add(m, ip, 1, &meta);
    }
    struct IpBlockInfo *list = NULL;
    uint32_t n = 0;
    CHECK_EQ(ipset_m_snapshot(m, &list, &n), 0, "photo de 3000 IP");
    CHECK_EQ(n, 3000, "3000 lignes : aucune limite de buffer à deviner");
    int ok = 1;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t id = ((uint32_t)list[i].ip[1] << 16) | ((uint32_t)list[i].ip[2] << 8) | list[i].ip[3];
        if (list[i].meta.blocked_at_ms != 1000 + (id - 100000)) ok = 0;
        if (i > 0 && list[i - 1].meta.blocked_at_ms <= list[i].meta.blocked_at_ms) ok = 0;      /* strictement décroissant : dates toutes différentes */
    }
    CHECK(ok, "chaque ligne a la bonne date et l'ordre est strictement décroissant");
    ipset_m_snapshot_free(list);
    ipset_m_destroy(m);
}

struct SnapShared { IpSetM *m; atomic_int stop; atomic_int errors; };

static void *snap_writer(void *a) {
    struct SnapShared *sh = a;
    uint8_t ip[4];
    for (uint32_t i = 0; i < 4000 / STRESS_DIV; i++) {
        struct IpBlockMeta meta = { (uint8_t)(i & 0xFF), IPM_SRC_AUTO, 1000 + i, 0 };
        ip4(ip, 100000 + i);
        ipset_m_add(sh -> m, ip, 1, &meta);
        if (i % 3 == 2) { ip4(ip, 100000 + i - 2); ipset_m_remove(sh -> m, ip, 1); }
    }
    atomic_store(&sh -> stop, 1);
    return NULL;
}

static void t_snapshot_pendant_les_ecritures(void) {
    /* chaque photo doit être cohérente (pas de doublon, métadonnées exactes, ordre juste) même si on écrit en même temps */
    struct SnapShared sh;
    sh.m = new_m(64);
    atomic_init(&sh.stop, 0); atomic_init(&sh.errors, 0);
    pthread_t wr;
    pthread_create(&wr, NULL, snap_writer, &sh);
    int snapshots = 0;
    while (!atomic_load(&sh.stop)) {
        struct IpBlockInfo *list = NULL;
        uint32_t n = 0;
        if (ipset_m_snapshot(sh.m, &list, &n) != 0) { atomic_fetch_add(&sh.errors, 1); break; }
        for (uint32_t i = 0; i < n; i++) {
            uint32_t id = ((uint32_t)list[i].ip[1] << 16) | ((uint32_t)list[i].ip[2] << 8) | list[i].ip[3];
            if (list[i].meta.blocked_at_ms != 1000 + (id - 100000)) atomic_fetch_add(&sh.errors, 1);
            if (i > 0 && list[i - 1].meta.blocked_at_ms <= list[i].meta.blocked_at_ms) atomic_fetch_add(&sh.errors, 1);   /* trié ET sans doublon */
        }
        ipset_m_snapshot_free(list);
        snapshots++;
    }
    pthread_join(wr, NULL);
    CHECK_EQ(atomic_load(&sh.errors), 0, "toutes les photos prises pendant les écritures sont cohérentes");
    CHECK(snapshots > 0, "des photos ont bien été prises");
    ipset_m_destroy(sh.m);
}

/* ───────────── croissance et reconstruction ───────────── */

static void t_croissance(void) {
    IpSetM *m = new_m(64);
    int r = ipset_m_register(m);
    uint8_t ip[4];
    int refused = 0;
    for (uint32_t i = 0; i < 5000; i++) {
        ip4(ip, 100 + i);
        if (ipset_m_add(m, ip, 1, NULL) != 0) refused++;
        ipset_m_quiescent(m, r);
    }
    CHECK_EQ(refused, 0, "5000 IP ajoutées à partir de 64 : aucun refus, la table grandit seule");
    CHECK_EQ(ipset_m_count(m), 5000, "5000 IP");
    int ok = 1;
    for (uint32_t i = 0; i < 5000; i++) { ip4(ip, 100 + i); if (!ipset_m_contains(m, r, ip, 1)) ok = 0; }
    CHECK(ok, "toutes retrouvées sans verrou, après toutes les bascules");
    ip4(ip, 900000);
    CHECK_EQ(ipset_m_contains(m, r, ip, 1), 0, "une IP jamais ajoutée est absente");
    struct IpSetMStats st;
    ipset_m_stats(m, &st);
    CHECK(st.grows >= 5, "la capacité a doublé plusieurs fois");
    CHECK(st.capacity >= 5000, "capacité suffisante");
    CHECK_EQ(st.retired_pending + st.freed_tables, st.swaps, "chaque ancienne table est soit en attente, soit libérée");
    ipset_m_unregister(m, r);
    ipset_m_destroy(m);
}

static void t_fenetre_glissante(void) {
    /* comme un IPS : des IP arrivent, d'autres partent, 300 présentes en même temps, 100 000 IP différentes en tout */
    IpSetM *m = new_m(64);
    int r = ipset_m_register(m);
    uint8_t ip[4];
    int refused = 0;
    const uint32_t N = 100000, WIN = 300;
    for (uint32_t i = 0; i < N; i++) {
        ip4(ip, 10000 + i);
        if (ipset_m_add(m, ip, 1, NULL) != 0) refused++;
        if (i >= WIN) { ip4(ip, 10000 + i - WIN); if (ipset_m_remove(m, ip, 1) != 0) refused++; }
        ipset_m_quiescent(m, r);
    }
    CHECK_EQ(refused, 0, "100 000 IP différentes, 300 présentes à la fois : aucun refus");
    CHECK_EQ(ipset_m_count(m), WIN, "il reste 300 IP");
    int ok = 1;
    for (uint32_t i = N - WIN; i < N; i++) { ip4(ip, 10000 + i); if (!ipset_m_contains(m, r, ip, 1)) ok = 0; }
    CHECK(ok, "les 300 dernières sont toutes retrouvées");
    int ghost = 0;
    for (uint32_t i = 0; i < 3000; i++) { ip4(ip, 10000 + i); if (ipset_m_contains(m, r, ip, 1)) ghost++; }
    CHECK_EQ(ghost, 0, "aucune ancienne IP retirée n'est encore vue");
    struct IpSetMStats st;
    ipset_m_stats(m, &st);
    CHECK(st.swaps > 100, "des reconstructions ont eu lieu (les fiches retirées ne s'accumulent pas)");
    CHECK(st.retired_pending <= 2, "et les anciennes tables sont libérées au fur et à mesure");
    ipset_m_unregister(m, r);
    ipset_m_destroy(m);
}

/* ───────────── la libération des anciennes tables (le cœur du design) ───────────── */

static void add_many(IpSetM *m, uint32_t first, uint32_t n) {
    uint8_t ip[4];
    for (uint32_t i = 0; i < n; i++) { ip4(ip, first + i); ipset_m_add(m, ip, 1, NULL); }
}

static void t_liberation_apres_quiescence(void) {
    IpSetM *m = new_m(64);
    int r = ipset_m_register(m);
    struct IpSetMStats st;

    add_many(m, 1000, 200);                                   /* provoque des croissances, pendant que le lecteur « tient » son ancienne vue */
    ipset_m_stats(m, &st);
    CHECK(st.swaps >= 2, "plusieurs bascules ont eu lieu");
    CHECK_EQ(st.freed_tables, 0, "le lecteur n'a rien annoncé : AUCUNE ancienne table n'est libérée");
    CHECK_EQ(st.retired_pending, st.swaps, "toutes attendent");
    uint64_t swaps_avant = st.swaps;

    ipset_m_quiescent(m, r);                                  /* « je ne tiens rien » */
    add_many(m, 5000, 1);                                     /* le balayage paresseux se fait au coup d'écriture */
    ipset_m_stats(m, &st);
    CHECK_EQ(st.retired_pending, 0, "après l'annonce du lecteur, tout est libéré");
    CHECK_EQ(st.freed_tables, swaps_avant, "exactement les tables en attente");

    /* un lecteur qui a annoncé AVANT une bascule ne libère pas celle-ci */
    ipset_m_quiescent(m, r);
    add_many(m, 6000, 3000);                                  /* nouvelles croissances */
    ipset_m_stats(m, &st);
    CHECK(st.retired_pending >= 1, "annonce faite avant la bascule : la table de cette bascule attend");
    CHECK_EQ(ipset_m_reclaim(m), 0, "ipset_m_reclaim ne libère rien tant que le lecteur n'a pas annoncé");

    /* un lecteur qui dort ne bloque personne */
    ipset_m_offline(m, r);
    CHECK(ipset_m_reclaim(m) >= 1, "offline : les tables en attente sont libérées");
    ipset_m_stats(m, &st);
    CHECK_EQ(st.retired_pending, 0, "plus rien en attente");
    add_many(m, 20000, 3000);
    ipset_m_stats(m, &st);
    CHECK(st.retired_pending <= 1, "offline : les croissances libèrent derrière elles");

    ipset_m_online(m, r);                                     /* il revient : il annonce l'époque courante */
    ipset_m_quiescent(m, r);
    ipset_m_unregister(m, r);
    CHECK(ipset_m_reclaim(m) <= 1, "lecteur parti : plus personne n'attend");
    ipset_m_stats(m, &st);
    CHECK_EQ(st.retired_pending, 0, "tout est libéré");
    CHECK_EQ(st.readers, 0, "plus aucun lecteur inscrit");
    ipset_m_destroy(m);
}

static void t_destroy_avec_tables_en_attente(void) {
    IpSetM *m = new_m(64);
    ipset_m_register(m);                                      /* un lecteur qui n'annonce jamais */
    add_many(m, 1, 500);
    struct IpSetMStats st;
    ipset_m_stats(m, &st);
    CHECK(st.retired_pending >= 1, "des tables attendent");
    ipset_m_destroy(m);                                       /* le détecteur de fuites vérifie que tout est rendu */
}

static void t_trop_de_tables_en_attente(void) {
    /* un lecteur qui n'annonce jamais ne doit pas empiler les anciennes TABLES sans limite : au plus IPSET_M_MAX_RETIRED en attente.
     * (Pendant ce temps on ne peut plus reconstruire : les fiches retirées de la table courante, ~32 octets par retrait, s'accumulent
     *  jusqu'à la prochaine reconstruction. C'est le prix d'un lecteur bloqué.) */
    IpSetM *m = new_m(64);
    int r = ipset_m_register(m);
    uint8_t ip[4];
    for (uint32_t i = 0; i < 150000 / STRESS_DIV; i++) {      /* ajouts/retraits : une reconstruction toutes les 256 retraits... et on ne passe jamais ipset_m_quiescent */
        ip4(ip, 1 + (i % 1000));
        CHECK_EQ(ipset_m_add(m, ip, 1, NULL), 0, "l'ajout réussit même quand on ne peut plus reconstruire");
        ipset_m_remove(m, ip, 1);
        struct IpSetMStats st;
        if (i % 4096 == 0) { ipset_m_stats(m, &st); CHECK(st.retired_pending <= IPSET_M_MAX_RETIRED, "jamais plus de MAX_RETIRED en attente"); }
    }
    struct IpSetMStats st;
    ipset_m_stats(m, &st);
    CHECK(st.retired_pending <= IPSET_M_MAX_RETIRED, "la limite tient");
    ipset_m_quiescent(m, r);
    ip4(ip, 77777);
    CHECK_EQ(ipset_m_add(m, ip, 1, NULL), 0, "dès que le lecteur annonce, tout repart");
    ipset_m_destroy(m);
}

static void t_lecteurs_saturation(void) {
    IpSetM *m = new_m(64);
    int ids[IPSET_M_MAX_READERS];
    int ok = 1;
    for (int i = 0; i < IPSET_M_MAX_READERS; i++) { ids[i] = ipset_m_register(m); if (ids[i] < 0) ok = 0; }
    CHECK(ok, "32 lecteurs inscrits");
    CHECK_EQ(ipset_m_register(m), -1, "le 33e est refusé");
    ipset_m_unregister(m, ids[5]);
    int again = ipset_m_register(m);
    CHECK_EQ(again, ids[5], "un slot libéré est réutilisé");
    struct IpSetMStats st;
    ipset_m_stats(m, &st);
    CHECK_EQ(st.readers, IPSET_M_MAX_READERS, "32 inscrits");
    ipset_m_quiescent(m, -1); ipset_m_quiescent(m, 999); ipset_m_unregister(m, -1);   /* numéros invalides : sans effet */
    ipset_m_destroy(m);
}

/* ───────────── stress : des lecteurs sans verrou pendant que des écrivains font basculer la table ───────────── */

struct Shared { IpSetM *m; atomic_int stop; atomic_int errors; atomic_int unreg_reads; int n_perm; };

static void *reader(void *a) {
    struct Shared *sh = a;
    static _Atomic int next_period = 1;
    int period = 1 + (atomic_fetch_add(&next_period, 3) % 16);            /* chaque lecteur annonce à son rythme */
    int id = ipset_m_register(sh -> m);
    if (id < 0) { atomic_fetch_add(&sh -> errors, 1); return NULL; }
    uint8_t ip[4];
    uint32_t n = 0;
    while (!atomic_load(&sh -> stop)) {
        for (int i = 0; i < sh -> n_perm; i++) {
            ip4(ip, 1000 + (uint32_t)i);
            if (!ipset_m_contains(sh -> m, id, ip, 1)) atomic_fetch_add(&sh -> errors, 1);   /* JAMAIS de faux négatif, même pendant une bascule */
        }
        ip4(ip, 5000000 + (n % 1000));
        if (ipset_m_contains(sh -> m, id, ip, 1)) atomic_fetch_add(&sh -> errors, 1);        /* jamais ajoutée : jamais vue */
        if (++n % (uint32_t)period == 0) ipset_m_quiescent(sh -> m, id);
    }
    ipset_m_unregister(sh -> m, id);
    return NULL;
}

static void *python_like(void *a) {                                        /* thread non inscrite : voie sûre avec mutex */
    struct Shared *sh = a;
    uint8_t ip[4];
    while (!atomic_load(&sh -> stop)) {
        for (int i = 0; i < sh -> n_perm; i += 7) {
            ip4(ip, 1000 + (uint32_t)i);
            if (!ipset_m_contains(sh -> m, -1, ip, 1)) atomic_fetch_add(&sh -> errors, 1);
            atomic_fetch_add(&sh -> unreg_reads, 1);
        }
    }
    return NULL;
}

struct W { struct Shared *sh; uint32_t base; };

static void *writer(void *a) {
    struct W *w = a;
    uint8_t ip[4];
    uint32_t added[40];
    for (int round = 0; round < 800 / STRESS_DIV; round++) {
        uint32_t n_added = 0;
        for (uint32_t i = 0; i < 40; i++) {
            uint32_t id = w -> base + (uint32_t)(round % 11) * 53 + i;
            ip4(ip, id);
            if (ipset_m_add(w -> sh -> m, ip, 1, NULL) == 0) added[n_added++] = id;
        }
        for (uint32_t i = 0; i < n_added; i++) { ip4(ip, added[i]); ipset_m_remove(w -> sh -> m, ip, 1); }
    }
    return NULL;
}

static void t_stress_lecteurs_et_ecrivains(void) {
    struct Shared sh;
    sh.m = new_m(64);
    sh.n_perm = 200;                                          /* 200 permanentes : ça fait déjà grandir la table avant le début */
    atomic_init(&sh.stop, 0); atomic_init(&sh.errors, 0); atomic_init(&sh.unreg_reads, 0);
    uint8_t ip[4];
    for (int i = 0; i < sh.n_perm; i++) { ip4(ip, 1000 + (uint32_t)i); CHECK_EQ(ipset_m_add(sh.m, ip, 1, NULL), 0, "permanente ajoutée"); }

    pthread_t rd[4], py, wr[2];
    struct W w[2] = { { &sh, 100000 }, { &sh, 200000 } };
    for (int i = 0; i < 4; i++) pthread_create(&rd[i], NULL, reader, &sh);
    pthread_create(&py, NULL, python_like, &sh);
    for (int i = 0; i < 2; i++) pthread_create(&wr[i], NULL, writer, &w[i]);
    for (int i = 0; i < 2; i++) pthread_join(wr[i], NULL);
    atomic_store(&sh.stop, 1);
    for (int i = 0; i < 4; i++) pthread_join(rd[i], NULL);
    pthread_join(py, NULL);

    CHECK_EQ(atomic_load(&sh.errors), 0, "4 lecteurs + 1 thread Python pendant 2 écrivains : aucun faux négatif, aucune IP fantôme");
    CHECK(atomic_load(&sh.unreg_reads) > 0, "la thread Python a bien lu");
    CHECK_EQ(ipset_m_count(sh.m), 200, "il ne reste que les permanentes");
    struct IpSetMStats st;
    ipset_m_stats(sh.m, &st);
    CHECK(st.swaps > 10, "beaucoup de bascules ont eu lieu pendant que les lecteurs lisaient");
    ipset_m_reclaim(sh.m);
    ipset_m_stats(sh.m, &st);
    CHECK_EQ(st.retired_pending, 0, "tous les lecteurs sont partis : toutes les anciennes tables sont libérées");
    CHECK_EQ(st.readers, 0, "plus aucun lecteur inscrit");
    ipset_m_destroy(sh.m);
}

int main(int argc, char **argv) {
    tc_begin("test_ipset_m.c", argc, argv);
    RUN_LEAKS("bases : ajouter, lire, retirer, métadonnées",    t_basique);
    RUN_LEAKS("liste et expiration",                            t_liste_et_expiration);
    RUN_LEAKS("photo : liste vide, ordre, métadonnées",         t_snapshot_vide_et_trie);
    RUN_LEAKS("photo : 3000 IP d'un coup",                      t_snapshot_gros);
    RUN_LEAKS("photo : cohérente pendant les écritures",        t_snapshot_pendant_les_ecritures);
    RUN_LEAKS("croissance : 64 → 5000 IP sans refus",           t_croissance);
    RUN_LEAKS("fenêtre glissante : 100 000 IP différentes",     t_fenetre_glissante);
    RUN_LEAKS("libération : seulement après l'annonce des lecteurs", t_liberation_apres_quiescence);
    RUN_LEAKS("destroy avec des tables en attente",             t_destroy_avec_tables_en_attente);
    RUN_LEAKS("lecteur bloqué : au plus 32 tables en attente",  t_trop_de_tables_en_attente);
    RUN_LEAKS("32 lecteurs au plus",                            t_lecteurs_saturation);
    RUN_LEAKS("stress : 4 lecteurs + Python + 2 écrivains",     t_stress_lecteurs_et_ecrivains);
    return tc_end();
}
