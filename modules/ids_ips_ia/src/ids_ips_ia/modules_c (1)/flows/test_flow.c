/* test_flow.c : tests de flow.c (clé de flux, hachage, copies, fiche de flux, mise à jour)
 *
 * Compiler (depuis modules_c/) :
 *   gcc -std=gnu11 -g -O0 -Wall -Wextra -fsanitize=address,undefined \
 *       flows/test_flow.c flows/flow.c dict/dict.c -o build/test_flow
 * Ou simplement : ./run_tests.sh flow
 *
 * Convention de flow.c utilisée ici : le paramètre « v4 » vaut 1 pour IPv4 et 0 pour IPv6 (question « est-ce de l'IPv4 ? » : 1 = oui).
 *
 * Contrat testé :
 *   build_flow_key   : clé CANONIQUE. Les deux bouts sont rangés (min / max) pour que A→B et B→A
 *                      donnent la même clé ; deux flux DIFFÉRENTS ne doivent jamais donner la même clé ;
 *                      le champ key (type v4 / v6) est rempli.
 *   flow_key_compare : même contrat que strcmp : 0 si les deux clés sont égales, non nul sinon
 *                      (c'est ce que dict.c attend : « compare(...) == 0 » veut dire « trouvé »).
 *   flow_hash        : même clé → même hash ; toute la clé compte (les 16 octets d'une IPv6) ;
 *                      -1 réservé aux erreurs ; répartition correcte.
 *   *_dup / *_free   : copies indépendantes ; NULL accepté par les free.
 *   build_flow_entry : remplit FlowData depuis le PREMIER paquet : initiateur, receveur (IP et port
 *                      en entier), flags, compteurs (1 paquet ltr, 0 rtl).
 *   entry_update     : détermine le sens (ltr = vient de l'initiateur), compte paquets et flags.
 *
 * Les clés « k4t / k6t » ont leur champ type corrigé à la main : elles servent aux tests qui
 * ne portent PAS sur build_flow_key, pour ne pas mélanger les bugs.
 */
#include <stddef.h>
#include "../test_common.h"
#include "../test_packets.h"
#include "flow.h"

/* ───────────── outils ───────────── */

/* clé IPv4 construite par build_flow_key, mémoire pré-remplie de 0xAA pour repérer
   un champ que la fonction aurait oublié d'écrire */
static FlowKeyIpv4 k4(const uint8_t *a, uint16_t ap, const uint8_t *b, uint16_t bp, uint8_t proto) {
    FlowKeyIpv4 k;
    uint8_t p1[2], p2[2];
    memset(&k, 0xAA, sizeof k);
    pk_put16(p1, ap);
    pk_put16(p2, bp);
    build_flow_key(&k, (uint8_t *)a, (uint8_t *)b, p1, p2, proto, 1);
    return k;
}
static FlowKeyIpv6 k6(const uint8_t *a, uint16_t ap, const uint8_t *b, uint16_t bp, uint8_t proto) {
    FlowKeyIpv6 k;
    uint8_t p1[2], p2[2];
    memset(&k, 0xAA, sizeof k);
    pk_put16(p1, ap);
    pk_put16(p2, bp);
    build_flow_key(&k, (uint8_t *)a, (uint8_t *)b, p1, p2, proto, 0);
    return k;
}
static FlowKeyIpv4 k4t(const uint8_t *a, uint16_t ap, const uint8_t *b, uint16_t bp, uint8_t proto) {
    FlowKeyIpv4 k = k4(a, ap, b, bp, proto);
    k.key = FlowKeyIpv4Type;
    return k;
}
static FlowKeyIpv6 k6t(const uint8_t *a, uint16_t ap, const uint8_t *b, uint16_t bp, uint8_t proto) {
    FlowKeyIpv6 k = k6(a, ap, b, bp, proto);
    k.key = FlowKeyIpv6Type;
    return k;
}

/* ═══════════════════════════ build_flow_key ═══════════════════════════ */

static void t_key_arguments(void) {
    FlowKeyIpv4 k;
    uint8_t ip[4] = {1, 2, 3, 4}, p[2] = {0, 80};
    CHECK_EQ(build_flow_key(NULL, ip, ip, p, p, 6, 1), -1, "key == NULL → -1");
    CHECK_EQ(build_flow_key(&k, ip, ip, p, p, 6, 2), -1, "v4 == 2 → -1");
    CHECK_EQ(build_flow_key(&k, ip, ip, p, p, 6, -1), -1, "v4 == -1 → -1");
    CHECK_EQ(build_flow_key(&k, ip, ip, p, p, 6, 1), 0, "cas valide IPv4 → 0");
    FlowKeyIpv6 k6_;
    uint8_t ip6[16];
    pk_ip6(ip6, 1);
    CHECK_EQ(build_flow_key(&k6_, ip6, ip6, p, p, 6, 0), 0, "cas valide IPv6 → 0");
}

static void t_key_v4_champs(void) {
    /* 10.0.0.1:1234  ↔  10.0.0.2:80 */
    FlowKeyIpv4 k = k4(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    CHECK_MEM(k.ip_min, IP4(10, 0, 0, 1), 4, "ip_min = la plus petite IP");
    CHECK_MEM(k.ip_max, IP4(10, 0, 0, 2), 4, "ip_max = la plus grande IP");
    uint8_t p80[2], p1234[2];
    pk_put16(p80, 80);
    pk_put16(p1234, 1234);
    /* les deux ports doivent se retrouver dans la clé (dans quel ordre : c'est ton choix de conception) */
    int ordre1 = memcmp(k.port_min, p80, 2) == 0 && memcmp(k.port_max, p1234, 2) == 0;
    int ordre2 = memcmp(k.port_min, p1234, 2) == 0 && memcmp(k.port_max, p80, 2) == 0;
    CHECK(ordre1 || ordre2, "port_min et port_max contiennent les ports 80 et 1234");
    CHECK_EQ(k.proto, TCP, "proto == TCP");
    CHECK_EQ(k.key, FlowKeyIpv4Type, "le champ key vaut FlowKeyIpv4Type");
}

static void t_key_v4_symetrique(void) {
    FlowKeyIpv4 aller  = k4(IP4(10, 0, 0, 1), 51000, IP4(192, 168, 1, 7), 443, TCP);
    FlowKeyIpv4 retour = k4(IP4(192, 168, 1, 7), 443, IP4(10, 0, 0, 1), 51000, TCP);
    CHECK_MEM(&aller, &retour, sizeof aller, "A→B et B→A donnent exactement la même clé");
}

static void t_key_v4_ordre_octets(void) {
    /* l'ordre doit se faire sur l'adresse entière : 9.255.255.255 < 10.0.0.0 */
    FlowKeyIpv4 k = k4(IP4(10, 0, 0, 0), 5000, IP4(9, 255, 255, 255), 6000, UDP);
    CHECK_MEM(k.ip_min, IP4(9, 255, 255, 255), 4, "9.255.255.255 < 10.0.0.0");
    CHECK_MEM(k.ip_max, IP4(10, 0, 0, 0), 4, "ip_max = 10.0.0.0");
}

static void t_key_v4_flux_differents_clefs_differentes(void) {
    /* deux conversations DIFFÉRENTES entre les mêmes deux machines :
         flux 1 : 10.0.0.1 port 80  ↔ 10.0.0.2 port 443
         flux 2 : 10.0.0.1 port 443 ↔ 10.0.0.2 port 80
       (qui écoute sur quel port n'est pas pareil) : ce sont deux flux, donc deux clés */
    FlowKeyIpv4 f1 = k4(IP4(10, 0, 0, 1), 80,  IP4(10, 0, 0, 2), 443, TCP);
    FlowKeyIpv4 f2 = k4(IP4(10, 0, 0, 1), 443, IP4(10, 0, 0, 2), 80,  TCP);
    CHECK(memcmp(&f1, &f2, sizeof f1) != 0, "deux flux différents ne partagent pas la même clé");
}

static void t_key_v4_proto_et_ports(void) {
    FlowKeyIpv4 tcp = k4(IP4(1, 1, 1, 1), 1000, IP4(2, 2, 2, 2), 80, TCP);
    FlowKeyIpv4 udp = k4(IP4(1, 1, 1, 1), 1000, IP4(2, 2, 2, 2), 80, UDP);
    CHECK(memcmp(&tcp, &udp, sizeof tcp) != 0, "même quadruplet, TCP vs UDP : clés différentes");
    FlowKeyIpv4 p1 = k4(IP4(1, 1, 1, 1), 1000, IP4(2, 2, 2, 2), 80, TCP);
    FlowKeyIpv4 p2 = k4(IP4(1, 1, 1, 1), 1001, IP4(2, 2, 2, 2), 80, TCP);
    CHECK(memcmp(&p1, &p2, sizeof p1) != 0, "port source différent : clés différentes");
    FlowKeyIpv4 i1 = k4(IP4(1, 1, 1, 1), 1000, IP4(2, 2, 2, 2), 80, TCP);
    FlowKeyIpv4 i2 = k4(IP4(1, 1, 1, 1), 1000, IP4(2, 2, 2, 3), 80, TCP);
    CHECK(memcmp(&i1, &i2, sizeof i1) != 0, "IP destination différente : clés différentes");
}

static void t_key_v4_bouts_identiques(void) {
    /* une machine qui se parle à elle-même, même port : ne doit pas planter et reste cohérent */
    FlowKeyIpv4 k = k4(IP4(127, 0, 0, 1), 5353, IP4(127, 0, 0, 1), 5353, UDP);
    CHECK_MEM(k.ip_min, IP4(127, 0, 0, 1), 4, "ip_min == 127.0.0.1");
    CHECK_MEM(k.ip_max, IP4(127, 0, 0, 1), 4, "ip_max == 127.0.0.1");
    CHECK_MEM(k.port_min, k.port_max, 2, "port_min == port_max");
}

static void t_key_v6_champs(void) {
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    FlowKeyIpv6 k = k6(a, 1234, b, 80, TCP);
    CHECK_MEM(k.ip_min, a, 16, "ip_min = ::1 (16 octets)");
    CHECK_MEM(k.ip_max, b, 16, "ip_max = ::2 (16 octets)");
    CHECK_EQ(k.proto, TCP, "proto == TCP");
    CHECK_EQ(k.key, FlowKeyIpv6Type, "le champ key vaut FlowKeyIpv6Type");
}

static void t_key_v6_symetrique_et_octets_du_milieu(void) {
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 1);
    b[8] = 9;                                   /* b ne diffère de a QUE par l'octet 8 */
    FlowKeyIpv6 aller  = k6(a, 4000, b, 22, TCP);
    FlowKeyIpv6 retour = k6(b, 22, a, 4000, TCP);
    CHECK_MEM(&aller, &retour, sizeof aller, "A→B et B→A : même clé (IPv6)");
    CHECK_MEM(aller.ip_min, a, 16, "ip_min = celle dont l'octet 8 est le plus petit");
    CHECK_MEM(aller.ip_max, b, 16, "ip_max = celle dont l'octet 8 est le plus grand");
}

/* ═══════════════════════════ flow_key_compare ═══════════════════════════ */

static void t_cmp_egales(void) {
    FlowKeyIpv4 a = k4t(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 b = k4t(IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 1234, TCP);
    CHECK_EQ(flow_key_compare(&a, &a), 0, "une clé comparée à elle-même → 0");
    CHECK_EQ(flow_key_compare(&a, &b), 0, "deux clés égales (sens inverse) → 0");
}

static void t_cmp_chaque_champ(void) {
    FlowKeyIpv4 base = k4t(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 m;
    m = base; m.ip_min[3] ^= 1;   CHECK(flow_key_compare(&base, &m) != 0, "ip_min différente → non nul");
    m = base; m.ip_max[3] ^= 1;   CHECK(flow_key_compare(&base, &m) != 0, "ip_max différente → non nul");
    m = base; m.port_min[1] ^= 1; CHECK(flow_key_compare(&base, &m) != 0, "port_min différent → non nul");
    m = base; m.port_max[1] ^= 1; CHECK(flow_key_compare(&base, &m) != 0, "port_max différent → non nul");
    m = base; m.proto = UDP;      CHECK(flow_key_compare(&base, &m) != 0, "proto différent → non nul");
    m = base; m.ip_min[3] ^= 1;   CHECK(flow_key_compare(&m, &base) != 0, "…et dans l'autre sens aussi");
}

static void t_cmp_v4_contre_v6(void) {
    uint8_t a6[16];
    pk_ip6(a6, 1);
    FlowKeyIpv4 a = k4t(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv6 b = k6t(a6, 1234, a6, 80, TCP);
    CHECK(flow_key_compare(&a, &b) != 0, "clé v4 contre clé v6 → non nul");
    CHECK(flow_key_compare(&b, &a) != 0, "clé v6 contre clé v4 → non nul");
}

static void t_cmp_v6(void) {
    uint8_t x[16], y[16];
    pk_ip6(x, 1);
    pk_ip6(y, 2);
    FlowKeyIpv6 a = k6t(x, 1234, y, 80, TCP);
    FlowKeyIpv6 b = k6t(y, 80, x, 1234, TCP);
    CHECK_EQ(flow_key_compare(&a, &b), 0, "v6 égales → 0");
    FlowKeyIpv6 m = a;
    m.ip_max[15] ^= 1;
    CHECK(flow_key_compare(&a, &m) != 0, "v6 : dernier octet de ip_max différent → non nul");
    m = a;
    m.ip_min[15] ^= 1;
    CHECK(flow_key_compare(&a, &m) != 0, "v6 : dernier octet de ip_min différent → non nul");
    m = a;
    m.ip_min[8] ^= 1;
    CHECK(flow_key_compare(&a, &m) != 0, "v6 : octet 8 de ip_min différent → non nul");
}

/* ═══════════════════════════ flow_hash ═══════════════════════════ */

static void t_hash_arguments(void) {
    CHECK_EQ(flow_hash(NULL), -1, "flow_hash(NULL) → -1");
    FlowKeyType mauvais = (FlowKeyType)99;
    CHECK_EQ(flow_hash(&mauvais), -1, "type de clé invalide → -1");
}

static void t_hash_deterministe(void) {
    FlowKeyIpv4 a = k4t(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 b = k4t(IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 1234, TCP);
    CHECK_EQ(flow_hash(&a), flow_hash(&a), "même clé, deux appels → même hash");
    CHECK_EQ(flow_hash(&a), flow_hash(&b), "sens inverse → même hash");
    CHECK(flow_hash(&a) != -1, "un hash valide n'est pas -1 (réservé aux erreurs)");
}

static int cmp_int(const void *x, const void *y) {
    int a = *(const int *)x, b = *(const int *)y;
    return (a > b) - (a < b);
}

static void t_hash_repartition_v4(void) {
    enum { N = 4096, BUCKETS = 1024 };
    static int hs[N];
    static int seaux[BUCKETS];
    for (int i = 0; i < N; i++) {
        FlowKeyIpv4 k = k4t(IP4(10, 0, (uint8_t)(i >> 8), (uint8_t)(i & 255)), (uint16_t)(40000 + i),
                            IP4(192, 168, 0, 1), 443, TCP);
        hs[i] = flow_hash(&k);
        seaux[(uint32_t)hs[i] % BUCKETS]++;
    }
    int max = 0;
    for (int i = 0; i < BUCKETS; i++) if (seaux[i] > max) max = seaux[i];
    qsort(hs, N, sizeof hs[0], cmp_int);
    int distincts = 1;
    for (int i = 1; i < N; i++) if (hs[i] != hs[i - 1]) distincts++;
    CHECK(distincts >= N * 95 / 100, "au moins 95 % de hash distincts sur 4096 clés");
    CHECK(max <= 20, "aucun seau (sur 1024) ne reçoit plus de 20 clés (moyenne : 4)");
    printf("      · info : %d hash distincts sur %d, seau le plus chargé : %d\n", distincts, N, max);
}

static void t_hash_v6_utilise_tous_les_octets(void) {
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    FlowKeyIpv6 base = k6t(a, 1234, b, 80, TCP);
    int h0 = flow_hash(&base), identiques = 0;
    for (int i = 0; i < 16; i++) {
        FlowKeyIpv6 m = base;
        m.ip_max[i] ^= 0x40;
        if (flow_hash(&m) == h0) identiques++;
    }
    CHECK_EQ(identiques, 0, "changer UN octet quelconque de l'IPv6 (0..15) change le hash : octets ignorés");
}

static void t_hash_v6_deterministe(void) {
    uint8_t x[16], y[16];
    pk_ip6(x, 1);
    pk_ip6(y, 2);
    FlowKeyIpv6 a = k6t(x, 1234, y, 80, TCP);
    FlowKeyIpv6 b = k6t(y, 80, x, 1234, TCP);
    CHECK_EQ(flow_hash(&a), flow_hash(&b), "v6 : sens inverse → même hash");
}

/* ═══════════════════════════ dup / free ═══════════════════════════ */

static void t_key_dup_v4(void) {
    FlowKeyIpv4 k = k4t(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 *c = (FlowKeyIpv4 *)flow_key_dup(&k);
    CHECK(c != NULL, "dup != NULL");
    if (!c) return;
    CHECK(c != &k, "la copie est un autre objet");
    CHECK_MEM(c, &k, sizeof k, "copie identique à l'original");
    k.proto = 99;
    CHECK_EQ(c->proto, TCP, "modifier l'original ne change pas la copie");
    flow_key_free(c);
}

static void t_key_dup_v6(void) {
    uint8_t x[16], y[16];
    pk_ip6(x, 1);
    pk_ip6(y, 2);
    FlowKeyIpv6 k = k6t(x, 1234, y, 80, UDP);
    FlowKeyIpv6 *c = (FlowKeyIpv6 *)flow_key_dup(&k);
    CHECK(c != NULL, "dup v6 != NULL");
    if (!c) return;
    CHECK_MEM(c, &k, sizeof k, "copie v6 complète (les 44 octets)");
    flow_key_free(c);
}

static void t_key_dup_invalide(void) {
    CHECK(flow_key_dup(NULL) == NULL, "flow_key_dup(NULL) → NULL");
    FlowKeyType mauvais = (FlowKeyType)99;
    CHECK(flow_key_dup(&mauvais) == NULL, "type invalide → NULL");
}

static void t_free_null(void) {
    flow_key_free(NULL);
    flow_value_free(NULL);
    CHECK(1, "flow_key_free(NULL) et flow_value_free(NULL) ne plantent pas");
}

static void t_value_dup(void) {
    CHECK(flow_value_dup(NULL) == NULL, "flow_value_dup(NULL) → NULL");
    FlowKeyType kk = FlowKeyIpv4Type;
    FlowData dd;
    memset(&dd, 0, sizeof dd);
    FlowEntry src;
    memset(&src, 0, sizeof src);
    src.key = &kk;
    src.data = &dd;
    src.dcl_pos = 7;
    FlowEntry *c = (FlowEntry *)flow_value_dup(&src);
    CHECK(c != NULL, "dup != NULL");
    if (!c) return;
    CHECK(c != &src, "la copie est un autre objet");
    CHECK_PTR(c->key, &kk, "copie : même pointeur key (copie superficielle)");
    CHECK_PTR(c->data, &dd, "copie : même pointeur data (copie superficielle)");
    CHECK_EQ(c->dcl_pos, 7, "copie : dcl_pos recopié");
    flow_value_free(c);
}

/* ═══════════════════════════ create_ft_dict ═══════════════════════════ */

static void t_ftdict_creation(void) {
    CHECK(create_ft_dict(0) == NULL, "create_ft_dict(0) → NULL");
    Dict *d = create_ft_dict(16);
    CHECK(d != NULL, "create_ft_dict(16) != NULL");
    if (!d) return;
    CHECK(d->hash == flow_hash, "hash == flow_hash");
    CHECK(d->compare == flow_key_compare, "compare == flow_key_compare");
    CHECK(d->key_dup == flow_key_dup && d->key_free == flow_key_free, "key_dup / key_free branchés");
    dict_clear(d);
}

static void t_ftdict_aller_retour(void) {
    Dict *d = create_ft_dict(16);
    FlowEntry e;
    memset(&e, 0, sizeof e);
    e.dcl_pos = 42;
    FlowKeyIpv4 aller  = k4t(IP4(10, 0, 0, 1), 1234, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 retour = k4t(IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 1234, TCP);
    CHECK_EQ(dict_setitem(d, &aller, &e), 0, "dict_setitem → 0");
    FlowEntry *g = (FlowEntry *)dict_getitem(d, &retour);
    CHECK(g != NULL, "on retrouve le flux avec la clé du sens inverse");
    if (g) CHECK_EQ(g->dcl_pos, 42, "c'est bien la bonne fiche");
    dict_clear(d);
}

static void t_ftdict_plusieurs_flux(void) {
    Dict *d = create_ft_dict(16);
    FlowEntry e1, e2;
    memset(&e1, 0, sizeof e1);
    memset(&e2, 0, sizeof e2);
    e1.dcl_pos = 1;
    e2.dcl_pos = 2;
    FlowKeyIpv4 k1 = k4t(IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 k2 = k4t(IP4(10, 0, 0, 3), 2000, IP4(10, 0, 0, 4), 443, TCP);
    FlowKeyIpv4 k3 = k4t(IP4(10, 0, 0, 5), 3000, IP4(10, 0, 0, 6), 22, TCP);
    dict_setitem(d, &k1, &e1);
    dict_setitem(d, &k2, &e2);
    CHECK_EQ(d->nbr_elements, 2, "2 éléments");
    FlowEntry *g1 = (FlowEntry *)dict_getitem(d, &k1);
    FlowEntry *g2 = (FlowEntry *)dict_getitem(d, &k2);
    CHECK(g1 != NULL && g1->dcl_pos == 1, "k1 → fiche 1");
    CHECK(g2 != NULL && g2->dcl_pos == 2, "k2 → fiche 2");
    CHECK(dict_getitem(d, &k3) == NULL, "une clé jamais ajoutée → NULL");
    dict_clear(d);
}

static void t_ftdict_remplacement(void) {
    Dict *d = create_ft_dict(16);
    FlowEntry e1, e2;
    memset(&e1, 0, sizeof e1);
    memset(&e2, 0, sizeof e2);
    e1.dcl_pos = 1;
    e2.dcl_pos = 2;
    FlowKeyIpv4 k = k4t(IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, TCP);
    dict_setitem(d, &k, &e1);
    dict_setitem(d, &k, &e2);
    CHECK_EQ(d->nbr_elements, 1, "même clé deux fois : toujours 1 élément");
    FlowEntry *g = (FlowEntry *)dict_getitem(d, &k);
    CHECK(g != NULL && g->dcl_pos == 2, "la valeur est la dernière");
    dict_clear(d);
}

static void t_ftdict_suppression(void) {
    Dict *d = create_ft_dict(16);
    FlowEntry e;
    memset(&e, 0, sizeof e);
    FlowKeyIpv4 k = k4t(IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, TCP);
    FlowKeyIpv4 kr = k4t(IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 1000, TCP);
    dict_setitem(d, &k, &e);
    CHECK_EQ(dict_delitem(d, &kr), 0, "dict_delitem avec la clé du sens inverse → 0");
    CHECK(dict_getitem(d, &k) == NULL, "le flux a disparu");
    CHECK_EQ(d->nbr_elements, 0, "0 élément");
    dict_clear(d);
}

static void t_ftdict_beaucoup(void) {
    /* 500 flux : tous retrouvables, ça force un ou deux rehash du dict */
    enum { N = 500 };
    static FlowEntry fiches[N];
    Dict *d = create_ft_dict(8);
    int manquants = 0, mauvaise_fiche = 0;
    for (int i = 0; i < N; i++) {
        FlowKeyIpv4 k = k4t(IP4(10, 1, (uint8_t)(i >> 8), (uint8_t)(i & 255)), (uint16_t)(2000 + i), IP4(10, 2, 0, 1), 80, TCP);
        fiches[i].dcl_pos = (uint32_t)i;
        dict_setitem(d, &k, &fiches[i]);
    }
    CHECK_EQ(d->nbr_elements, N, "500 éléments");
    for (int i = 0; i < N; i++) {
        FlowKeyIpv4 k = k4t(IP4(10, 2, 0, 1), 80, IP4(10, 1, (uint8_t)(i >> 8), (uint8_t)(i & 255)), (uint16_t)(2000 + i), TCP);
        FlowEntry *g = (FlowEntry *)dict_getitem(d, &k);
        if (!g) manquants++;
        else if (g->dcl_pos != (uint32_t)i) mauvaise_fiche++;
    }
    CHECK_EQ(manquants, 0, "flux introuvables");
    CHECK_EQ(mauvaise_fiche, 0, "flux retrouvés avec la mauvaise fiche");
    dict_clear(d);
}

/* ═══════════════════════════ build_flow_entry ═══════════════════════════ */

#define IPV4_SRC IP4(10, 0, 0, 1)
#define IPV4_DST IP4(10, 0, 0, 2)

static void t_bfe_arguments(void) {
    FlowEntry e;
    memset(&e, 0, sizeof e);
    ParserResult pr = pk_tcp4(IPV4_SRC, 51000, IPV4_DST, 443, SYN);
    FlowKeyIpv4 k = k4t(IPV4_SRC, 51000, IPV4_DST, 443, TCP);
    CHECK_EQ(build_flow_entry(NULL, &pr, (void *)&k, 1, 0), -1, "entry == NULL → -1");
    CHECK_EQ(build_flow_entry(&e, NULL, (void *)&k, 1, 0), -1, "pr == NULL → -1");
    ParserResult bad = pr;
    bad.code = (uint8_t)TOO_LITTLE;
    CHECK_EQ(build_flow_entry(&e, &bad, (void *)&k, 1, 0), -1, "pr.code != SUCCES → -1");
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 2, 0), -1, "v4 == 2 → -1");
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 0, 0), -1, "v4 dit IPv6 mais le paquet est IPv4 → -1");
    uint8_t a6[16];
    pk_ip6(a6, 1);
    ParserResult p6 = pk_tcp6(a6, 1, a6, 2, SYN);
    CHECK_EQ(build_flow_entry(&e, &p6, (void *)&k, 1, 0), -1, "v4 dit IPv4 mais le paquet est IPv6 → -1");
    CHECK(e.data == NULL, "aucune allocation quand l'appel est refusé");
}

static void t_bfe_tcp_v4(void) {
    FlowEntry e;
    memset(&e, 0, sizeof e);
    ParserResult pr = pk_tcp4(IPV4_SRC, 51000, IPV4_DST, 443, SYN);
    FlowKeyIpv4 k = k4t(IPV4_SRC, 51000, IPV4_DST, 443, TCP);
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 1, 0), 0, "build_flow_entry → 0");
    FlowData *d = e.data;
    CHECK(d != NULL, "data alloué");
    if (!d) return;
    CHECK_PTR(e.key, &k, "entry->key = la clé passée");
    CHECK_EQ(d->v4, 1, "d->v4 == 1 (convention : 1 = IPv4)");
    CHECK_MEM(d->header.ipv4_headers.initiator_ip, IPV4_SRC, 4, "initiateur : IP source");
    CHECK_EQ(sizeof(d->header.ipv4_headers.receiver_ip), L_IPV4, "receiver_ip peut contenir une IPv4 (4 octets)");
    CHECK_MEM(d->header.ipv4_headers.receiver_ip, IPV4_DST, 4, "receveur : IP destination (4 octets)");
    uint8_t p51000[2], p443[2];
    pk_put16(p51000, 51000);
    pk_put16(p443, 443);
    CHECK_MEM(d->header.ipv4_headers.initiator_port, p51000, 2, "initiateur : port source 51000");
    CHECK_MEM(d->header.ipv4_headers.receiver_port, p443, 2, "receveur : port destination 443");
    CHECK_EQ(d->proto, TCP, "proto == TCP");
    CHECK_EQ(d->n_pkt_ltr, 1, "1 paquet ltr");
    CHECK_EQ(d->n_pkt_rtl, 0, "0 paquet rtl");
    CHECK_EQ(d->octets_data_ltr, pr.len, "octets_data_ltr == len du premier paquet");
    CHECK_EQ(d->octets_data_rtl, 0, "octets_data_rtl == 0");
    CHECK_EQ(d->verdict, UNKNOW, "verdict == UNKNOW");
    CHECK_EQ(d->flag_count.syn, 1, "syn == 1");
    CHECK_EQ(d->flag_count.ack + d->flag_count.fin + d->flag_count.rst + d->flag_count.psh +
             d->flag_count.urg + d->flag_count.ece + d->flag_count.cwr, 0, "tous les autres flags à 0");
    free(e.data);
}

static void t_bfe_flags_un_par_un(void) {
    struct { uint8_t masque; const char *nom; } flags[8] = {
        {RST, "rst"}, {SYN, "syn"}, {ACK, "ack"}, {FIN, "fin"}, {URG, "urg"}, {CWR, "cwr"}, {ECE, "ece"}, {PSH, "psh"}};
    for (int i = 0; i < 8; i++) {
        FlowEntry e;
        memset(&e, 0, sizeof e);
        ParserResult pr = pk_tcp4(IPV4_SRC, 1, IPV4_DST, 2, flags[i].masque);
        FlowKeyIpv4 k = k4t(IPV4_SRC, 1, IPV4_DST, 2, TCP);
        if (build_flow_entry(&e, &pr, (void *)&k, 1, 0) != 0) { CHECK(0, "build_flow_entry a échoué"); return; }
        struct _FlagSeens f = e.data->flag_count;
        uint32_t compteurs[8] = {f.rst, f.syn, f.ack, f.fin, f.urg, f.cwr, f.ece, f.psh};
        for (int j = 0; j < 8; j++) {
            char msg[80];
            snprintf(msg, sizeof msg, "flag %s seul : compteur %s == %d", flags[i].nom, flags[j].nom, i == j);
            CHECK_EQ(compteurs[j], i == j ? 1 : 0, msg);
        }
        free(e.data);
    }
}

static void t_bfe_udp_v4(void) {
    FlowEntry e;
    memset(&e, 0, sizeof e);
    ParserResult pr = pk_udp4(IPV4_SRC, 5353, IPV4_DST, 53);
    FlowKeyIpv4 k = k4t(IPV4_SRC, 5353, IPV4_DST, 53, UDP);
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 1, 0), 0, "→ 0");
    if (!e.data) return;
    uint8_t p5353[2], p53[2];
    pk_put16(p5353, 5353);
    pk_put16(p53, 53);
    CHECK_MEM(e.data->header.ipv4_headers.initiator_port, p5353, 2, "port source 5353");
    CHECK_MEM(e.data->header.ipv4_headers.receiver_port, p53, 2, "port destination 53");
    CHECK_EQ(e.data->proto, UDP, "proto == UDP");
    CHECK_EQ(e.data->flag_count.syn + e.data->flag_count.ack + e.data->flag_count.rst, 0, "pas de flags en UDP");
    free(e.data);
}

static void t_bfe_icmp_v4(void) {
    FlowEntry e;
    memset(&e, 0, sizeof e);
    ParserResult pr = pk_icmp4(IPV4_SRC, IPV4_DST, 8, 0);
    FlowKeyIpv4 k = k4t(IPV4_SRC, 0, IPV4_DST, 0, ICMP);
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 1, 0), 0, "→ 0");
    if (!e.data) return;
    uint8_t zero[2] = {0, 0};
    CHECK_EQ(e.data->proto, ICMP, "proto == ICMP");
    CHECK_MEM(e.data->header.ipv4_headers.initiator_port, zero, 2, "ICMP : port initiateur à 0");
    CHECK_MEM(e.data->header.ipv4_headers.receiver_port, zero, 2, "ICMP : port receveur à 0");
    CHECK_MEM(e.data->header.ipv4_headers.initiator_ip, IPV4_SRC, 4, "initiateur : IP source");
    free(e.data);
}

static void t_bfe_tcp_v6(void) {
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    FlowEntry e;
    memset(&e, 0, sizeof e);
    ParserResult pr = pk_tcp6(a, 40000, b, 22, SYN);
    FlowKeyIpv6 k = k6t(a, 40000, b, 22, TCP);
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 0, 0), 0, "build_flow_entry v6 → 0");
    FlowData *d = e.data;
    if (!d) return;
    CHECK_EQ(d->v4, 0, "d->v4 == 0 (convention : 0 = IPv6)");
    CHECK_MEM(d->header.ipv6_headers.initiator_ip, a, 16, "initiateur : IPv6 source (16 octets)");
    CHECK_MEM(d->header.ipv6_headers.receiver_ip, b, 16, "receveur : IPv6 destination (16 octets)");
    uint8_t p40000[2], p22[2];
    pk_put16(p40000, 40000);
    pk_put16(p22, 22);
    CHECK_MEM(d->header.ipv6_headers.initiator_port, p40000, 2, "port source");
    CHECK_MEM(d->header.ipv6_headers.receiver_port, p22, 2, "port destination");
    CHECK_EQ(d->proto, TCP, "proto == TCP");
    CHECK_EQ(d->flag_count.syn, 1, "syn == 1");
    free(e.data);
}

static void t_bfe_udp_v6(void) {
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    FlowEntry e;
    memset(&e, 0, sizeof e);
    ParserResult pr = pk_udp6(a, 5000, b, 53);
    FlowKeyIpv6 k = k6t(a, 5000, b, 53, UDP);
    CHECK_EQ(build_flow_entry(&e, &pr, (void *)&k, 0, 0), 0, "→ 0");
    if (!e.data) return;
    CHECK_EQ(e.data->proto, UDP, "proto == UDP");
    uint8_t p53[2];
    pk_put16(p53, 53);
    CHECK_MEM(e.data->header.ipv6_headers.receiver_port, p53, 2, "port destination 53");
    free(e.data);
}

/* ═══════════════════════════ entry_update ═══════════════════════════ */

/* fabrique une fiche à partir d'un premier paquet ; la clé est fournie par l'appelant */
static int fiche(FlowEntry *e, const ParserResult *pr, void *key, int v4) {
    memset(e, 0, sizeof *e);
    return build_flow_entry(e, (ParserResult *)pr, key, v4, 0);
}

static void t_upd_arguments(void) {
    FlowEntry e;
    ParserResult pr = pk_tcp4(IPV4_SRC, 51000, IPV4_DST, 443, SYN);
    FlowKeyIpv4 k = k4t(IPV4_SRC, 51000, IPV4_DST, 443, TCP);
    fiche(&e, &pr, (void *)&k, 1);
    CHECK_EQ(entry_update(NULL, &pr, 0), -1, "entry NULL → -1");
    CHECK_EQ(entry_update(&e, NULL, 0), -1, "pr NULL → -1");
    ParserResult bad = pr;
    bad.code = (uint8_t)NOT_HANDLE;
    CHECK_EQ(entry_update(&e, &bad, 0), -1, "pr.code != SUCCES → -1");
    CHECK_EQ(e.data->n_pkt_ltr, 1, "les refus ne changent pas les compteurs");
    FlowEntry sans_data = e;
    sans_data.data = NULL;
    CHECK_EQ(entry_update(&sans_data, &pr, 0), -1, "entry->data NULL → -1");
    FlowEntry sans_cle = e;
    sans_cle.key = NULL;
    CHECK_EQ(entry_update(&sans_cle, &pr, 0), -1, "entry->key NULL → -1");
    free(e.data);
}

static void t_upd_sens_tcp_v4(void) {
    FlowEntry e;
    FlowKeyIpv4 k = k4t(IPV4_SRC, 51000, IPV4_DST, 443, TCP);
    ParserResult syn    = pk_tcp4(IPV4_SRC, 51000, IPV4_DST, 443, SYN);
    ParserResult synack = pk_tcp4(IPV4_DST, 443, IPV4_SRC, 51000, SYN | ACK);
    ParserResult ack    = pk_tcp4(IPV4_SRC, 51000, IPV4_DST, 443, ACK);
    fiche(&e, &syn, (void *)&k, 1);
    FlowData *d = e.data;
    CHECK_EQ(entry_update(&e, &synack, 0), 0, "SYN-ACK (retour) → 0");
    CHECK_EQ(d->n_pkt_ltr, 1, "après SYN-ACK : ltr == 1");
    CHECK_EQ(d->n_pkt_rtl, 1, "après SYN-ACK : rtl == 1");
    CHECK_EQ(d->flag_count.syn, 2, "syn == 2 (SYN + SYN-ACK)");
    CHECK_EQ(d->flag_count.ack, 1, "ack == 1");
    CHECK_EQ(entry_update(&e, &ack, 0), 0, "ACK (aller) → 0");
    CHECK_EQ(d->n_pkt_ltr, 2, "après ACK : ltr == 2");
    CHECK_EQ(d->n_pkt_rtl, 1, "après ACK : rtl == 1");
    CHECK_EQ(d->flag_count.ack, 2, "ack == 2");
    for (int i = 0; i < 3; i++) entry_update(&e, &synack, 0);
    CHECK_EQ(d->n_pkt_rtl, 4, "3 retours de plus : rtl == 4");
    CHECK_EQ(d->n_pkt_ltr + d->n_pkt_rtl, 6, "6 paquets au total");
    free(e.data);
}

static void t_upd_tous_les_flags(void) {
    FlowEntry e;
    FlowKeyIpv4 k = k4t(IPV4_SRC, 1, IPV4_DST, 2, TCP);
    ParserResult p0   = pk_tcp4(IPV4_SRC, 1, IPV4_DST, 2, SYN);
    ParserResult tous = pk_tcp4(IPV4_DST, 2, IPV4_SRC, 1, 0xFF);
    fiche(&e, &p0, (void *)&k, 1);
    entry_update(&e, &tous, 0);
    struct _FlagSeens f = e.data->flag_count;
    CHECK_EQ(f.syn, 2, "syn == 2");
    CHECK_EQ(f.ack, 1, "ack == 1");
    CHECK_EQ(f.fin, 1, "fin == 1");
    CHECK_EQ(f.rst, 1, "rst == 1");
    CHECK_EQ(f.psh, 1, "psh == 1");
    CHECK_EQ(f.urg, 1, "urg == 1");
    CHECK_EQ(f.ece, 1, "ece == 1");
    CHECK_EQ(f.cwr, 1, "cwr == 1");
    free(e.data);
}

static void t_upd_ne_change_pas_l_initiateur(void) {
    FlowEntry e;
    FlowKeyIpv4 k = k4t(IPV4_SRC, 51000, IPV4_DST, 443, TCP);
    ParserResult syn  = pk_tcp4(IPV4_SRC, 51000, IPV4_DST, 443, SYN);
    ParserResult rep  = pk_tcp4(IPV4_DST, 443, IPV4_SRC, 51000, ACK);
    fiche(&e, &syn, (void *)&k, 1);
    FlowData *data_avant = e.data;
    void *key_avant = e.key;
    entry_update(&e, &rep, 0);
    CHECK_MEM(e.data->header.ipv4_headers.initiator_ip, IPV4_SRC, 4, "l'initiateur reste celui du premier paquet");
    CHECK_PTR(e.data, data_avant, "entry->data inchangé (même pointeur)");
    CHECK_PTR(e.key, key_avant, "entry->key inchangé (même pointeur)");
    free(e.data);
}

static void t_upd_udp_v4(void) {
    FlowEntry e;
    FlowKeyIpv4 k = k4t(IPV4_SRC, 5353, IPV4_DST, 53, UDP);
    ParserResult q = pk_udp4(IPV4_SRC, 5353, IPV4_DST, 53);
    ParserResult r = pk_udp4(IPV4_DST, 53, IPV4_SRC, 5353);
    fiche(&e, &q, (void *)&k, 1);
    CHECK_EQ(entry_update(&e, &r, 0), 0, "réponse UDP → 0");
    CHECK_EQ(e.data->n_pkt_ltr, 1, "ltr == 1");
    CHECK_EQ(e.data->n_pkt_rtl, 1, "rtl == 1");
    CHECK_EQ(e.data->flag_count.syn + e.data->flag_count.ack + e.data->flag_count.fin + e.data->flag_count.rst, 0,
             "UDP : aucun flag compté");
    free(e.data);
}

static void t_upd_icmp_v4(void) {
    FlowEntry e;
    FlowKeyIpv4 k = k4t(IPV4_SRC, 0, IPV4_DST, 0, ICMP);
    ParserResult req = pk_icmp4(IPV4_SRC, IPV4_DST, 8, 0);
    ParserResult rep = pk_icmp4(IPV4_DST, IPV4_SRC, 0, 0);
    fiche(&e, &req, (void *)&k, 1);
    entry_update(&e, &req, 0);
    CHECK_EQ(e.data->n_pkt_ltr, 2, "2e requête : ltr == 2");
    entry_update(&e, &rep, 0);
    CHECK_EQ(e.data->n_pkt_rtl, 1, "réponse (IP source = l'autre bout) : rtl == 1");
    CHECK_EQ(e.data->n_pkt_ltr, 2, "ltr reste 2");
    free(e.data);
}

static void t_upd_v6(void) {
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    FlowEntry e;
    FlowKeyIpv6 k = k6t(a, 40000, b, 22, TCP);
    ParserResult syn    = pk_tcp6(a, 40000, b, 22, SYN);
    ParserResult synack = pk_tcp6(b, 22, a, 40000, SYN | ACK);
    ParserResult ack    = pk_tcp6(a, 40000, b, 22, ACK);
    fiche(&e, &syn, (void *)&k, 0);
    entry_update(&e, &synack, 0);
    entry_update(&e, &ack, 0);
    CHECK_EQ(e.data->n_pkt_ltr, 2, "v6 : ltr == 2");
    CHECK_EQ(e.data->n_pkt_rtl, 1, "v6 : rtl == 1");
    CHECK_EQ(e.data->flag_count.syn, 2, "v6 : syn == 2");
    CHECK_EQ(e.data->flag_count.ack, 2, "v6 : ack == 2");
    free(e.data);
}

static void t_upd_v6_octets_du_milieu(void) {
    /* deux IPv6 qui ne diffèrent que par l'octet 8 : le sens doit quand même être détecté */
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 1);
    b[8] = 7;
    FlowEntry e;
    FlowKeyIpv6 k = k6t(a, 1000, b, 2000, UDP);
    ParserResult aller = pk_udp6(a, 1000, b, 2000);
    ParserResult retour = pk_udp6(b, 2000, a, 1000);
    fiche(&e, &aller, (void *)&k, 0);
    entry_update(&e, &retour, 0);
    CHECK_EQ(e.data->n_pkt_rtl, 1, "le retour est bien compté rtl");
    free(e.data);
}

int main(int argc, char **argv) {
    tc_begin("test_flow.c — flow.c", argc, argv);

    RUN("build_flow_key : arguments invalides",                      t_key_arguments);
    RUN("build_flow_key : champs d'une clé IPv4",                    t_key_v4_champs);
    RUN("build_flow_key : A→B et B→A, même clé (IPv4)",              t_key_v4_symetrique);
    RUN("build_flow_key : l'ordre se fait sur l'IP entière",         t_key_v4_ordre_octets);
    RUN("build_flow_key : deux flux différents, deux clés",          t_key_v4_flux_differents_clefs_differentes);
    RUN("build_flow_key : proto, ports, IP distinguent les clés",    t_key_v4_proto_et_ports);
    RUN("build_flow_key : les deux bouts identiques",                t_key_v4_bouts_identiques);
    RUN("build_flow_key : champs d'une clé IPv6",                    t_key_v6_champs);
    RUN("build_flow_key : IPv6, symétrie et octets du milieu",       t_key_v6_symetrique_et_octets_du_milieu);

    RUN("flow_key_compare : clés égales → 0",                        t_cmp_egales);
    RUN("flow_key_compare : chaque champ compte",                    t_cmp_chaque_champ);
    RUN("flow_key_compare : v4 contre v6",                           t_cmp_v4_contre_v6);
    RUN("flow_key_compare : IPv6",                                   t_cmp_v6);

    RUN("flow_hash : NULL et type invalide",                         t_hash_arguments);
    RUN("flow_hash : déterministe et symétrique (v4)",               t_hash_deterministe);
    RUN("flow_hash : répartition sur 4096 clés v4",                  t_hash_repartition_v4);
    RUN("flow_hash : les 16 octets d'une IPv6 comptent",             t_hash_v6_utilise_tous_les_octets);
    RUN("flow_hash : symétrique (v6)",                               t_hash_v6_deterministe);

    RUN("flow_key_dup : IPv4",                                       t_key_dup_v4);
    RUN("flow_key_dup : IPv6 (44 octets)",                           t_key_dup_v6);
    RUN("flow_key_dup : NULL et type invalide",                      t_key_dup_invalide);
    RUN("flow_key_free / flow_value_free : NULL accepté",            t_free_null);
    RUN("flow_value_dup",                                            t_value_dup);

    RUN("create_ft_dict : création et callbacks",                    t_ftdict_creation);
    RUN("dict de flux : aller-retour avec la clé inverse",           t_ftdict_aller_retour);
    RUN("dict de flux : plusieurs flux, clé absente",                t_ftdict_plusieurs_flux);
    RUN("dict de flux : même clé deux fois = remplacement",          t_ftdict_remplacement);
    RUN("dict de flux : suppression",                                t_ftdict_suppression);
    RUN("dict de flux : 500 flux (avec rehash)",                     t_ftdict_beaucoup);

    RUN("build_flow_entry : arguments invalides",                    t_bfe_arguments);
    RUN("build_flow_entry : TCP IPv4, tous les champs",              t_bfe_tcp_v4);
    RUN("build_flow_entry : chaque flag TCP, un par un",             t_bfe_flags_un_par_un);
    RUN("build_flow_entry : UDP IPv4",                               t_bfe_udp_v4);
    RUN("build_flow_entry : ICMP IPv4",                              t_bfe_icmp_v4);
    RUN("build_flow_entry : TCP IPv6",                               t_bfe_tcp_v6);
    RUN("build_flow_entry : UDP IPv6",                               t_bfe_udp_v6);

    RUN("entry_update : arguments invalides",                        t_upd_arguments);
    RUN("entry_update : sens et compteurs (poignée de main TCP)",    t_upd_sens_tcp_v4);
    RUN("entry_update : les 8 flags TCP",                            t_upd_tous_les_flags);
    RUN("entry_update : l'initiateur ne change pas",                 t_upd_ne_change_pas_l_initiateur);
    RUN("entry_update : UDP",                                        t_upd_udp_v4);
    RUN("entry_update : ICMP",                                       t_upd_icmp_v4);
    RUN("entry_update : IPv6",                                       t_upd_v6);
    RUN("entry_update : IPv6 qui diffèrent par l'octet 8",           t_upd_v6_octets_du_milieu);

    return tc_end();
}
