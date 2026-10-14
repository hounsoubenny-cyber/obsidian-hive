/* test_flow_table.c : tests de flow_table.c (le chef d'orchestre)
 *
 * Compiler (depuis modules_c/) :
 *   gcc -std=gnu11 -g -O0 -Wall -Wextra -fsanitize=address,undefined \
 *       flows/test_flow_table.c flows/flow_table.c flows/flow.c dict/dict.c \
 *       dchained_list/dchained_list.c portmap/portmap.c utils/utils.c -o build/test_flow_table
 * Ou simplement : ./run_tests.sh flow_table
 *
 * Les tests vont du plus simple au plus complet, pour qu'un bug « du bas » ne cache pas tout :
 *   1. création / destruction / arguments
 *   2. ft_get, ft_contains, ft_can_add          (sans rien ajouter, ou presque)
 *   3. ft_add et ft_evict_oldest avec des fiches fabriquées à la main
 *   4. ft_process avec de vrais paquets (ParserResult construits dans test_packets.h)
 *   5. port_per_ip : une PortMap par IP source, avec refcount
 *   6. invariants après 20 000 paquets au hasard, et fuites mémoire
 *
 * Contrat testé (hypothèses de lecture, à discuter si tu n'es pas d'accord) :
 *   - capacité : une table de taille N peut contenir N flux ; au (N+1)e, le plus ANCIEN part
 *   - ft_contains : 1 = présent, 0 = absent (question oui / non) ; ft_add : 0 = succès, -1 = échec
 *   - ft_can_add  : 1 = il reste de la place, 0 = table pleine (question oui / non)
 *   - l'ordre LRU : un flux qui reçoit un paquet devient le plus récent
 *   - après n'importe quelle suite d'opérations :
 *       nbr_elements == dict->nbr_elements == dcl->n_elements == longueur réelle de la file
 *   - port_per_ip : une PortMap par IP initiatrice, refcount = nombre de flux vivants de cette IP,
 *       supprimée quand le dernier flux part ; count = nombre de ports destination distincts vus
 *   - ft_destroy ne fuit rien (testé avec RUN_LEAKS)
 */
#include "../test_common.h"
#include "../test_packets.h"
#include "flow_table.h"
#include "flow.h"

/* ───────────── outils ───────────── */

static FlowKeyIpv4 key_of(const uint8_t *a, uint16_t ap, const uint8_t *b, uint16_t bp, uint8_t proto) {
    FlowKeyIpv4 k;
    uint8_t p1[2], p2[2];
    memset(&k, 0, sizeof k);
    pk_put16(p1, ap);
    pk_put16(p2, bp);
    build_flow_key(&k, (uint8_t *)a, (uint8_t *)b, p1, p2, proto, 1);   /* 1 = IPv4 */
    k.key = FlowKeyIpv4Type;                 /* on corrige le type à la main : ce n'est pas ce qu'on teste ici */
    return k;
}

static FlowKeyIpv6 key_of6(const uint8_t *a, uint16_t ap, const uint8_t *b, uint16_t bp, uint8_t proto) {
    FlowKeyIpv6 k;
    uint8_t p1[2], p2[2];
    memset(&k, 0, sizeof k);
    pk_put16(p1, ap);
    pk_put16(p2, bp);
    build_flow_key(&k, (uint8_t *)a, (uint8_t *)b, p1, p2, proto, 0);   /* 0 = IPv6 */
    k.key = FlowKeyIpv6Type;
    return k;
}

/* flux numéro i : 10.0.(i/250).(i%250+1):(1000+i)  →  192.168.0.1:80, TCP */
static void src_of(int i, uint8_t out[4]) {
    out[0] = 10; out[1] = 0; out[2] = (uint8_t)(i / 250); out[3] = (uint8_t)(i % 250 + 1);
}
static ParserResult pr_flow(int i, uint8_t flags) {
    uint8_t s[4];
    src_of(i, s);
    return pk_tcp4(s, (uint16_t)(1000 + i), IP4(192, 168, 0, 1), 80, flags);
}
static FlowKeyIpv4 key_flow(int i) {
    uint8_t s[4];
    src_of(i, s);
    return key_of(s, (uint16_t)(1000 + i), IP4(192, 168, 0, 1), 80, TCP);
}

/* fiche fabriquée comme le fait ft_process : tout sur le tas */
static FlowEntry *new_entry(int i) {
    ParserResult pr = pr_flow(i, SYN);
    FlowKeyIpv4 k = key_flow(i);
    FlowKeyType *copie = (FlowKeyType *)flow_key_dup(&k);
    FlowEntry *e = (FlowEntry *)calloc(1, sizeof *e);
    build_flow_entry(e, &pr, copie, 1, 0);   /* 1 = IPv4 */
    return e;
}

static int add_flow(FlowTable *ft, int i, FlowEntry **out) {
    FlowKeyIpv4 k = key_flow(i);
    FlowEntry *e = new_entry(i);
    if (out) *out = e;
    return ft_add(ft, (FlowKeyType *)&k, e);
}

static int present(FlowTable *ft, int i) {
    FlowKeyIpv4 k = key_flow(i);
    return ft_get(ft, &k) != NULL;
}

static int process_flow(FlowTable *ft, int i, uint8_t flags) {
    ParserResult pr = pr_flow(i, flags);
    return ft_process(ft, &pr, 0);
}

static struct PortMap *pm_of(FlowTable *ft, const uint8_t ip[4]) {
    struct PortPerIpKey k;
    memset(&k, 0, sizeof k);
    k.v4 = 1;   /* 1 = IPv4 */
    memcpy(k.ip, ip, 4);
    return (struct PortMap *)dict_getitem(ft->port_per_ip, &k);
}

/* longueur réelle de la file en la parcourant ; -1 si les liens sont incohérents */
static int dcl_walk(FlowTable *ft) {
    DChainedList *d = ft->flow_dcl;
    int n = 0;
    FlowEntry *prev = NULL;
    for (FlowEntry *e = d->head; e; e = e->lru_next) {
        if (e->lru_prev != prev) return -1;
        prev = e;
        if (++n > 100000) return -1;
    }
    if (prev != d->tail) return -1;
    return n;
}

static char g_msg[200];

/* NULL si la table est cohérente, sinon une phrase qui dit ce qui cloche */
static const char *invariants(FlowTable *ft) {
    if (ft->nbr_elements > ft->size) {
        snprintf(g_msg, sizeof g_msg, "nbr_elements (%u) dépasse la capacité (%u)", ft->nbr_elements, ft->size);
        return g_msg;
    }
    if (ft->flow_dict->nbr_elements != ft->nbr_elements) {
        snprintf(g_msg, sizeof g_msg, "dict->nbr_elements = %u mais nbr_elements = %u", ft->flow_dict->nbr_elements, ft->nbr_elements);
        return g_msg;
    }
    if (ft->flow_dcl->n_elements != ft->nbr_elements) {
        snprintf(g_msg, sizeof g_msg, "dcl->n_elements = %u mais nbr_elements = %u", ft->flow_dcl->n_elements, ft->nbr_elements);
        return g_msg;
    }
    int n = dcl_walk(ft);
    if (n < 0) { snprintf(g_msg, sizeof g_msg, "liens lru_prev / lru_next incohérents dans la file"); return g_msg; }
    if ((unsigned)n != ft->nbr_elements) {
        snprintf(g_msg, sizeof g_msg, "la file contient %d maillons mais nbr_elements = %u", n, ft->nbr_elements);
        return g_msg;
    }
    for (FlowEntry *e = ft->flow_dcl->head; e; e = e->lru_next) {
        FlowEntry *g = ft_get(ft, e->key);
        if (!g) { snprintf(g_msg, sizeof g_msg, "un flux de la file est introuvable dans le dict"); return g_msg; }
        if (g->data != e->data) { snprintf(g_msg, sizeof g_msg, "le dict et la file ne pointent pas vers le même FlowData"); return g_msg; }
    }
    return NULL;
}

#define CHECK_INVARIANTS(ft, msg) do {                                               \
        const char *p_ = invariants(ft);                                             \
        tc_checks++;                                                                 \
        if (p_) { tc_fails++; printf("      ✗ %s : %s  (ligne %d)\n", (msg), p_, __LINE__); } \
    } while (0)

/* ═══════════════════════════ 1. création / destruction ═══════════════════════════ */

static void t_creation(void) {
    CHECK(ft_create(0) == NULL, "ft_create(0) → NULL");
    FlowTable *ft = ft_create(8);
    CHECK(ft != NULL, "ft_create(8) != NULL");
    if (!ft) return;
    CHECK_EQ(ft->size, 8, "size == 8");
    CHECK_EQ(ft->nbr_elements, 0, "nbr_elements == 0");
    CHECK_EQ(ft->n_evicted, 0, "n_evicted == 0");
    CHECK(ft->flow_dict != NULL, "flow_dict créé");
    CHECK(ft->flow_dcl != NULL, "flow_dcl créée");
    CHECK(ft->port_per_ip != NULL, "port_per_ip créé");
    if (ft->flow_dcl) CHECK_EQ(ft->flow_dcl->max_element, 8, "la file a la même capacité (8)");
    ft_destroy(ft);
}

static void t_arguments_nuls(void) {
    FlowTable *ft = ft_create(8);
    FlowKeyIpv4 k = key_flow(1);
    ParserResult pr = pr_flow(1, SYN);
    CHECK_EQ(ft_process(NULL, &pr, 0), -1, "ft_process(NULL, pr, 0) → -1");
    CHECK_EQ(ft_process(ft, NULL, 0), -1, "ft_process(ft, NULL, 0) → -1");
    CHECK(ft_get(NULL, &k) == NULL, "ft_get(NULL, key) → NULL");
    CHECK_EQ(ft_contains(NULL, &k), 0, "ft_contains(NULL, key) → 0 (non)");
    ft_evict_oldest(NULL);
    ft_destroy(NULL);
    CHECK_EQ(ft->nbr_elements, 0, "rien n'a été créé");
    ft_destroy(ft);
}

static void t_add_et_can_add_sur_null(void) {
    FlowKeyIpv4 k = key_flow(1);
    FlowEntry *e = new_entry(1);
    CHECK_EQ(ft_add(NULL, (FlowKeyType *)&k, e), -1, "ft_add(NULL, ...) → -1");
    CHECK_EQ(ft_can_add(NULL), 0, "ft_can_add(NULL) → 0 (pas de place)");
}

static void t_destroy_table_vide_sans_fuite(void) {
    FlowTable *ft = ft_create(64);
    ft_destroy(ft);
    CHECK(1, "create puis destroy : aucune fuite (rapport LSan sinon)");
}

/* ═══════════════════════════ 2. ft_get / ft_contains / ft_can_add ═══════════════════════════ */

static void t_get_table_vide(void) {
    FlowTable *ft = ft_create(8);
    FlowKeyIpv4 k = key_flow(1);
    CHECK(ft_get(ft, &k) == NULL, "ft_get sur table vide → NULL");
    CHECK_EQ(ft_contains(ft, &k), 0, "ft_contains sur table vide → 0");
    ft_destroy(ft);
}

static void t_can_add(void) {
    FlowTable *ft = ft_create(4);
    CHECK_EQ(ft_can_add(ft), 1, "table vide : on peut ajouter (1)");
    ft->nbr_elements = 3;
    CHECK_EQ(ft_can_add(ft), 1, "3 flux sur 4 : il reste une place (1)");
    ft->nbr_elements = 4;
    CHECK_EQ(ft_can_add(ft), 0, "4 flux sur 4 : plein (0)");
    ft->nbr_elements = 0;
    ft_destroy(ft);
}

/* ═══════════════════════════ 3. ft_add / ft_evict_oldest (fiches faites main) ═══════════════════════════ */

static void t_add_un_flux(void) {
    FlowTable *ft = ft_create(16);
    FlowEntry *e;
    CHECK_EQ(add_flow(ft, 1, &e), 0, "ft_add → 0");
    CHECK_EQ(ft->nbr_elements, 1, "nbr_elements == 1");
    FlowKeyIpv4 k = key_flow(1), absent = key_flow(2);
    FlowEntry *g = ft_get(ft, &k);
    CHECK(g != NULL, "ft_get retrouve le flux");
    if (g) CHECK_PTR(g->data, e->data, "même FlowData que la fiche ajoutée");
    CHECK_EQ(ft_contains(ft, &k), 1, "ft_contains(présent) → 1");
    CHECK_EQ(ft_contains(ft, &absent), 0, "ft_contains(absent) → 0");
    CHECK(ft_get(ft, &absent) == NULL, "ft_get(absent) → NULL");
    CHECK_EQ(ft->flow_dcl->n_elements, 1, "la file a 1 élément");
    CHECK_PTR(ft->flow_dcl->head, e, "head de la file = la fiche");
    CHECK_PTR(ft->flow_dcl->tail, e, "tail de la file = la fiche");
    ft_destroy(ft);
}

static void t_add_plusieurs(void) {
    FlowTable *ft = ft_create(16);
    FlowEntry *e[5];
    for (int i = 0; i < 5; i++) CHECK_EQ(add_flow(ft, i, &e[i]), 0, "ft_add → 0");
    CHECK_EQ(ft->nbr_elements, 5, "nbr_elements == 5");
    CHECK_EQ(ft->n_evicted, 0, "aucune éviction");
    int manquants = 0;
    for (int i = 0; i < 5; i++) if (!present(ft, i)) manquants++;
    CHECK_EQ(manquants, 0, "les 5 flux sont retrouvables");
    CHECK_PTR(ft->flow_dcl->head, e[0], "head = le premier ajouté (le plus ancien)");
    CHECK_PTR(ft->flow_dcl->tail, e[4], "tail = le dernier ajouté (le plus récent)");
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

static void t_add_jusqu_a_la_capacite(void) {
    FlowTable *ft = ft_create(8);
    for (int i = 0; i < 8; i++) add_flow(ft, i, NULL);
    CHECK_EQ(ft->nbr_elements, 8, "8 flux dans une table de taille 8");
    CHECK_EQ(ft->n_evicted, 0, "aucune éviction tant que la table n'est pas pleine");
    int manquants = 0;
    for (int i = 0; i < 8; i++) if (!present(ft, i)) manquants++;
    CHECK_EQ(manquants, 0, "les 8 flux sont présents");
    ft_destroy(ft);
}

static void t_add_deja_present(void) {
    FlowTable *ft = ft_create(16);
    FlowKeyIpv4 k = key_flow(1);
    FlowEntry *e;
    add_flow(ft, 1, &e);
    CHECK_EQ(ft_add(ft, (FlowKeyType *)&k, e), 0, "ré-ajouter la même clé → 0");
    CHECK_EQ(ft->nbr_elements, 1, "toujours 1 flux");
    CHECK_EQ(ft->flow_dcl->n_elements, 1, "toujours 1 maillon dans la file");
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

static void t_evict_oldest(void) {
    FlowTable *ft = ft_create(16);
    for (int i = 0; i < 3; i++) add_flow(ft, i, NULL);
    ft_evict_oldest(ft);
    CHECK_EQ(ft->nbr_elements, 2, "nbr_elements == 2");
    CHECK_EQ(ft->n_evicted, 1, "n_evicted == 1");
    CHECK(!present(ft, 0), "le plus ancien (0) est parti");
    CHECK(present(ft, 1) && present(ft, 2), "les flux 1 et 2 sont toujours là");
    CHECK_INVARIANTS(ft, "table cohérente après éviction");
    ft_destroy(ft);
}

static void t_evict_tout(void) {
    FlowTable *ft = ft_create(16);
    for (int i = 0; i < 3; i++) add_flow(ft, i, NULL);
    for (int i = 0; i < 3; i++) ft_evict_oldest(ft);
    CHECK_EQ(ft->nbr_elements, 0, "table vide");
    CHECK_EQ(ft->n_evicted, 3, "n_evicted == 3");
    CHECK(ft->flow_dcl->head == NULL && ft->flow_dcl->tail == NULL, "file vide : head et tail NULL");
    CHECK_EQ(ft->flow_dcl->n_elements, 0, "file : 0 élément");
    ft_evict_oldest(ft);
    CHECK_EQ(ft->n_evicted, 3, "évincer une table vide ne change rien");
    ft_destroy(ft);
}

static void t_evict_ordre_lru(void) {
    FlowTable *ft = ft_create(16);
    FlowEntry *e[3];
    for (int i = 0; i < 3; i++) add_flow(ft, i, &e[i]);
    FlowKeyIpv4 k0 = key_flow(0);
    ft_add(ft, (FlowKeyType *)&k0, e[0]);          /* on « touche » le flux 0 : il devient le plus récent */
    ft_evict_oldest(ft);
    CHECK(present(ft, 0), "le flux 0, touché, est resté");
    CHECK(!present(ft, 1), "le flux 1 est devenu le plus ancien : il part");
    CHECK(present(ft, 2), "le flux 2 est là");
    ft_destroy(ft);
}

static void t_capacite_eviction_automatique(void) {
    FlowTable *ft = ft_create(4);
    for (int i = 0; i < 6; i++) CHECK_EQ(add_flow(ft, i, NULL), 0, "ft_add → 0");
    CHECK_EQ(ft->nbr_elements, 4, "la table garde 4 flux (sa taille)");
    CHECK_EQ(ft->n_evicted, 2, "2 évictions (6 flux ajoutés, 4 places)");
    CHECK(!present(ft, 0) && !present(ft, 1), "les 2 plus anciens (0, 1) sont partis");
    CHECK(present(ft, 2) && present(ft, 3) && present(ft, 4) && present(ft, 5), "les 4 plus récents (2..5) sont là");
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

static void t_destroy_apres_ajouts_sans_fuite(void) {
    FlowTable *ft = ft_create(8);
    for (int i = 0; i < 5; i++) add_flow(ft, i, NULL);
    ft_destroy(ft);
    CHECK(1, "destroy après 5 ajouts : toutes les fiches, données et clés sont libérées (rapport LSan sinon)");
}

/* ═══════════════════════════ 4. ft_process ═══════════════════════════ */

static void t_process_paquet_non_valide(void) {
    FlowTable *ft = ft_create(8);
    uint8_t codes[] = {(uint8_t)ERROR, (uint8_t)TOO_LITTLE, (uint8_t)INCOHERENCE, (uint8_t)NOT_HANDLE, (uint8_t)FRAGMENT};
    for (size_t i = 0; i < sizeof codes; i++) {
        ParserResult pr = pr_flow(1, SYN);
        pr.code = codes[i];
        char msg[60];
        snprintf(msg, sizeof msg, "pr.code = %d → -1", codes[i]);
        CHECK_EQ(ft_process(ft, &pr, 0), -1, msg);
    }
    CHECK_EQ(ft->nbr_elements, 0, "aucun flux créé");
    ft_destroy(ft);
}

static void t_process_un_paquet_v4(void) {
    FlowTable *ft = ft_create(8);
    ParserResult pr = pr_flow(1, SYN);
    CHECK_EQ(ft_process(ft, &pr, 0), 0, "ft_process → 0");
    CHECK_EQ(ft->nbr_elements, 1, "nbr_elements == 1");
    FlowKeyIpv4 k = key_flow(1);
    FlowEntry *e = ft_get(ft, &k);
    CHECK(e != NULL, "le flux est retrouvable avec la clé IPv4 canonique");
    if (e && e->data) {
        uint8_t s[4];
        src_of(1, s);
        CHECK_MEM(e->data->header.ipv4_headers.initiator_ip, s, 4, "initiateur : IP source");
        CHECK_EQ(e->data->n_pkt_ltr, 1, "ltr == 1");
        CHECK_EQ(e->data->n_pkt_rtl, 0, "rtl == 0");
        CHECK_EQ(e->data->flag_count.syn, 1, "syn == 1");
        CHECK_EQ(e->data->v4, 1, "FlowData->v4 == 1 (convention : 1 = IPv4)");
    }
    ft_destroy(ft);
}

static void t_process_type_de_cle_stockee(void) {
    FlowTable *ft = ft_create(8);
    ParserResult p4 = pr_flow(1, SYN);
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    ParserResult p6 = pk_tcp6(a, 40000, b, 22, SYN);

    CHECK_EQ(ft_process(ft, &p4, 0), 0, "paquet IPv4 → 0");
    CHECK_EQ(ft_process(ft, &p6, 0), 0, "paquet IPv6 → 0");

    FlowKeyIpv4 k4 = key_flow(1);
    FlowKeyIpv6 k6 = key_of6(a, 40000, b, 22, TCP);
    FlowEntry *e4 = ft_get(ft, &k4);
    FlowEntry *e6 = ft_get(ft, &k6);

    CHECK(e4 != NULL && e4->key != NULL, "flux IPv4 retrouvé");
    CHECK(e6 != NULL && e6->key != NULL, "flux IPv6 retrouvé");

    if (e4 && e4->key) {
        FlowKeyType tag4 = *(FlowKeyType *)e4->key;
        CHECK_EQ(tag4, FlowKeyIpv4Type, "flux IPv4 : type de clé stocké == FlowKeyIpv4Type");
    }
    if (e6 && e6->key) {
        FlowKeyType tag6 = *(FlowKeyType *)e6->key;
        CHECK_EQ(tag6, FlowKeyIpv6Type, "flux IPv6 : type de clé stocké == FlowKeyIpv6Type");
    }
    if (e6 && e6->key) {
        FlowKeyType tag6 = *(FlowKeyType *)e6->key;
        if (tag6 == FlowKeyIpv6Type) {
            FlowKeyIpv6 *stockee = (FlowKeyIpv6 *)e6->key;
            CHECK_MEM(stockee->ip_min, a, 16, "clé IPv6 stockée : ip_min complète (16 octets)");
        }
    }
    ft_destroy(ft);
}

static void t_process_sens_inverse_meme_flux(void) {
    FlowTable *ft = ft_create(8);
    uint8_t s[4];
    src_of(1, s);
    ParserResult syn    = pk_tcp4(s, 1001, IP4(192, 168, 0, 1), 80, SYN);
    ParserResult synack = pk_tcp4(IP4(192, 168, 0, 1), 80, s, 1001, SYN | ACK);
    ParserResult ack    = pk_tcp4(s, 1001, IP4(192, 168, 0, 1), 80, ACK);
    CHECK_EQ(ft_process(ft, &syn, 0), 0, "SYN → 0");
    CHECK_EQ(ft_process(ft, &synack, 0), 0, "SYN-ACK → 0");
    CHECK_EQ(ft_process(ft, &ack, 0), 0, "ACK → 0");
    CHECK_EQ(ft->nbr_elements, 1, "une seule conversation : 1 flux");
    FlowKeyIpv4 k = key_flow(1);
    FlowEntry *e = ft_get(ft, &k);
    CHECK(e != NULL && e->data != NULL, "flux retrouvé");
    if (e && e->data) {
        CHECK_EQ(e->data->n_pkt_ltr, 2, "ltr == 2 (SYN, ACK)");
        CHECK_EQ(e->data->n_pkt_rtl, 1, "rtl == 1 (SYN-ACK)");
        CHECK_EQ(e->data->flag_count.syn, 2, "syn == 2");
        CHECK_EQ(e->data->flag_count.ack, 2, "ack == 2");
    }
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

static void t_process_compteurs_nombreux(void) {
    FlowTable *ft = ft_create(8);
    uint8_t s[4];
    src_of(1, s);
    ParserResult aller  = pk_tcp4(s, 1001, IP4(192, 168, 0, 1), 80, ACK);
    ParserResult retour = pk_tcp4(IP4(192, 168, 0, 1), 80, s, 1001, ACK);
    for (int i = 0; i < 5; i++) ft_process(ft, &aller, 0);
    for (int i = 0; i < 3; i++) ft_process(ft, &retour, 0);
    FlowKeyIpv4 k = key_flow(1);
    FlowEntry *e = ft_get(ft, &k);
    CHECK(e != NULL && e->data != NULL, "flux retrouvé");
    if (e && e->data) {
        CHECK_EQ(e->data->n_pkt_ltr, 5, "ltr == 5");
        CHECK_EQ(e->data->n_pkt_rtl, 3, "rtl == 3");
    }
    CHECK_EQ(ft->nbr_elements, 1, "1 flux");
    ft_destroy(ft);
}

static void t_process_flux_distincts(void) {
    FlowTable *ft = ft_create(16);
    ParserResult base = pk_tcp4(IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, SYN);
    ParserResult autre_port = pk_tcp4(IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 81, SYN);
    ParserResult autre_ip = pk_tcp4(IP4(10, 0, 0, 3), 1000, IP4(10, 0, 0, 2), 80, SYN);
    ParserResult en_udp = pk_udp4(IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80);
    ft_process(ft, &base, 0);
    CHECK_EQ(ft->nbr_elements, 1, "1 flux");
    ft_process(ft, &autre_port, 0);
    CHECK_EQ(ft->nbr_elements, 2, "autre port destination → 2 flux");
    ft_process(ft, &autre_ip, 0);
    CHECK_EQ(ft->nbr_elements, 3, "autre IP source → 3 flux");
    ft_process(ft, &en_udp, 0);
    CHECK_EQ(ft->nbr_elements, 4, "même quadruplet en UDP → 4 flux");
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

static void t_process_flux_croises_distincts(void) {
    /* 10.0.0.1:80 ↔ 10.0.0.2:443  et  10.0.0.1:443 ↔ 10.0.0.2:80 : deux conversations différentes */
    FlowTable *ft = ft_create(16);
    ParserResult f1 = pk_tcp4(IP4(10, 0, 0, 1), 80,  IP4(10, 0, 0, 2), 443, SYN);
    ParserResult f2 = pk_tcp4(IP4(10, 0, 0, 1), 443, IP4(10, 0, 0, 2), 80,  SYN);
    ft_process(ft, &f1, 0);
    ft_process(ft, &f2, 0);
    CHECK_EQ(ft->nbr_elements, 2, "deux conversations croisées = 2 flux");
    ft_destroy(ft);
}

static void t_process_udp(void) {
    FlowTable *ft = ft_create(8);
    ParserResult q = pk_udp4(IP4(10, 0, 0, 1), 5353, IP4(10, 0, 0, 2), 53);
    ParserResult r = pk_udp4(IP4(10, 0, 0, 2), 53, IP4(10, 0, 0, 1), 5353);
    ft_process(ft, &q, 0);
    ft_process(ft, &r, 0);
    CHECK_EQ(ft->nbr_elements, 1, "question + réponse = 1 flux");
    FlowKeyIpv4 k = key_of(IP4(10, 0, 0, 1), 5353, IP4(10, 0, 0, 2), 53, UDP);
    FlowEntry *e = ft_get(ft, &k);
    CHECK(e != NULL && e->data != NULL, "flux UDP retrouvé");
    if (e && e->data) {
        CHECK_EQ(e->data->n_pkt_ltr, 1, "ltr == 1");
        CHECK_EQ(e->data->n_pkt_rtl, 1, "rtl == 1");
    }
    ft_destroy(ft);
}

static void t_process_icmp(void) {
    FlowTable *ft = ft_create(8);
    ParserResult req = pk_icmp4(IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 8, 0);
    ParserResult rep = pk_icmp4(IP4(10, 0, 0, 2), IP4(10, 0, 0, 1), 0, 0);
    ft_process(ft, &req, 0);
    ft_process(ft, &req, 0);
    ft_process(ft, &rep, 0);
    CHECK_EQ(ft->nbr_elements, 1, "ping aller-retour = 1 flux");
    FlowKeyIpv4 k = key_of(IP4(10, 0, 0, 1), 0, IP4(10, 0, 0, 2), 0, ICMP);
    FlowEntry *e = ft_get(ft, &k);
    CHECK(e != NULL && e->data != NULL, "flux ICMP retrouvé (ports à 0)");
    if (e && e->data) {
        CHECK_EQ(e->data->n_pkt_ltr, 2, "ltr == 2");
        CHECK_EQ(e->data->n_pkt_rtl, 1, "rtl == 1");
    }
    ft_destroy(ft);
}

static void t_process_v6(void) {
    FlowTable *ft = ft_create(8);
    uint8_t a[16], b[16];
    pk_ip6(a, 1);
    pk_ip6(b, 2);
    ParserResult syn    = pk_tcp6(a, 40000, b, 22, SYN);
    ParserResult synack = pk_tcp6(b, 22, a, 40000, SYN | ACK);
    CHECK_EQ(ft_process(ft, &syn, 0), 0, "SYN v6 → 0");
    CHECK_EQ(ft_process(ft, &synack, 0), 0, "SYN-ACK v6 → 0");
    CHECK_EQ(ft->nbr_elements, 1, "1 flux");
    FlowKeyIpv6 k = key_of6(a, 40000, b, 22, TCP);
    FlowEntry *e = ft_get(ft, &k);
    CHECK(e != NULL && e->data != NULL, "flux IPv6 retrouvé avec la clé IPv6 canonique");
    if (e && e->data) {
        CHECK_MEM(e->data->header.ipv6_headers.initiator_ip, a, 16, "initiateur : IPv6 source (16 octets)");
        CHECK_EQ(e->data->n_pkt_ltr, 1, "ltr == 1");
        CHECK_EQ(e->data->n_pkt_rtl, 1, "rtl == 1");
    }
    ft_destroy(ft);
}

static void t_process_ordre_lru(void) {
    FlowTable *ft = ft_create(16);
    for (int i = 0; i < 3; i++) process_flow(ft, i, SYN);
    process_flow(ft, 0, ACK);                   /* le flux 0 reçoit un paquet : il devient le plus récent */
    ft_evict_oldest(ft);
    CHECK(present(ft, 0), "flux 0 (touché) : toujours là");
    CHECK(!present(ft, 1), "flux 1 : le plus ancien, parti");
    CHECK(present(ft, 2), "flux 2 : toujours là");
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

static void t_process_capacite(void) {
    FlowTable *ft = ft_create(8);
    for (int i = 0; i < 20; i++) CHECK_EQ(process_flow(ft, i, SYN), 0, "ft_process → 0");
    CHECK_EQ(ft->nbr_elements, 8, "table pleine : 8 flux");
    CHECK_EQ(ft->n_evicted, 12, "12 évictions (20 flux, 8 places)");
    int anciens_restes = 0, recents_manquants = 0;
    for (int i = 0; i < 12; i++) if (present(ft, i)) anciens_restes++;
    for (int i = 12; i < 20; i++) if (!present(ft, i)) recents_manquants++;
    CHECK_EQ(anciens_restes, 0, "les 12 plus anciens sont partis");
    CHECK_EQ(recents_manquants, 0, "les 8 plus récents sont là");
    CHECK_INVARIANTS(ft, "table cohérente");
    ft_destroy(ft);
}

/* ═══════════════════════════ 5. port_per_ip ═══════════════════════════ */

static void t_ports_scan_simple(void) {
    FlowTable *ft = ft_create(64);
    uint8_t scanner[4] = {10, 0, 0, 5};
    for (int p = 1; p <= 25; p++) {
        ParserResult pr = pk_tcp4(scanner, (uint16_t)(40000 + p), IP4(192, 168, 0, 1), (uint16_t)p, SYN);
        ft_process(ft, &pr, 0);
    }
    CHECK_EQ(ft->nbr_elements, 25, "25 flux (un par port visé)");
    struct PortMap *pm = pm_of(ft, scanner);
    CHECK(pm != NULL, "une PortMap existe pour l'IP du scanner");
    if (pm) {
        CHECK_EQ(pm->count, 25, "25 ports distincts comptés");
        CHECK_EQ(portmap_test(pm, 1), 1, "port 1 vu");
        CHECK_EQ(portmap_test(pm, 25), 1, "port 25 vu");
        CHECK_EQ(portmap_test(pm, 26), 0, "port 26 pas vu");
        CHECK_EQ(portmap_test(pm, 40001), 0, "les ports SOURCE ne comptent pas");
    }
    ft_destroy(ft);
}

static void t_ports_pas_de_double_compte(void) {
    FlowTable *ft = ft_create(64);
    uint8_t scanner[4] = {10, 0, 0, 5};
    ParserResult pr = pk_tcp4(scanner, 40001, IP4(192, 168, 0, 1), 22, SYN);
    for (int i = 0; i < 10; i++) ft_process(ft, &pr, 0);
    struct PortMap *pm = pm_of(ft, scanner);
    CHECK(pm != NULL, "PortMap créée");
    if (pm) CHECK_EQ(pm->count, 1, "10 paquets sur le même flux : 1 seul port");
    /* même port visé par deux flux différents (deux ports source) */
    ParserResult pr2 = pk_tcp4(scanner, 40002, IP4(192, 168, 0, 1), 22, SYN);
    ft_process(ft, &pr2, 0);
    pm = pm_of(ft, scanner);
    if (pm) CHECK_EQ(pm->count, 1, "2 flux vers le même port 22 : toujours 1 port distinct");
    ft_destroy(ft);
}

static void t_ports_deux_sources(void) {
    FlowTable *ft = ft_create(64);
    uint8_t a[4] = {10, 0, 0, 5}, b[4] = {10, 0, 0, 6};
    for (int p = 1; p <= 10; p++) { ParserResult pr = pk_tcp4(a, (uint16_t)(30000 + p), IP4(192, 168, 0, 1), (uint16_t)p, SYN); ft_process(ft, &pr, 0); }
    for (int p = 1; p <= 5; p++)  { ParserResult pr = pk_tcp4(b, (uint16_t)(31000 + p), IP4(192, 168, 0, 1), (uint16_t)(100 + p), SYN); ft_process(ft, &pr, 0); }
    struct PortMap *pa = pm_of(ft, a), *pb = pm_of(ft, b);
    CHECK(pa != NULL && pb != NULL, "une PortMap par IP source");
    if (pa && pb) {
        CHECK_EQ(pa->count, 10, "IP a : 10 ports");
        CHECK_EQ(pb->count, 5, "IP b : 5 ports");
        CHECK_EQ(portmap_test(pa, 101), 0, "les ports de b ne sont pas chez a");
        CHECK_EQ(portmap_test(pb, 1), 0, "les ports de a ne sont pas chez b");
    }
    ft_destroy(ft);
}

static void t_ports_icmp_sans_port(void) {
    FlowTable *ft = ft_create(8);
    ParserResult req = pk_icmp4(IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 8, 0);
    CHECK_EQ(ft_process(ft, &req, 0), 0, "ping → 0");
    struct PortMap *pm = pm_of(ft, IP4(10, 0, 0, 1));
    CHECK(pm == NULL || pm->count == 0, "ICMP : aucun port enregistré");
    ft_destroy(ft);
}

static void t_ports_refcount_et_liberation(void) {
    FlowTable *ft = ft_create(16);
    uint8_t s[4] = {10, 0, 0, 5};
    ParserResult f1 = pk_tcp4(s, 40001, IP4(192, 168, 0, 1), 80, SYN);
    ParserResult f2 = pk_tcp4(s, 40002, IP4(192, 168, 0, 1), 81, SYN);
    ft_process(ft, &f1, 0);
    ft_process(ft, &f2, 0);
    struct PortMap *pm = pm_of(ft, s);
    CHECK(pm != NULL, "PortMap créée");
    if (pm) CHECK_EQ(pm->refcount, 2, "refcount == 2 (2 flux vivants de cette IP)");
    ft_evict_oldest(ft);
    pm = pm_of(ft, s);
    CHECK(pm != NULL, "1 flux évincé, il en reste 1 : la PortMap est toujours là");
    if (pm) CHECK_EQ(pm->refcount, 1, "refcount == 1");
    ft_evict_oldest(ft);
    CHECK(pm_of(ft, s) == NULL, "dernier flux évincé : la PortMap est supprimée");
    CHECK_EQ(ft->port_per_ip->nbr_elements, 0, "port_per_ip vide");
    ft_destroy(ft);
}

/* ═══════════════════════════ 6. gros volumes et fuites ═══════════════════════════ */

static void t_invariants_apres_20000_paquets(void) {
    FlowTable *ft = ft_create(256);
    uint32_t seed = 777;
    int echecs = 0;
    for (int n = 0; n < 20000; n++) {
        seed = seed * 1103515245u + 12345u;
        int id = (int)((seed >> 8) % 600), rev = (int)((seed >> 4) & 1), kind = (int)((seed >> 20) % 3);
        uint8_t a[4] = {10, 1, (uint8_t)(id >> 8), (uint8_t)(id & 255)}, b[4] = {10, 2, 0, (uint8_t)(id % 7 + 1)};
        uint16_t pa = (uint16_t)(2000 + id), pb = (uint16_t)(80 + id % 5);
        const uint8_t *src = rev ? b : a, *dst = rev ? a : b;
        uint16_t sp = rev ? pb : pa, dp = rev ? pa : pb;
        ParserResult pr;
        if (kind == 0)      pr = pk_tcp4(src, sp, dst, dp, (uint8_t)(seed >> 24));
        else if (kind == 1) pr = pk_udp4(src, sp, dst, dp);
        else                pr = pk_icmp4(src, dst, 8, 0);
        if (ft_process(ft, &pr, 0) != 0) echecs++;
        if (n % 500 == 499) {
            const char *p = invariants(ft);
            if (p) {
                tc_checks++; tc_fails++;
                printf("      ✗ incohérence après %d paquets : %s\n", n + 1, p);
                return;
            }
        }
    }
    CHECK_EQ(echecs, 0, "aucun ft_process n'a renvoyé -1");
    CHECK(ft->n_evicted > 0, "des évictions ont eu lieu (1800 flux possibles, 256 places)");
    CHECK_EQ(ft->nbr_elements, 256, "table pleine à la fin");
    CHECK_INVARIANTS(ft, "table cohérente à la fin");
    ft_destroy(ft);
}

static void t_destroy_apres_process_sans_eviction_sans_fuite(void) {
    FlowTable *ft = ft_create(64);
    for (int i = 0; i < 30; i++) process_flow(ft, i, SYN);
    for (int i = 0; i < 30; i++) process_flow(ft, i, ACK);
    ft_destroy(ft);
    CHECK(1, "30 flux, 60 paquets, destroy : rien ne fuit (rapport LSan sinon)");
}

static void t_destroy_apres_process_avec_evictions_sans_fuite(void) {
    FlowTable *ft = ft_create(16);
    for (int i = 0; i < 100; i++) process_flow(ft, i, SYN);
    ft_destroy(ft);
    CHECK(1, "100 flux dans 16 places, destroy : rien ne fuit (rapport LSan sinon)");
}

int main(int argc, char **argv) {
    tc_begin("test_flow_table.c — flow_table", argc, argv);

    /* 1 */
    RUN("ft_create : tailles et sous-structures",                     t_creation);
    RUN("arguments NULL : ft_process, ft_get, ft_contains...",        t_arguments_nuls);
    RUN("ft_add(NULL) et ft_can_add(NULL)",                           t_add_et_can_add_sur_null);
    RUN_LEAKS("ft_create puis ft_destroy : pas de fuite",             t_destroy_table_vide_sans_fuite);
    /* 2 */
    RUN("ft_get / ft_contains sur table vide",                        t_get_table_vide);
    RUN("ft_can_add : place restante et table pleine",                t_can_add);
    /* 3 */
    RUN("ft_add : un flux",                                           t_add_un_flux);
    RUN("ft_add : plusieurs flux, ordre de la file",                  t_add_plusieurs);
    RUN("ft_add : jusqu'à la capacité exacte",                        t_add_jusqu_a_la_capacite);
    RUN("ft_add : clé déjà présente",                                 t_add_deja_present);
    RUN("ft_evict_oldest : évince le plus ancien",                    t_evict_oldest);
    RUN("ft_evict_oldest : jusqu'à vider la table",                   t_evict_tout);
    RUN("ft_evict_oldest : respecte l'ordre LRU",                     t_evict_ordre_lru);
    RUN("ft_add : éviction automatique quand la table est pleine",    t_capacite_eviction_automatique);
    RUN_LEAKS("ft_destroy après des ft_add : pas de fuite",           t_destroy_apres_ajouts_sans_fuite);
    /* 4 */
    RUN("ft_process : paquets non valides refusés",                   t_process_paquet_non_valide);
    RUN("ft_process : un paquet IPv4 crée un flux",                   t_process_un_paquet_v4);
    RUN("ft_process : type de clé stocké (v4 et v6)",                 t_process_type_de_cle_stockee);
    RUN("ft_process : SYN, SYN-ACK, ACK = un seul flux",              t_process_sens_inverse_meme_flux);
    RUN("ft_process : compteurs ltr / rtl",                           t_process_compteurs_nombreux);
    RUN("ft_process : flux distincts (port, IP, protocole)",          t_process_flux_distincts);
    RUN("ft_process : conversations croisées = 2 flux",               t_process_flux_croises_distincts);
    RUN("ft_process : UDP",                                           t_process_udp);
    RUN("ft_process : ICMP",                                          t_process_icmp);
    RUN("ft_process : IPv6",                                          t_process_v6);
    RUN("ft_process : un paquet remet le flux en tête de l'ordre LRU", t_process_ordre_lru);
    RUN("ft_process : capacité 8, 20 flux",                           t_process_capacite);
    /* 5 */
    RUN("port_per_ip : scan de 25 ports",                             t_ports_scan_simple);
    RUN("port_per_ip : pas de double comptage",                       t_ports_pas_de_double_compte);
    RUN("port_per_ip : deux sources indépendantes",                   t_ports_deux_sources);
    RUN("port_per_ip : ICMP n'enregistre aucun port",                 t_ports_icmp_sans_port);
    RUN("port_per_ip : refcount et libération à l'éviction",          t_ports_refcount_et_liberation);
    /* 6 */
    RUN("20 000 paquets au hasard : la table reste cohérente",        t_invariants_apres_20000_paquets);
    RUN_LEAKS("ft_destroy après ft_process (sans éviction) : pas de fuite", t_destroy_apres_process_sans_eviction_sans_fuite);
    RUN_LEAKS("ft_destroy après ft_process (avec évictions) : pas de fuite", t_destroy_apres_process_avec_evictions_sans_fuite);

    return tc_end();
}
