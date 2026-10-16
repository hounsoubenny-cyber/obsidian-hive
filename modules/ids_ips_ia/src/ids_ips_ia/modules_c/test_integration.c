/* test_integration.c : trois familles de tests qui traversent TOUS les modules
 *
 *   1. CONVENTIONS : chaque famille de fonctions respecte la règle (voir le tableau dans flow.h)
 *        action    → 0 = succès, -1 = échec        question → 1 = oui, 0 = non
 *        comparaison → 0 = égaux                   pointeur → NULL = absent / échec
 *        drapeau v4 → 1 = IPv4, 0 = IPv6
 *   2. MÉMOIRE : tailles, positions (offsetof) et unions. Si un jour tu ajoutes un champ et que
 *        ces tests rougissent, c'est NORMAL : ils te disent que la carte mémoire a changé.
 *   3. DE BOUT EN BOUT : de vrais OCTETS de paquets → parse() → ft_process(, g_now) → on lit la table.
 *        C'est le chemin exact que fera le moteur de capture.
 *
 * Lancer : ./run_tests.sh integration
 */
#include "test_common.h"
#include "test_packets.h"
#include <stddef.h>
#include "parser/parser.h"
#include "flows/flow.h"
#include "flows/flow_table.h"
#include "dict/dict.h"
#include "dchained_list/dchained_list.h"
#include "portmap/portmap.h"
#include "rules/rules.h"

/* ═══════════════════════════ fabrique de VRAIS paquets (en octets) ═══════════════════════════ */

static uint64_t g_now = 1000000;   /* fausse heure (ms) : les tests la font avancer à la main */

static const uint8_t MAC_DST[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t MAC_SRC[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};

static void put_eth(uint8_t *b, uint16_t type) {
    memcpy(b, MAC_DST, 6);
    memcpy(b + 6, MAC_SRC, 6);
    pk_put16(b + 12, type);
}

/* Ethernet (14) + IPv4 (20) + TCP (20) = 54 octets */
static int tcp4_pkt(uint8_t *b, const uint8_t *src, uint16_t sp, const uint8_t *dst, uint16_t dp, uint8_t flags) {
    memset(b, 0, 54);
    put_eth(b, 0x0800);
    b[14] = 0x45;                 /* version 4, IHL 5 */
    pk_put16(b + 16, 40);         /* longueur totale IP = 20 + 20 */
    b[22] = 64;                   /* TTL */
    b[23] = 6;                    /* proto TCP */
    memcpy(b + 26, src, 4);
    memcpy(b + 30, dst, 4);
    pk_put16(b + 34, sp);
    pk_put16(b + 36, dp);
    b[46] = 0x50;                 /* data offset 5 → 20 octets */
    b[47] = flags;
    return 54;
}

/* Ethernet (14) + IPv4 (20) + UDP (8) = 42 octets */
static int udp4_pkt(uint8_t *b, const uint8_t *src, uint16_t sp, const uint8_t *dst, uint16_t dp) {
    memset(b, 0, 42);
    put_eth(b, 0x0800);
    b[14] = 0x45;
    pk_put16(b + 16, 28);
    b[22] = 64;
    b[23] = 17;                   /* proto UDP */
    memcpy(b + 26, src, 4);
    memcpy(b + 30, dst, 4);
    pk_put16(b + 34, sp);
    pk_put16(b + 36, dp);
    pk_put16(b + 38, 8);
    return 42;
}

/* Ethernet (14) + IPv6 (40) + TCP (20) = 74 octets. Les IP sont 2001:db8::<dernier octet>. */
static int tcp6_pkt(uint8_t *b, uint8_t src_last, uint16_t sp, uint8_t dst_last, uint16_t dp, uint8_t flags) {
    memset(b, 0, 74);
    put_eth(b, 0x86DD);
    b[14] = 0x60;                 /* version 6 */
    pk_put16(b + 18, 20);         /* payload length */
    b[20] = 6;                    /* next header = TCP */
    b[21] = 64;                   /* hop limit */
    pk_ip6(b + 22, src_last);
    pk_ip6(b + 38, dst_last);
    pk_put16(b + 54, sp);
    pk_put16(b + 56, dp);
    b[66] = 0x50;
    b[67] = flags;
    return 74;
}

/* Ethernet (14) + IPv6 (40) + ICMPv6 echo request (8) = 62 octets */
static int icmp6_pkt(uint8_t *b, uint8_t src_last, uint8_t dst_last) {
    memset(b, 0, 62);
    put_eth(b, 0x86DD);
    b[14] = 0x60;
    pk_put16(b + 18, 8);
    b[20] = 58;                   /* next header = ICMPv6 */
    b[21] = 64;
    pk_ip6(b + 22, src_last);
    pk_ip6(b + 38, dst_last);
    b[54] = 128;                  /* echo request */
    return 62;
}

/* Ethernet (14) + ARP (28) = 42 octets : « qui a 10.0.0.2 ? » */
static int arp_pkt(uint8_t *b) {
    memset(b, 0, 42);
    put_eth(b, 0x0806);
    pk_put16(b + 14, 1);          /* matériel : Ethernet */
    pk_put16(b + 16, 0x0800);     /* protocole : IPv4 */
    b[18] = 6; b[19] = 4;
    pk_put16(b + 20, 1);          /* 1 = demande */
    memcpy(b + 22, MAC_SRC, 6);
    memcpy(b + 28, IP4(10, 0, 0, 1), 4);
    memcpy(b + 38, IP4(10, 0, 0, 2), 4);
    return 42;
}

/* insère un tag VLAN 100 après les MAC : le paquet grandit de 4 octets */
static int add_vlan(uint8_t *b, int n) {
    memmove(b + 16, b + 12, (size_t)(n - 12));
    b[12] = 0x81; b[13] = 0x00; b[14] = 0x00; b[15] = 0x64;
    return n + 4;
}

/* bourrage Ethernet : une trame fait au moins 60 octets, la carte réseau ajoute des 0 */
static int pad_to_60(uint8_t *b, int n) {
    if (n < 60) { memset(b + n, 0, (size_t)(60 - n)); return 60; }
    return n;
}

/* octets → parse → ft_process (le chemin complet) */
static int feed(FlowTable *ft, const uint8_t *b, int n) {
    ParserResult pr = parse(b, n);
    return ft_process(ft, &pr, g_now);
}

/* retrouve la fiche d'un paquet dans la table (NULL si le flux n'existe pas) */
static FlowEntry *flow_of(FlowTable *ft, const uint8_t *b, int n) {
    ParserResult pr = parse(b, n);
    PacketTuple t;
    if (pr_tuple(&pr, &t) != 0) return NULL;
    union { FlowKeyIpv4 k4; FlowKeyIpv6 k6; } key;
    if (build_flow_key(&key, t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.proto, t.v4) != 0) return NULL;
    return ft_get(ft, &key);
}

static struct PortMap *portmap_v4(FlowTable *ft, const uint8_t ip[4]) {
    struct PortPerIpKey k;
    memset(&k, 0, sizeof k);
    k.v4 = 1;
    memcpy(k.ip, ip, 4);
    return (struct PortMap *)dict_getitem(ft -> port_per_ip, &k);
}

/* ═══════════════════════════ 1. CONVENTIONS ═══════════════════════════ */

static void t_conv_actions_echec(void) {
    /* action → -1 quand les arguments sont mauvais */
    uint8_t ip[4] = {1, 2, 3, 4}, p[2] = {0, 80};
    FlowKeyIpv4 k;
    FlowEntry e;
    ParserResult pr = pk_tcp4(IP4(10, 0, 0, 1), 1, IP4(10, 0, 0, 2), 2, SYN);
    CHECK_EQ(build_flow_key(NULL, ip, ip, p, p, 6, 1), -1, "build_flow_key(NULL)");
    CHECK_EQ(build_flow_entry(NULL, &pr, &k, 1, g_now), -1, "build_flow_entry(NULL, g_now)");
    CHECK_EQ(entry_update(NULL, &pr, g_now), -1, "entry_update(NULL, g_now)");
    CHECK_EQ(pr_tuple(NULL, NULL), -1, "pr_tuple(NULL)");
    CHECK_EQ(ft_add(NULL, &k, &e), -1, "ft_add(NULL)");
    CHECK_EQ(ft_process(NULL, &pr, g_now), -1, "ft_process(NULL, g_now)");
    CHECK_EQ(dict_setitem(NULL, &k, &e), -1, "dict_setitem(NULL)");
    CHECK_EQ(dict_delitem(NULL, &k), -1, "dict_delitem(NULL)");
    CHECK_EQ(add_to_end(NULL, &e, 0), -1, "add_to_end(NULL)");
    CHECK_EQ(add_to_top(NULL, &e, 0), -1, "add_to_top(NULL)");
    CHECK_EQ(move_to_end(NULL, &e), -1, "move_to_end(NULL)");
    CHECK_EQ(move_to_top(NULL, &e), -1, "move_to_top(NULL)");
    CHECK_EQ(delete_from_end(NULL), -1, "delete_from_end(NULL)");
    CHECK_EQ(delete_from_top(NULL), -1, "delete_from_top(NULL)");
}

static void t_conv_actions_succes(void) {
    /* action → 0 quand tout va bien */
    FlowTable *ft = ft_create(8);
    CHECK(ft != NULL, "ft_create");
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, SYN);
    CHECK_EQ(feed(ft, b, n), 0, "ft_process : nouveau flux → 0");
    CHECK_EQ(feed(ft, b, n), 0, "ft_process : flux existant → 0");
    ParserResult pr = parse(b, n);
    PacketTuple t;
    CHECK_EQ(pr_tuple(&pr, &t), 0, "pr_tuple → 0");
    uint8_t kbuf[64];
    CHECK_EQ(build_flow_key(kbuf, t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.proto, t.v4), 0, "build_flow_key → 0");
    ft_destroy(ft);

    Dict *d = create_dict_int(8);
    int key = 7, val = 1;
    CHECK_EQ(dict_setitem(d, &key, &val), 0, "dict_setitem → 0");
    CHECK_EQ(dict_delitem(d, &key), 0, "dict_delitem (présent) → 0");
    CHECK_EQ(dict_delitem(d, &key), -1, "dict_delitem (absent) → -1");
    dict_clear(d);

    DChainedList *dcl = create_dcl(0);
    CHECK_EQ(delete_from_top(dcl), 0, "delete_from_top sur liste VIDE → 0 (pas une erreur)");
    CHECK_EQ(delete_from_end(dcl), 0, "delete_from_end sur liste VIDE → 0 (pas une erreur)");
    free(dcl);
}

static void t_conv_questions_oui_non(void) {
    /* question → exactement 1 ou 0, jamais -1 */
    FlowTable *ft = ft_create(2);
    uint8_t b1[128], b2[128], b3[128];
    int n1 = tcp4_pkt(b1, IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, SYN);
    int n2 = tcp4_pkt(b2, IP4(10, 0, 0, 1), 1001, IP4(10, 0, 0, 2), 80, SYN);
    int n3 = tcp4_pkt(b3, IP4(10, 0, 0, 1), 1002, IP4(10, 0, 0, 2), 80, SYN);

    CHECK_EQ(ft_can_add(ft), 1, "table vide : ft_can_add == 1");
    CHECK_EQ(ft_contains(ft, &(FlowKeyIpv4){0}), 0, "ft_contains(absent) == 0");
    feed(ft, b1, n1);
    CHECK_EQ(ft_can_add(ft), 1, "1 flux sur 2 : ft_can_add == 1");
    feed(ft, b2, n2);
    CHECK_EQ(ft_can_add(ft), 0, "2 flux sur 2 : ft_can_add == 0");
    FlowEntry *e = flow_of(ft, b1, n1);
    CHECK(e != NULL, "flux 1 présent");
    if (e) CHECK_EQ(ft_contains(ft, e -> key), 1, "ft_contains(présent) == 1");
    CHECK_EQ(ft_contains(NULL, NULL), 0, "ft_contains(NULL) == 0");
    CHECK_EQ(ft_can_add(NULL), 0, "ft_can_add(NULL) == 0");
    feed(ft, b3, n3);   /* la table est pleine : éviction */
    CHECK_EQ(ft_can_add(ft), 0, "toujours pleine après éviction");
    ft_destroy(ft);

    struct PortMap pm;
    portmap_init(&pm);
    CHECK_EQ(portmap_add(&pm, 80), 1, "portmap_add(nouveau) == 1");
    CHECK_EQ(portmap_add(&pm, 80), 0, "portmap_add(déjà vu) == 0");
    CHECK_EQ(portmap_test(&pm, 80), 1, "portmap_test(vu) == 1");
    CHECK_EQ(portmap_test(&pm, 81), 0, "portmap_test(pas vu) == 0");
}

static void t_conv_comparaisons(void) {
    /* comparaison → 0 = égaux, autre chose = différents (comme memcmp) */
    FlowKeyIpv4 a, b, c;
    uint8_t p80[2] = {0, 80}, p81[2] = {0, 81};
    build_flow_key(&a, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), p80, p81, 6, 1);
    build_flow_key(&b, IP4(10, 0, 0, 2), IP4(10, 0, 0, 1), p81, p80, 6, 1);   /* sens inverse = même clé */
    build_flow_key(&c, IP4(10, 0, 0, 1), IP4(10, 0, 0, 3), p80, p81, 6, 1);
    CHECK_EQ(flow_key_compare(&a, &b), 0, "même conversation, sens inverse → 0");
    CHECK(flow_key_compare(&a, &c) != 0, "conversations différentes → non nul");
    CHECK(flow_key_compare(&a, NULL) != 0, "NULL → non nul");
    int x = 5, y = 5, z = 6;
    Dict *d = create_dict_int(4);
    CHECK_EQ(d -> compare(&x, &y), 0, "dict int : 5 contre 5 → 0");
    CHECK(d -> compare(&x, &z) != 0, "dict int : 5 contre 6 → non nul");
    dict_clear(d);
}

static void t_conv_pointeurs_null(void) {
    /* pointeur → NULL = absent ou échec */
    FlowTable *ft = ft_create(4);
    FlowKeyIpv4 absent;
    uint8_t p[2] = {0, 1};
    build_flow_key(&absent, IP4(1, 1, 1, 1), IP4(2, 2, 2, 2), p, p, 6, 1);
    CHECK(ft_get(ft, &absent) == NULL, "ft_get(absent) == NULL");
    CHECK(ft_get(NULL, &absent) == NULL, "ft_get(NULL, key) == NULL");
    CHECK(ft_create(0) == NULL, "ft_create(0) == NULL");
    CHECK(flow_key_dup(NULL) == NULL, "flow_key_dup(NULL) == NULL");
    FlowKeyType mauvais = (FlowKeyType)99;
    CHECK(flow_key_dup(&mauvais) == NULL, "flow_key_dup(type inconnu) == NULL");
    DChainedList *dcl = create_dcl(0);
    CHECK(dcl != NULL, "create_dcl → pas NULL");
    free(dcl);
    ft_destroy(ft);
    Dict *d = create_dict_int(4);
    int k = 1;
    CHECK(dict_getitem(d, &k) == NULL, "dict_getitem(absent) == NULL");
    dict_clear(d);
}

static void t_conv_drapeau_v4(void) {
    /* drapeau v4 : 1 = IPv4, 0 = IPv6, partout */
    uint8_t b4[128], b6[128];
    int n4 = tcp4_pkt(b4, IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, SYN);
    int n6 = tcp6_pkt(b6, 1, 1000, 2, 80, SYN);
    PacketTuple t;
    ParserResult p4 = parse(b4, n4), p6 = parse(b6, n6);
    CHECK_EQ(pr_tuple(&p4, &t), 0, "pr_tuple v4");
    CHECK_EQ(t.v4, 1, "pr_tuple : IPv4 → v4 == 1");
    CHECK_EQ(pr_tuple(&p6, &t), 0, "pr_tuple v6");
    CHECK_EQ(t.v4, 0, "pr_tuple : IPv6 → v4 == 0");

    uint8_t ab[128];
    int na = arp_pkt(ab);
    ParserResult pa = parse(ab, na);
    CHECK_EQ(pa.code, SUCCES, "ARP bien parsé");
    CHECK_EQ(pr_tuple(&pa, &t), -1, "pr_tuple : ARP n'a pas d'IP → -1");

    FlowTable *ft = ft_create(8);
    feed(ft, b4, n4);
    feed(ft, b6, n6);
    FlowEntry *e4 = flow_of(ft, b4, n4), *e6 = flow_of(ft, b6, n6);
    CHECK(e4 && e6, "les deux flux existent");
    if (e4 && e6) {
        CHECK_EQ(e4 -> data -> v4, 1, "FlowData.v4 == 1 pour IPv4");
        CHECK_EQ(e6 -> data -> v4, 0, "FlowData.v4 == 0 pour IPv6");
        CHECK_EQ(*(FlowKeyType *)e4 -> key, FlowKeyIpv4Type, "clé du flux v4 : type IPv4");
        CHECK_EQ(*(FlowKeyType *)e6 -> key, FlowKeyIpv6Type, "clé du flux v6 : type IPv6");
    }
    ft_destroy(ft);
}

static void t_conv_codes_du_parser(void) {
    /* parser : 0 = tout va bien, les erreurs sont des nombres > 0 tous différents */
    CHECK_EQ(SUCCES, 0, "SUCCES == 0");
    int codes[] = {ERROR, TOO_LITTLE, INCOHERENCE, NOT_HANDLE, FRAGMENT};
    for (int i = 0; i < 5; i++) {
        CHECK(codes[i] > 0, "code d'erreur > 0");
        for (int j = i + 1; j < 5; j++) CHECK(codes[i] != codes[j], "codes tous différents");
    }
}

/* ═══════════════════════════ 2. MÉMOIRE ═══════════════════════════ */

static void t_mem_parser_result(void) {
    CHECK_EQ(sizeof(ParserResult), 92, "sizeof(ParserResult)");
    CHECK_EQ(offsetof(ParserResult, len), 0, "len à 0");
    CHECK_EQ(offsetof(ParserResult, code), 4, "code à 4 (puis 3 octets de remplissage)");
    CHECK_EQ(offsetof(ParserResult, n_vlan), 8, "n_vlan à 8 (aligné sur 4)");
    CHECK_EQ(offsetof(ParserResult, ip_start), 12, "ip_start à 12");
    CHECK_EQ(offsetof(ParserResult, type), 16, "type à 16");
    CHECK_EQ(offsetof(ParserResult, ihl), 18, "ihl à 18");
    CHECK_EQ(offsetof(ParserResult, version), 19, "version à 19");
    CHECK_EQ(offsetof(ParserResult, src_mac), 20, "src_mac à 20");
    CHECK_EQ(offsetof(ParserResult, dst_mac), 26, "dst_mac à 26");
    CHECK_EQ(offsetof(ParserResult, ip_data), 32, "ip_data (union) à 32");
    CHECK_EQ(offsetof(ParserResult, data), 68, "data (union) à 68 (33 + 3 de remplissage)");
}

static void t_mem_unions_du_parser(void) {
    ParserResult r;
    /* union ip_data : taille = le plus grand membre (IPv6 = 33), et tous les membres commencent au même endroit */
    CHECK_EQ(sizeof(r.ip_data), 33, "sizeof(ip_data) == sizeof(IPV6_DATA) == 33");
    CHECK_EQ(sizeof(IPV4_DATA), 9, "sizeof(IPV4_DATA)");
    CHECK_EQ(sizeof(IPV6_DATA), 33, "sizeof(IPV6_DATA)");
    CHECK_PTR(&r.ip_data.ipv4, &r.ip_data.ipv6, "ipv4 et ipv6 commencent à la même adresse");
    /* union data : taille = le plus grand membre (ARP = 22, arrondi à 24 pour l'alignement de ICMP_DATA) */
    CHECK_EQ(sizeof(r.data), 24, "sizeof(data)");
    CHECK_EQ(sizeof(ARP_DATA), 22, "sizeof(ARP_DATA)");
    CHECK_EQ(sizeof(ICMP_DATA), 8, "sizeof(ICMP_DATA)");
    CHECK_EQ(sizeof(TCP_DATA), 5, "sizeof(TCP_DATA)");
    CHECK_EQ(sizeof(UDP_DATA), 4, "sizeof(UDP_DATA)");
    CHECK_PTR(&r.data.tcp, &r.data.udp, "tcp et udp au même endroit");
    CHECK_PTR(&r.data.tcp, &r.data.icmp, "tcp et icmp au même endroit");
    CHECK_PTR(&r.data.tcp, &r.data.arp, "tcp et arp au même endroit");

    /* écrire dans un membre = écraser les octets de l'autre */
    memset(&r, 0, sizeof r);
    r.ip_data.ipv4.src_ip[0] = 10; r.ip_data.ipv4.src_ip[3] = 1;
    CHECK_EQ(r.ip_data.ipv6.src_ip[0], 10, "union : l'octet 0 d'ipv4 est AUSSI l'octet 0 d'ipv6");
    CHECK_EQ(r.ip_data.ipv6.src_ip[3], 1, "union : l'octet 3 aussi");
    memset(&r, 0, sizeof r);
    r.data.tcp.src_port[0] = 0x1F; r.data.tcp.src_port[1] = 0x90;
    CHECK_EQ(r.data.udp.src_port[0], 0x1F, "tcp.src_port et udp.src_port partagent leurs octets");
    CHECK_EQ(r.data.udp.src_port[1], 0x90, "idem octet 1");
}

static void t_mem_flow(void) {
    CHECK_EQ(sizeof(FlowKeyType), 4, "enum = 4 octets");
    CHECK_EQ(sizeof(FlowKeyIpv4), 20, "sizeof(FlowKeyIpv4)");
    CHECK_EQ(sizeof(FlowKeyIpv6), 44, "sizeof(FlowKeyIpv6)");
    CHECK_EQ(offsetof(FlowKeyIpv4, key), 0, "FlowKeyIpv4.key EN PREMIER (pour lire le type depuis un void *)");
    CHECK_EQ(offsetof(FlowKeyIpv6, key), 0, "FlowKeyIpv6.key EN PREMIER");
    CHECK_EQ(offsetof(FlowKeyIpv4, ip_min), 4, "FlowKeyIpv4.ip_min à 4");
    CHECK_EQ(offsetof(FlowKeyIpv6, ip_min), 4, "FlowKeyIpv6.ip_min à 4");
    CHECK_EQ(sizeof(FlowData), 120, "sizeof(FlowData)");
    CHECK_EQ(offsetof(FlowData, v4), 0, "FlowData.v4 à 0");
    CHECK_EQ(offsetof(FlowData, header), 1, "FlowData.header (union) à 1 : tout est en uint8_t, pas d'alignement");
    CHECK_EQ(sizeof(struct Ipv4EntryData), 12, "sizeof(Ipv4EntryData)");
    CHECK_EQ(sizeof(struct Ipv6EntryData), 36, "sizeof(Ipv6EntryData)");
    CHECK_EQ(offsetof(FlowData, start_time), 40, "start_time à 40 (aligné sur 8 : 1 + 36 = 37 → 40)");
    CHECK_EQ(offsetof(FlowData, flag_count), 56, "flag_count à 56");
    CHECK_EQ(sizeof(struct _FlagSeens), 32, "8 compteurs de 4 octets");
    CHECK_EQ(offsetof(FlowData, n_pkt_ltr), 88, "n_pkt_ltr à 88");
    CHECK_EQ(offsetof(FlowData, octets_data_ltr), 96, "octets_data_ltr à 96 (uint64, aligné sur 8)");
    CHECK_EQ(offsetof(FlowData, octets_data_rtl), 104, "octets_data_rtl à 104");
    CHECK_EQ(offsetof(FlowData, proto), 112, "proto à 112");
    CHECK_EQ(offsetof(FlowData, rule_reason), 113, "rule_reason à 113 : dans le remplissage entre proto et verdict");
    CHECK_EQ(offsetof(FlowData, verdict), 116, "verdict à 116 (rule_reason n'a pas bougé la mémoire)");
    CHECK_EQ(sizeof(FlowRuleResult), 8, "FlowRuleResult = verdict + reason (2 enums de 4 octets)");
    CHECK(RULE_COUNT <= 256, "les règles tiennent dans un uint8_t");
    CHECK_EQ(sizeof(FlowRecord), 176, "sizeof(FlowRecord) : clé 44 + remplissage 4 + FlowData 120 + reason 4 + remplissage 4");
    CHECK_EQ(offsetof(FlowRecord, data), 48, "FlowRecord.data à 48");
    CHECK_EQ(offsetof(FlowRecord, reason), 168, "FlowRecord.reason à 168");
    CHECK_EQ(sizeof(FlowEntry), 40, "sizeof(FlowEntry)");
    CHECK_EQ(offsetof(FlowEntry, data), 8, "FlowEntry.data à 8");
    CHECK_EQ(offsetof(FlowEntry, lru_prev), 16, "FlowEntry.lru_prev à 16");

    FlowData d;
    CHECK_PTR(&d.header.ipv4_headers, &d.header.ipv6_headers, "header : v4 et v6 au même endroit");
    CHECK_EQ(sizeof(d.header), 36, "header = le plus grand des deux (v6 = 36)");
}

static void t_mem_table_dict_portmap(void) {
    CHECK_EQ(sizeof(FlowTable), 120, "sizeof(FlowTable)");
    CHECK_EQ(offsetof(FlowTable, hooks), 48, "hooks à 48 (n_blocked_flows est venu s'ajouter avant)");
    CHECK_EQ(offsetof(FlowTable, blocklist), 104, "blocklist (pointeur vers la liste noire) à 104");
    CHECK_EQ(offsetof(FlowTable, reader), 112, "reader à 112");
    CHECK_EQ(sizeof(struct FlowHooks), 56, "sizeof(FlowHooks) : idle_ms 8, max_ms 8, close_on_tcp_end 1 + 7 de remplissage, 4 pointeurs de 8 (check, rules_cfg, sink, ctx)");
    CHECK_EQ(sizeof(DChainedList), 24, "sizeof(DChainedList)");
    CHECK_EQ(sizeof(Dict), 72, "sizeof(Dict)");
    CHECK_EQ(sizeof(Entry), 32, "sizeof(Entry) du dict");
    CHECK_EQ(sizeof(struct PortMap), 8200, "sizeof(PortMap) = 8192 + 4 + 4");
    CHECK_EQ(sizeof(struct PortPerIpKey), 20, "sizeof(PortPerIpKey) : 16 + 1 + 3 de pad, sans trou caché");
    CHECK_EQ(offsetof(struct PortPerIpKey, v4), 16, "PortPerIpKey.v4 à 16");
}

static void t_mem_valeurs_des_enums(void) {
    CHECK_EQ(IPV4, 0x0800, "IPV4 = 0x0800");
    CHECK_EQ(IPV6, 0x86DD, "IPV6 = 0x86DD");
    CHECK_EQ(ARP, 0x0806, "ARP = 0x0806");
    CHECK_EQ(VLAN, 0x8100, "VLAN = 0x8100");
    CHECK_EQ(QINQ, 0x88A8, "QINQ = 0x88A8");
    CHECK_EQ(TCP, 6, "TCP = 6");
    CHECK_EQ(UDP, 17, "UDP = 17");
    CHECK_EQ(ICMP, 1, "ICMP = 1");
    CHECK_EQ(ICMPV6, 58, "ICMPV6 = 58");
    CHECK_EQ(FIN, 0x01, "FIN = bit 0");
    CHECK_EQ(SYN, 0x02, "SYN = bit 1");
    CHECK_EQ(RST, 0x04, "RST = bit 2");
    CHECK_EQ(PSH, 0x08, "PSH = bit 3");
    CHECK_EQ(ACK, 0x10, "ACK = bit 4");
    CHECK_EQ(URG, 0x20, "URG = bit 5");
    CHECK_EQ(ECE, 0x40, "ECE = bit 6");
    CHECK_EQ(CWR, 0x80, "CWR = bit 7");
    CHECK_EQ(FlowKeyIpv4Type, 0, "FlowKeyIpv4Type = 0 (1re valeur d'un enum)");
    CHECK_EQ(FlowKeyIpv6Type, 1, "FlowKeyIpv6Type = 1");
    CHECK_EQ(UNKNOW, 0, "UNKNOW = 0");
    CHECK_EQ(BLOCK, 1, "BLOCK = 1");
    CHECK_EQ(LIMIT_REACHED, 2, "LIMIT_REACHED = 2");
}

/* ═══════════════════════════ 3. DE BOUT EN BOUT (vrais octets) ═══════════════════════════ */

static void t_e2e_poignee_de_main_tcp(void) {
    FlowTable *ft = ft_create(16);
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 50000, IP4(10, 0, 0, 2), 80, SYN);
    CHECK_EQ(feed(ft, b, n), 0, "SYN");
    uint8_t first[128]; memcpy(first, b, (size_t)n); int n_first = n;
    n = tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 50000, SYN | ACK);
    CHECK_EQ(feed(ft, b, n), 0, "SYN-ACK");
    n = tcp4_pkt(b, IP4(10, 0, 0, 1), 50000, IP4(10, 0, 0, 2), 80, ACK);
    CHECK_EQ(feed(ft, b, n), 0, "ACK");

    CHECK_EQ(ft -> nbr_elements, 1, "les 3 paquets = UN seul flux");
    FlowEntry *e = flow_of(ft, first, n_first);
    CHECK(e != NULL, "le flux est retrouvable");
    if (e) {
        FlowData *d = e -> data;
        CHECK_EQ(d -> n_pkt_ltr, 2, "SYN et ACK vont de l'initiateur vers le receveur");
        CHECK_EQ(d -> n_pkt_rtl, 1, "SYN-ACK va dans l'autre sens");
        CHECK_EQ(d -> flag_count.syn, 2, "SYN vu 2 fois (SYN et SYN-ACK)");
        CHECK_EQ(d -> flag_count.ack, 2, "ACK vu 2 fois (SYN-ACK et ACK)");
        CHECK_EQ(d -> flag_count.fin, 0, "pas de FIN");
        CHECK_EQ(d -> proto, TCP, "proto TCP");
        CHECK_MEM(d -> header.ipv4_headers.initiator_ip, IP4(10, 0, 0, 1), 4, "initiateur = celui du SYN");
        CHECK_EQ(port_to_u16(d -> header.ipv4_headers.initiator_port), 50000, "port initiateur");
        CHECK_EQ(port_to_u16(d -> header.ipv4_headers.receiver_port), 80, "port receveur");
        CHECK_EQ(d -> verdict, UNKNOW, "verdict inconnu au départ");
        CHECK(d -> start_time > 0, "start_time rempli");
    }
    ft_destroy(ft);
}

static void t_e2e_meme_flux_vlan_et_bourrage(void) {
    /* le même paquet, avec un tag VLAN, avec du bourrage Ethernet : TOUJOURS le même flux */
    FlowTable *ft = ft_create(16);
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 50000, IP4(10, 0, 0, 2), 80, ACK);
    CHECK_EQ(feed(ft, b, n), 0, "paquet nu");

    int nv = add_vlan(b, n);
    ParserResult pv = parse(b, nv);
    CHECK_EQ(pv.n_vlan, 1, "1 tag VLAN vu");
    CHECK_EQ(pv.ip_start, 18, "l'IP commence à 18 avec un tag");
    CHECK_EQ(ft_process(ft, &pv, g_now), 0, "paquet avec VLAN");

    n = tcp4_pkt(b, IP4(10, 0, 0, 1), 50000, IP4(10, 0, 0, 2), 80, ACK);
    n = pad_to_60(b, n);
    CHECK_EQ(n, 60, "bourrage jusqu'à 60");
    CHECK_EQ(feed(ft, b, n), 0, "paquet avec bourrage");

    CHECK_EQ(ft -> nbr_elements, 1, "toujours UN flux");
    FlowEntry *e = flow_of(ft, b, n);
    if (e) CHECK_EQ(e -> data -> n_pkt_ltr, 3, "3 paquets comptés");
    ft_destroy(ft);
}

static void t_e2e_paquets_refuses(void) {
    FlowTable *ft = ft_create(16);
    uint8_t b[128];
    int n;

    n = arp_pkt(b);
    CHECK_EQ(feed(ft, b, n), -1, "ARP : parsé mais pas un flux IP → -1");

    n = tcp4_pkt(b, IP4(10, 0, 0, 1), 1, IP4(10, 0, 0, 2), 2, SYN);
    CHECK_EQ(feed(ft, b, 20), -1, "paquet coupé (20 octets) → -1");
    CHECK_EQ(feed(ft, b, 10), -1, "paquet minuscule (10 octets) → -1");
    CHECK_EQ(feed(ft, NULL, 54), -1, "pkt NULL → -1");

    n = tcp4_pkt(b, IP4(10, 0, 0, 1), 1, IP4(10, 0, 0, 2), 2, SYN);
    b[22 - 16] = 0;                       /* octet de TTL, sans importance */
    pk_put16(b + 20, 0x00B9);             /* décalage de fragment != 0 : pas le 1er fragment */
    CHECK_EQ(feed(ft, b, n), -1, "fragment IPv4 → -1");

    memset(b, 0xFF, 60);
    CHECK_EQ(feed(ft, b, 60), -1, "octets au hasard → -1");

    n = tcp4_pkt(b, IP4(10, 0, 0, 1), 1, IP4(10, 0, 0, 2), 2, SYN);
    b[14] = 0x44;                         /* IHL = 4 : impossible */
    CHECK_EQ(feed(ft, b, n), -1, "IHL < 5 → -1");

    CHECK_EQ(ft -> nbr_elements, 0, "aucun de ces paquets n'a créé de flux");
    ft_destroy(ft);
}

static void t_e2e_ipv6_et_icmpv6(void) {
    FlowTable *ft = ft_create(16);
    uint8_t b[128];
    int n = tcp6_pkt(b, 1, 40000, 2, 443, SYN);
    CHECK_EQ(feed(ft, b, n), 0, "TCP IPv6");
    FlowEntry *e = flow_of(ft, b, n);
    CHECK(e != NULL, "flux v6 retrouvé");
    if (e) {
        CHECK_EQ(e -> data -> v4, 0, "FlowData.v4 == 0");
        CHECK_EQ(port_to_u16(e -> data -> header.ipv6_headers.receiver_port), 443, "port receveur 443");
        CHECK_EQ(e -> data -> header.ipv6_headers.initiator_ip[15], 1, "initiateur 2001:db8::1");
        CHECK_EQ(e -> data -> flag_count.syn, 1, "1 SYN");
    }
    n = tcp6_pkt(b, 2, 443, 1, 40000, SYN | ACK);
    CHECK_EQ(feed(ft, b, n), 0, "réponse IPv6");
    if (e) CHECK_EQ(e -> data -> n_pkt_rtl, 1, "la réponse est comptée rtl");

    n = icmp6_pkt(b, 1, 2);
    ParserResult pr = parse(b, n);
    CHECK_EQ(pr.code, SUCCES, "ICMPv6 bien parsé (58)");
    CHECK_EQ(pr.data.icmp.type, 128, "echo request");
    CHECK_EQ(ft_process(ft, &pr, g_now), 0, "ICMPv6 → un flux (ports à 0)");
    CHECK_EQ(ft -> nbr_elements, 2, "TCP + ICMPv6 = 2 flux");
    ft_destroy(ft);
}

static void t_e2e_scan_de_ports(void) {
    FlowTable *ft = ft_create(64);
    uint8_t b[128];
    for (int p = 1000; p < 1030; p++) {
        int n = tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), (uint16_t)p, SYN);
        CHECK_EQ(feed(ft, b, n), 0, "SYN du scanner");
    }
    CHECK_EQ(ft -> nbr_elements, 30, "30 ports = 30 flux");
    struct PortMap *pm = portmap_v4(ft, IP4(10, 9, 9, 9));
    CHECK(pm != NULL, "le scanner a une PortMap");
    if (pm) {
        CHECK_EQ(pm -> count, 30, "30 ports distincts visités");
        CHECK_EQ(pm -> refcount, 30, "30 flux s'appuient sur cette IP");
        CHECK_EQ(portmap_test(pm, 1000), 1, "port 1000 vu");
        CHECK_EQ(portmap_test(pm, 1029), 1, "port 1029 vu");
        CHECK_EQ(portmap_test(pm, 1030), 0, "port 1030 pas vu");
        CHECK_EQ(portmap_test(pm, 40000), 0, "le port SOURCE n'est pas noté");
    }
    CHECK(portmap_v4(ft, IP4(10, 0, 0, 2)) == NULL, "la victime n'a pas de PortMap (elle n'initie rien)");
    ft_destroy(ft);
}

static void t_e2e_v4_et_v6_ne_se_melangent_pas(void) {
    /* IP v4 10.0.0.1 → octets 0a 00 00 01 ; l'IPv6 0a00:0001:: commence par les mêmes 4 octets.
       Seul le drapeau v4 les distingue dans port_per_ip. */
    FlowTable *ft = ft_create(8);
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 2), 80, SYN);
    CHECK_EQ(feed(ft, b, n), 0, "flux IPv4");

    ParserResult p6 = pk_tcp6((const uint8_t[16]){0x0a, 0x00, 0x00, 0x01}, 1000,
                              (const uint8_t[16]){0x0a, 0x00, 0x00, 0x02}, 80, SYN);
    CHECK_EQ(ft_process(ft, &p6, g_now), 0, "flux IPv6 aux mêmes 4 premiers octets");
    CHECK_EQ(ft -> nbr_elements, 2, "deux flux distincts");
    CHECK_EQ(ft -> port_per_ip -> nbr_elements, 2, "deux PortMap distinctes");
    ft_destroy(ft);
}

static void t_e2e_eviction_et_refcount(void) {
    FlowTable *ft = ft_create(4);
    int n[10];
    uint8_t pkts[10][128];
    for (int i = 0; i < 10; i++) {
        n[i] = tcp4_pkt(pkts[i], IP4(10, 0, 0, 1), (uint16_t)(2000 + i), IP4(10, 0, 0, 2), 80, SYN);
        CHECK_EQ(feed(ft, pkts[i], n[i]), 0, "ft_process");
    }
    CHECK_EQ(ft -> nbr_elements, 4, "la table garde 4 flux");
    CHECK_EQ(ft -> n_evicted, 6, "6 flux chassés");
    CHECK(flow_of(ft, pkts[0], n[0]) == NULL, "le plus ancien est parti");
    CHECK(flow_of(ft, pkts[5], n[5]) == NULL, "le 6e est parti");
    CHECK(flow_of(ft, pkts[6], n[6]) != NULL, "le 7e est là");
    CHECK(flow_of(ft, pkts[9], n[9]) != NULL, "le dernier est là");
    struct PortMap *pm = portmap_v4(ft, IP4(10, 0, 0, 1));
    CHECK(pm != NULL, "la PortMap existe encore (4 flux vivants)");
    if (pm) CHECK_EQ(pm -> refcount, 4, "refcount == nombre de flux vivants");
    ft_destroy(ft);
}

static void t_e2e_portmap_liberee_avec_le_dernier_flux(void) {
    FlowTable *ft = ft_create(2);
    uint8_t a1[128], a2[128], b1[128], b2[128];
    int na1 = tcp4_pkt(a1, IP4(10, 0, 0, 1), 1000, IP4(10, 0, 0, 9), 80, SYN);
    int na2 = tcp4_pkt(a2, IP4(10, 0, 0, 1), 1001, IP4(10, 0, 0, 9), 80, SYN);
    int nb1 = tcp4_pkt(b1, IP4(10, 0, 0, 2), 1000, IP4(10, 0, 0, 9), 80, SYN);
    int nb2 = tcp4_pkt(b2, IP4(10, 0, 0, 2), 1001, IP4(10, 0, 0, 9), 80, SYN);
    feed(ft, a1, na1); feed(ft, a2, na2);
    CHECK(portmap_v4(ft, IP4(10, 0, 0, 1)) != NULL, "A a une PortMap");
    feed(ft, b1, nb1);                     /* chasse a1 : A garde 1 flux */
    CHECK(portmap_v4(ft, IP4(10, 0, 0, 1)) != NULL, "A garde sa PortMap (1 flux restant)");
    feed(ft, b2, nb2);                     /* chasse a2 : A n'a plus de flux */
    CHECK(portmap_v4(ft, IP4(10, 0, 0, 1)) == NULL, "A n'a plus de flux : PortMap libérée");
    CHECK(portmap_v4(ft, IP4(10, 0, 0, 2)) != NULL, "B a la sienne");
    ft_destroy(ft);
}

static void t_regression_ft_add_present_et_table_pleine(void) {
    /* avant la correction : ft_add chassait le plus ancien AVANT de regarder si la clé existait déjà,
       donc remettre un flux existant dans une table pleine pouvait chasser ce flux lui-même */
    FlowTable *ft = ft_create(3);
    uint8_t p[3][128];
    int n[3];
    for (int i = 0; i < 3; i++) {
        n[i] = tcp4_pkt(p[i], IP4(10, 0, 0, 1), (uint16_t)(3000 + i), IP4(10, 0, 0, 2), 80, SYN);
        feed(ft, p[i], n[i]);
    }
    FlowEntry *e0 = flow_of(ft, p[0], n[0]);
    CHECK(e0 != NULL, "flux 0 présent");
    CHECK_EQ(ft_can_add(ft), 0, "table pleine");
    if (e0) {
        CHECK_EQ(ft_add(ft, e0 -> key, e0), 0, "ft_add d'un flux déjà présent → 0");
        CHECK_EQ(ft -> n_evicted, 0, "rien n'a été chassé");
        CHECK_EQ(ft -> nbr_elements, 3, "toujours 3 flux");
        CHECK_PTR(ft -> flow_dcl -> tail, e0, "le flux 0 est passé en dernier");
    }
    ft_destroy(ft);
}

static void t_regression_evict_table_vide(void) {
    FlowTable *ft = ft_create(4);
    ft_evict_oldest(ft);
    CHECK_EQ(ft -> n_evicted, 0, "rien à chasser : compteur inchangé");
    CHECK_EQ(ft -> nbr_elements, 0, "table toujours vide");
    ft_evict_oldest(NULL);
    ft_destroy(ft);
}

static void t_fuites_beaucoup_de_paquets(void) {
    FlowTable *ft = ft_create(32);
    uint8_t b[128];
    for (int i = 0; i < 2000; i++) {
        int n;
        if (i % 3 == 0)      n = tcp4_pkt(b, IP4(10, 1, (uint8_t)(i >> 8), (uint8_t)i), (uint16_t)(1000 + i % 50), IP4(10, 0, 0, 2), 80, SYN);
        else if (i % 3 == 1) n = udp4_pkt(b, IP4(10, 2, (uint8_t)(i >> 8), (uint8_t)i), 5000, IP4(10, 0, 0, 3), 53);
        else                 n = tcp6_pkt(b, (uint8_t)i, (uint16_t)(2000 + i % 7), 9, 443, ACK);
        feed(ft, b, n);
    }
    CHECK(ft -> nbr_elements <= 32, "jamais plus de 32 flux");
    ft_destroy(ft);   /* RUN_LEAKS : ASan vérifie qu'il ne reste rien */
}


/* ═══════════════════════════ 4. TEMPS, EXPIRATION, SINK, LISTE NOIRE, RÈGLES ═══════════════════════════ */

struct Got { int n; FlowRecord rec[16]; };
static struct Got got;                       /* chaque test tourne dans son propre process : pas de mélange */
static void sink_collect(const FlowRecord *r, void *ctx) {
    struct Got *g = ctx;
    if (g -> n < 16) g -> rec[g -> n] = *r;
    g -> n++;
}
static RulesConfig g_rules;                  /* les réglages que la table lit ; les tests peuvent les changer « à chaud » */
static FlowTable *table_avec(uint32_t size, uint64_t idle_ms, uint8_t close_tcp, FlowRuleFn rule) {
    FlowTable *ft = ft_create(size);
    struct FlowHooks h = {0};
    rules_config_default(&g_rules);          /* défauts : toutes les règles actives, scan à 20 ports */
    h.idle_ms = idle_ms; h.close_on_tcp_end = close_tcp; h.check = rule; h.rules_cfg = &g_rules; h.sink = sink_collect; h.ctx = &got;
    ft_set_hooks(ft, &h);
    memset(&got, 0, sizeof got);
    return ft;
}
/* un SYN d'un client (src_port distinct = flux distinct) vers 10.0.0.2:80 */
static int syn(uint8_t *b, uint8_t host, uint16_t sp) {
    return tcp4_pkt(b, IP4(10, 0, 0, host), sp, IP4(10, 0, 0, 2), 80, SYN);
}

static void t_temps_et_octets(void) {
    FlowTable *ft = ft_create(8);
    uint8_t b[128];
    g_now = 1000;
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, SYN);
    uint8_t first[128]; memcpy(first, b, (size_t)n);
    feed(ft, b, n);
    g_now = 2500;
    int m = tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 5000, SYN | ACK);
    feed(ft, b, m);
    g_now = 4000;
    n = pad_to_60(first, n);                 /* même paquet, mais 60 octets (bourrage) */
    feed(ft, first, n);
    FlowEntry *e = flow_of(ft, first, n);
    CHECK(e != NULL, "flux présent");
    if (e) {
        FlowData *d = e -> data;
        CHECK_EQ(d -> start_time, 1000, "start_time = heure du 1er paquet");
        CHECK_EQ(d -> end_time, 4000, "end_time = heure du DERNIER paquet");
        CHECK_EQ(d -> octets_data_ltr, 54 + 60, "octets ltr = 54 (1er paquet) + 60 (3e)");
        CHECK_EQ(d -> octets_data_rtl, 54, "octets rtl = 54 (le SYN-ACK)");
        CHECK_EQ(sizeof(d -> octets_data_ltr), 8, "uint64 : pas de débordement à 4 Go");
    }
    ft_destroy(ft);
}

static void t_realtime_ms_lisible_par_python(void) {
    uint64_t a = realtime_ms();
    CHECK(a > 1700000000000ULL, "après 2023 : c'est bien une date depuis 1970, pas un compteur de démarrage");
    CHECK(a < 4000000000000ULL, "avant l'an 2096 (en ms)");
    CHECK(realtime_ms() >= a, "ne recule pas");
}

static void t_expire_inactif_et_limite(void) {
    FlowTable *ft = table_avec(8, 5000, 0, NULL);
    uint8_t b[128];
    g_now = 1000; feed(ft, b, syn(b, 1, 1000));
    CHECK_EQ(ft_expire(ft, 5999), 0, "inactif depuis 4999 ms : reste");
    CHECK_EQ(ft_expire(ft, 6000), 1, "inactif depuis 5000 ms : retiré (limite incluse)");
    CHECK_EQ(ft -> nbr_elements, 0, "table vide");
    CHECK_EQ(got.n, 1, "le sink a reçu 1 flux");
    CHECK_EQ(got.rec[0].reason, END_IDLE, "raison : inactif");
    CHECK_EQ(ft -> n_evicted, 0, "n_evicted compte la table pleine, pas l'expiration");
    CHECK(ft -> port_per_ip -> nbr_elements == 0, "sa PortMap est libérée aussi");
    ft_destroy(ft);
}

static void t_expire_ft_process_fait_le_menage(void) {
    FlowTable *ft = table_avec(8, 5000, 0, NULL);
    uint8_t b[128];
    g_now = 1000; feed(ft, b, syn(b, 1, 1000));
    g_now = 3000; feed(ft, b, syn(b, 1, 1001));
    g_now = 9000; feed(ft, b, syn(b, 1, 1002));   /* ft_process appelle ft_expire tout seul */
    CHECK_EQ(got.n, 2, "les 2 vieux flux sont partis");
    CHECK_EQ(port_to_u16(got.rec[0].data.header.ipv4_headers.initiator_port), 1000, "le plus ancien d'abord");
    CHECK_EQ(port_to_u16(got.rec[1].data.header.ipv4_headers.initiator_port), 1001, "puis le suivant");
    CHECK_EQ(ft -> nbr_elements, 1, "reste le flux frais");
    ft_destroy(ft);
}

static void t_expire_un_paquet_rafraichit(void) {
    FlowTable *ft = table_avec(8, 5000, 0, NULL);
    uint8_t a[128], c[128];
    g_now = 1000; int na = syn(a, 1, 1000); feed(ft, a, na);
    g_now = 2000; int nc = syn(c, 1, 1001); feed(ft, c, nc);
    g_now = 3000; feed(ft, a, na);               /* A parle à nouveau : elle passe en fin de file */
    CHECK_EQ(ft_expire(ft, 7500), 1, "seul B (inactif depuis 5500) part");
    CHECK(flow_of(ft, a, na) != NULL, "A est restée (inactive depuis 4500)");
    CHECK(flow_of(ft, c, nc) == NULL, "B est partie");
    ft_destroy(ft);
}

static void t_expire_cas_limites(void) {
    FlowTable *ft = table_avec(8, 0, 0, NULL);
    uint8_t b[128];
    g_now = 1000; feed(ft, b, syn(b, 1, 1000));
    CHECK_EQ(ft_expire(ft, 999999999), 0, "idle_ms == 0 : expiration désactivée");
    CHECK_EQ(ft_expire(NULL, 5), -1, "ft NULL → -1");
    struct FlowHooks h = {0}; h.idle_ms = 100; h.sink = sink_collect; h.ctx = &got;
    CHECK_EQ(ft_set_hooks(ft, &h), 0, "ft_set_hooks → 0");
    CHECK_EQ(ft_set_hooks(NULL, &h), -1, "ft_set_hooks(NULL) → -1");
    CHECK_EQ(ft_set_hooks(ft, NULL), -1, "ft_set_hooks(hooks NULL) → -1");
    CHECK_EQ(ft_expire(ft, 500), 0, "horloge qui recule : rien n'est retiré");
    CHECK_EQ(ft -> nbr_elements, 1, "le flux est toujours là");
    ft_destroy(ft);
}

static void t_sink_copie_a_plat(void) {
    FlowTable *ft = table_avec(8, 1000, 0, NULL);
    uint8_t b[128];
    g_now = 100; int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, SYN); feed(ft, b, n);
    g_now = 200; n = tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 5000, SYN | ACK); feed(ft, b, n);
    ft_expire(ft, 5000);
    CHECK_EQ(got.n, 1, "un flux reçu");
    FlowRecord *r = &got.rec[0];
    CHECK_EQ(*(FlowKeyType *)&r -> key, FlowKeyIpv4Type, "clé v4");
    CHECK_MEM(r -> key.k4.ip_min, IP4(10, 0, 0, 1), 4, "ip_min");
    CHECK_EQ(r -> data.n_pkt_ltr, 1, "1 paquet ltr");
    CHECK_EQ(r -> data.n_pkt_rtl, 1, "1 paquet rtl");
    CHECK_EQ(r -> data.start_time, 100, "start_time copié");
    CHECK_EQ(r -> data.end_time, 200, "end_time copié");
    CHECK_EQ(r -> data.flag_count.syn, 2, "flags copiés");
    CHECK_EQ(r -> data.v4, 1, "v4 copié");
    ft_destroy(ft);
}

static void t_sink_eviction_et_destroy(void) {
    FlowTable *ft = table_avec(2, 0, 0, NULL);
    uint8_t b[128];
    for (uint16_t i = 0; i < 3; i++) { g_now = 100 + i; feed(ft, b, syn(b, 1, (uint16_t)(1000 + i))); }
    CHECK_EQ(got.n, 1, "table pleine : le chassé passe par le sink");
    CHECK_EQ(got.rec[0].reason, END_EVICTED, "raison : chassé");
    CHECK_EQ(port_to_u16(got.rec[0].data.header.ipv4_headers.initiator_port), 1000, "c'est le plus ancien");
    ft_destroy(ft);
    CHECK_EQ(got.n, 3, "ft_destroy envoie les 2 restants");
    CHECK_EQ(got.rec[1].reason, END_SHUTDOWN, "raison : arrêt");
    CHECK_EQ(got.rec[2].reason, END_SHUTDOWN, "raison : arrêt");
}

static void t_sans_sink_pas_de_copie(void) {
    FlowTable *ft = ft_create(2);
    struct FlowHooks h = {0}; h.idle_ms = 10;
    ft_set_hooks(ft, &h);                         /* sink == NULL */
    uint8_t b[128];
    g_now = 100; feed(ft, b, syn(b, 1, 1000));
    g_now = 500; feed(ft, b, syn(b, 1, 1001));
    CHECK_EQ(ft -> nbr_elements, 1, "le vieux est parti sans sink, sans plantage");
    ft_destroy(ft);
}

static void t_liste_noire(void) {
    FlowTable *ft = ft_create(8);
    uint8_t b[128];
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 0, 0, 1), 1), 0, "pas bloquée au départ");
    CHECK_EQ(ft_block_ip(ft, IP4(10, 0, 0, 1), 1), 0, "ft_block_ip → 0");
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 0, 0, 1), 1), 1, "bloquée");
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 0, 0, 3), 1), 0, "une autre IP n'est pas bloquée");
    CHECK_EQ(feed(ft, b, syn(b, 1, 1000)), 0, "paquet d'une IP bloquée → 0 (ignoré, pas une erreur)");
    CHECK_EQ(ft -> nbr_elements, 0, "aucun flux stocké");
    CHECK_EQ(ft -> port_per_ip -> nbr_elements, 0, "aucune PortMap non plus");
    CHECK_EQ(ft -> n_blocked_pkts, 1, "1 paquet ignoré compté");
    CHECK_EQ(feed(ft, b, syn(b, 3, 1000)), 0, "une autre IP passe");
    CHECK_EQ(ft -> nbr_elements, 1, "son flux est stocké");
    uint8_t v6[16] = {10, 0, 0, 1};
    CHECK_EQ(ft_is_blocked(ft, v6, 0), 0, "même 4 premiers octets en IPv6 : pas bloquée");
    CHECK_EQ(ft_unblock_ip(ft, IP4(10, 0, 0, 1), 1), 0, "ft_unblock_ip → 0");
    CHECK_EQ(ft_unblock_ip(ft, IP4(10, 0, 0, 1), 1), -1, "déjà débloquée → -1");
    CHECK_EQ(feed(ft, b, syn(b, 1, 1000)), 0, "débloquée : ses flux sont stockés");
    CHECK_EQ(ft -> nbr_elements, 2, "2 flux");
    CHECK_EQ(ft_block_ip(NULL, IP4(1, 1, 1, 1), 1), -1, "ft NULL → -1");
    CHECK_EQ(ft_block_ip(ft, IP4(1, 1, 1, 1), 2), -1, "v4 == 2 → -1");
    ft_destroy(ft);
}

static void t_regle_scan_unitaire(void) {
    struct PortMap pm;
    RulesConfig cfg;
    rules_config_default(&cfg);
    portmap_init(&pm);
    CHECK_EQ(rule_port_scan(NULL, NULL, &cfg).verdict, UNKNOW, "pas de PortMap → pas d'avis");
    for (int p = 1; p < SCAN_PORT_THRESHOLD; p++) portmap_add(&pm, (uint16_t)p);
    CHECK_EQ(pm.count, SCAN_PORT_THRESHOLD - 1, "19 ports");
    CHECK_EQ(rule_port_scan(NULL, &pm, &cfg).verdict, UNKNOW, "19 ports : pas d'avis");
    portmap_add(&pm, 9999);
    FlowRuleResult r = rule_port_scan(NULL, &pm, &cfg);
    CHECK_EQ(r.verdict, BLOCK, "20 ports : BLOCK");
    CHECK_EQ(r.reason, RULE_PORT_SCAN, "la raison : RULE_PORT_SCAN");
    CHECK_EQ(rule_port_scan(NULL, &pm, NULL).verdict, UNKNOW, "cfg NULL → rien d'actif");
}

/* un client normal, du SYN à la fin : aucune règle ne doit s'en mêler */
static void t_trafic_normal_pas_bloque(void) {
    FlowTable *ft = table_avec(16, 0, 0, rules_check_all);
    uint8_t b[128];
    const uint8_t *c = IP4(10, 0, 0, 1), *s = IP4(10, 0, 0, 2);
    feed(ft, b, tcp4_pkt(b, c, 5000, s, 80, SYN));
    feed(ft, b, tcp4_pkt(b, s, 80, c, 5000, SYN | ACK));
    feed(ft, b, tcp4_pkt(b, c, 5000, s, 80, ACK));
    feed(ft, b, tcp4_pkt(b, c, 5000, s, 80, PSH | ACK));
    feed(ft, b, tcp4_pkt(b, c, 5000, s, 80, FIN | ACK));
    feed(ft, b, tcp4_pkt(b, s, 80, c, 5000, FIN | ACK));
    CHECK_EQ(ft_is_blocked(ft, c, 1), 0, "le client n'est pas bloqué");
    CHECK_EQ(ft_is_blocked(ft, s, 1), 0, "le serveur non plus");
    CHECK_EQ(ft -> nbr_elements, 1, "le flux est toujours là");
    FlowEntry *e = flow_of(ft, b, 54);
    if (e) CHECK_EQ(e -> data -> verdict, UNKNOW, "verdict UNKNOW");
    if (e) CHECK_EQ(e -> data -> rule_reason, RULE_NONE, "aucune règle");
    CHECK_EQ(got.n, 0, "rien envoyé");
    ft_destroy(ft);
}

static void t_regle_scan_bloque_l_ip(void) {
    FlowTable *ft = table_avec(64, 0, 0, rules_check_all);
    uint8_t b[128];
    for (uint16_t p = 1000; p < 1025; p++)       /* 25 ports visités par la même IP */
        feed(ft, b, tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), p, SYN));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 9, 9, 9), 1), 1, "le scanner est sur la liste noire");
    CHECK_EQ(ft -> nbr_elements, SCAN_PORT_THRESHOLD - 1, "19 flux restent : le 20e est parti au blocage, les 5 suivants sont ignorés");
    CHECK_EQ(ft -> n_blocked_pkts, 5, "5 paquets ignorés");
    CHECK_EQ(ft -> n_blocked_flows, 1, "1 flux retiré par blocage");
    CHECK_EQ(got.n, 1, "le flux bloqué est parti au sink tout de suite");
    CHECK_EQ(got.rec[0].reason, END_BLOCKED, "raison de départ : END_BLOCKED");
    CHECK_EQ(got.rec[0].data.verdict, BLOCK, "avec son verdict BLOCK");
    CHECK_EQ(got.rec[0].data.rule_reason, RULE_PORT_SCAN, "et la règle qui l'a décidé");
    int n = tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), 1019, SYN);
    CHECK(flow_of(ft, b, n) == NULL, "le 20e flux n'est plus dans la table");
    n = tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), 1000, SYN);
    FlowEntry *premier = flow_of(ft, b, n);
    CHECK(premier != NULL, "le 1er flux est encore là (il expirera tout seul)");
    if (premier) CHECK_EQ(premier -> data -> verdict, UNKNOW, "et il est resté UNKNOW");
    struct PortMap *pm = portmap_v4(ft, IP4(10, 9, 9, 9));
    CHECK(pm != NULL, "la PortMap existe encore : 19 flux de cette IP vivent");
    if (pm) {
        CHECK_EQ(pm -> count, 0, "mais elle a été remise à zéro au blocage");
        CHECK_EQ(pm -> refcount, SCAN_PORT_THRESHOLD - 1, "refcount intact (19 flux)");
    }
    CHECK_EQ(feed(ft, b, syn(b, 5, 2000)), 0, "un client normal n'est pas touché");
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 0, 0, 5), 1), 0, "pas bloqué");

    /* la victime répond à l'attaquant bloqué : ces paquets sont ignorés, ils ne fabriquent pas de faux flux « initiés par la victime » */
    int avant = ft -> nbr_elements;
    CHECK_EQ(feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 2), 1030, IP4(10, 9, 9, 9), 40000, RST | ACK)), 0, "réponse vers l'IP bloquée → 0");
    CHECK_EQ(ft -> nbr_elements, avant, "aucun flux créé");
    CHECK_EQ(ft -> n_blocked_pkts, 6, "compté comme ignoré");

    /* l'admin débloque : l'IP repart de zéro et n'est pas re-bloquée tout de suite */
    CHECK_EQ(ft_unblock_ip(ft, IP4(10, 9, 9, 9), 1), 0, "débloquée");
    for (uint16_t p = 2000; p < 2005; p++)
        feed(ft, b, tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), p, SYN));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 9, 9, 9), 1), 0, "5 nouveaux ports : pas re-bloquée (compteur reparti de 0)");
    pm = portmap_v4(ft, IP4(10, 9, 9, 9));
    if (pm) CHECK_EQ(pm -> count, 5, "5 ports comptés");
    ft_destroy(ft);
}

static void t_regles_a_chaud(void) {
    FlowTable *ft = table_avec(128, 0, 0, rules_check_all);
    uint8_t b[128];
    CHECK_EQ(rules_set_enabled(&g_rules, RULE_PORT_SCAN, 0), 0, "port_scan désactivée pendant que la table tourne");
    for (uint16_t p = 1000; p < 1030; p++)
        feed(ft, b, tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), p, SYN));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 9, 9, 9), 1), 0, "30 ports mais règle désactivée : pas bloquée");
    CHECK_EQ(ft -> nbr_elements, 30, "30 flux stockés");
    CHECK_EQ(rules_set_enabled(&g_rules, RULE_PORT_SCAN, 1), 0, "réactivée");
    feed(ft, b, tcp4_pkt(b, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), 1030, SYN));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 9, 9, 9), 1), 1, "au paquet suivant la règle s'applique : bloquée");

    CHECK_EQ(rules_set_threshold(&g_rules, RULE_PORT_SCAN, 5), 0, "seuil abaissé à 5");
    for (uint16_t p = 1000; p < 1006; p++)
        feed(ft, b, tcp4_pkt(b, IP4(10, 8, 8, 8), 40000, IP4(10, 0, 0, 2), p, SYN));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 8, 8, 8), 1), 1, "avec un seuil de 5, 5 ports suffisent");
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 7, 7, 7), 1), 0, "une IP qui n'a rien fait n'est pas touchée");
    ft_destroy(ft);
}

static void t_regles_scan_tcp_bloquent(void) {
    struct { const char *nom; uint8_t flags; FlowRuleReason regle; } cas[] = {
        { "NULL (aucun drapeau)",  0,               RULE_NULL_SCAN },
        { "Xmas (FIN+PSH+URG)",    FIN | PSH | URG, RULE_XMAS_SCAN },
        { "FIN seul",              FIN,             RULE_FIN_SCAN  },
    };
    for (int i = 0; i < 3; i++) {
        FlowTable *ft = table_avec(16, 0, 0, rules_check_all);
        uint8_t b[128];
        feed(ft, b, tcp4_pkt(b, IP4(10, 7, 7, 7), 4444, IP4(10, 0, 0, 2), 80, cas[i].flags));
        CHECK_EQ(ft_is_blocked(ft, IP4(10, 7, 7, 7), 1), 1, cas[i].nom);
        CHECK_EQ(ft -> nbr_elements, 0, "le flux est retiré tout de suite");
        CHECK_EQ(ft -> port_per_ip -> nbr_elements, 0, "et sa PortMap libérée (dernier flux de l'IP)");
        CHECK_EQ(got.n, 1, "envoyé au sink");
        CHECK_EQ(got.rec[0].reason, END_BLOCKED, "raison END_BLOCKED");
        CHECK_EQ(got.rec[0].data.verdict, BLOCK, "verdict BLOCK");
        CHECK_EQ(got.rec[0].data.rule_reason, cas[i].regle, "la bonne règle est notée");
        CHECK_EQ(got.rec[0].data.n_pkt_ltr, 1, "1 paquet");
        ft_destroy(ft);
    }
    /* désactivée : le même paquet passe */
    FlowTable *ft = table_avec(16, 0, 0, rules_check_all);
    uint8_t b[128];
    rules_set_enabled(&g_rules, RULE_NULL_SCAN, 0);
    feed(ft, b, tcp4_pkt(b, IP4(10, 7, 7, 7), 4444, IP4(10, 0, 0, 2), 80, 0));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 7, 7, 7), 1), 0, "null_scan désactivée : pas bloquée");
    CHECK_EQ(ft -> nbr_elements, 1, "flux stocké");
    ft_destroy(ft);
}

/* ───── la liste noire PARTAGÉE (ipset_m) ───── */

static void t_blocklist_partagee_entre_tables(void) {
    IpSetM *m = ipset_m_create(64);
    FlowTable *a = table_avec(64, 0, 0, rules_check_all);
    FlowTable *b = table_avec(64, 0, 0, rules_check_all);
    CHECK_EQ(ft_use_blocklist(a, m), 0, "la table A utilise la liste partagée");
    CHECK_EQ(ft_use_blocklist(b, m), 0, "la table B aussi");
    rules_set_block_ttl(&g_rules, 60000);
    g_now = 1000000;
    uint8_t buf[128];
    for (uint16_t p = 1000; p < 1025; p++)
        feed(a, buf, tcp4_pkt(buf, IP4(10, 9, 9, 9), 40000, IP4(10, 0, 0, 2), p, SYN));
    CHECK_EQ(ipset_m_is_blocked(m, IP4(10, 9, 9, 9), 1), 1, "bloquée par une règle de A : elle est dans la liste partagée");
    CHECK_EQ(ft_is_blocked(b, IP4(10, 9, 9, 9), 1), 1, "B la voit tout de suite");
    struct IpBlockMeta meta;
    memset(&meta, 0, sizeof meta);
    CHECK_EQ(ipset_m_get(m, IP4(10, 9, 9, 9), 1, &meta), 1, "métadonnées disponibles");
    CHECK_EQ(meta.rule, RULE_PORT_SCAN, "la raison : la règle qui a bloqué");
    CHECK_EQ(meta.source, IPM_SRC_AUTO, "source : automatique");
    CHECK_EQ(meta.blocked_at_ms, 1000000, "date du blocage = l'heure du paquet");
    CHECK_EQ(meta.until_ms, 1060000, "expiration = date + durée réglée à chaud (60 s)");

    feed(b, buf, tcp4_pkt(buf, IP4(10, 9, 9, 9), 41000, IP4(10, 0, 0, 3), 80, SYN));
    CHECK_EQ(b -> nbr_elements, 0, "B ignore l'IP bloquée par A");
    CHECK_EQ(b -> n_blocked_pkts, 1, "paquet compté comme ignoré");
    CHECK_EQ(ipset_m_remove(m, IP4(10, 9, 9, 9), 1), 0, "l'admin débloque (côté Python)");
    feed(b, buf, tcp4_pkt(buf, IP4(10, 9, 9, 9), 41000, IP4(10, 0, 0, 3), 80, SYN));
    CHECK_EQ(b -> nbr_elements, 1, "B suit de nouveau cette IP : débloquer côté C suffit");

    rules_set_block_ttl(&g_rules, 0);
    for (uint16_t p = 2000; p < 2025; p++)
        feed(a, buf, tcp4_pkt(buf, IP4(10, 8, 8, 8), 40000, IP4(10, 0, 0, 2), p, SYN));
    CHECK_EQ(ipset_m_get(m, IP4(10, 8, 8, 8), 1, &meta), 1, "deuxième scanner bloqué");
    CHECK_EQ(meta.until_ms, 0, "durée 0 : pour toujours");

    struct IpBlockMeta man = { 0, IPM_SRC_MANUAL, g_now, 0 };
    CHECK_EQ(ipset_m_add(m, IP4(10, 0, 0, 5), 1, &man), 0, "blocage manuel dans la liste partagée");
    int avant = (int)a -> nbr_elements;
    feed(a, buf, syn(buf, 5, 3000));
    CHECK_EQ((int)a -> nbr_elements, avant, "A ignore une IP bloquée à la main");
    ft_destroy(a);
    ft_destroy(b);
    ipset_m_destroy(m);
}

static void t_blocklist_les_tables_annoncent_leur_repos(void) {
    IpSetM *m = ipset_m_create(64);
    FlowTable *ft = table_avec(16, 0, 0, NULL);
    CHECK_EQ(ft_use_blocklist(ft, m), 0, "la table lit la liste partagée");
    uint8_t ip[4], buf[128];
    for (uint32_t i = 0; i < 2000; i++) { ip[0] = 10; ip[1] = 1; ip[2] = (uint8_t)(i >> 8); ip[3] = (uint8_t)i; ipset_m_add(m, ip, 1, NULL); }
    struct IpSetMStats st;
    ipset_m_stats(m, &st);
    CHECK(st.retired_pending >= 1, "la table n'a encore rien annoncé : les anciennes tables attendent");
    CHECK_EQ(ipset_m_reclaim(m), 0, "rien n'est libérable");
    feed(ft, buf, syn(buf, 1, 1000));                         /* ft_process annonce « je ne tiens aucune table » */
    CHECK(ipset_m_reclaim(m) >= 1, "après un paquet traité, les anciennes tables sont libérées");
    ipset_m_stats(m, &st);
    CHECK_EQ(st.retired_pending, 0, "plus rien en attente");
    for (uint32_t i = 0; i < 3000; i++) { ip[0] = 10; ip[1] = 2; ip[2] = (uint8_t)(i >> 8); ip[3] = (uint8_t)i; ipset_m_add(m, ip, 1, NULL); }
    ipset_m_stats(m, &st);
    CHECK(st.retired_pending >= 1, "de nouvelles bascules : de nouveau en attente");
    ft_expire(ft, g_now);                                     /* le ménage (rien n'arrive) annonce aussi le repos */
    CHECK(ipset_m_reclaim(m) >= 1, "ft_expire annonce aussi le repos");
    ft_destroy(ft);
    ipset_m_destroy(m);
}

static void t_blocklist_trop_de_lecteurs(void) {
    IpSetM *m = ipset_m_create(64);
    int ids[IPSET_M_MAX_READERS];
    for (int i = 0; i < IPSET_M_MAX_READERS; i++) ids[i] = ipset_m_register(m);
    FlowTable *ft = table_avec(16, 0, 0, NULL);
    CHECK_EQ(ft_use_blocklist(ft, m), -1, "plus de slot de lecteur : refusé");
    CHECK_EQ(ft_use_blocklist(NULL, m), -1, "table NULL");
    CHECK_EQ(ft_use_blocklist(ft, NULL), -1, "liste NULL");
    uint8_t ip[4] = {10, 0, 0, 1};
    CHECK_EQ(ft_block_ip(ft, ip, 1), 0, "la table garde sa propre liste et fonctionne");
    CHECK_EQ(ft_is_blocked(ft, ip, 1), 1, "elle bloque");
    CHECK_EQ(ipset_m_is_blocked(m, ip, 1), 0, "sans toucher à la liste partagée");
    for (int i = 0; i < IPSET_M_MAX_READERS; i++) ipset_m_unregister(m, ids[i]);
    ft_destroy(ft);
    ipset_m_destroy(m);
}

static void t_regle_flood_marque_sans_bloquer(void) {
    FlowTable *ft = table_avec(16, 0, 0, rules_check_all);
    uint8_t b[128];
    g_now = 5000;                                /* tous les paquets dans la même milliseconde : mesuré sur FLOOD_MIN_WINDOW_MS */
    int n = udp4_pkt(b, IP4(10, 6, 6, 6), 5000, IP4(10, 0, 0, 2), 53);
    for (int i = 0; i < 900; i++) feed(ft, b, n);
    FlowEntry *e = flow_of(ft, b, n);
    CHECK(e != NULL, "flux présent");
    if (e) CHECK_EQ(e -> data -> verdict, UNKNOW, "900 paquets en 100 ms = 9000/s : sous le seuil de 10000");
    for (int i = 0; i < 200; i++) feed(ft, b, n);
    if (e) {
        CHECK_EQ(e -> data -> verdict, LIMIT_REACHED, "1100 paquets en 100 ms : LIMIT_REACHED");
        CHECK_EQ(e -> data -> rule_reason, RULE_FLOOD, "règle flood");
    }
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 6, 6, 6), 1), 0, "un flood est marqué, l'IP n'est pas bloquée");
    CHECK_EQ(ft -> nbr_elements, 1, "le flux reste dans la table");
    CHECK_EQ(got.n, 0, "rien n'est parti");
    ft_destroy(ft);
}

static void t_sans_cfg_aucune_regle(void) {
    FlowTable *ft = ft_create(16);
    struct FlowHooks h = {0};
    h.check = rules_check_all; h.sink = sink_collect; h.ctx = &got;      /* rules_cfg reste NULL */
    ft_set_hooks(ft, &h);
    memset(&got, 0, sizeof got);
    uint8_t b[128];
    feed(ft, b, tcp4_pkt(b, IP4(10, 7, 7, 7), 4444, IP4(10, 0, 0, 2), 80, 0));
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 7, 7, 7), 1), 0, "sans réglages, aucune règle ne s'applique");
    CHECK_EQ(ft -> nbr_elements, 1, "le flux est stocké");
    ft_destroy(ft);
}

static void t_liste_noire_destination(void) {
    FlowTable *ft = ft_create(8);
    uint8_t b[128];
    ft_block_ip(ft, IP4(10, 0, 0, 2), 1);
    CHECK_EQ(feed(ft, b, syn(b, 1, 1000)), 0, "paquet VERS une IP bloquée → 0 (ignoré)");
    CHECK_EQ(ft -> nbr_elements, 0, "aucun flux");
    CHECK_EQ(ft -> n_blocked_pkts, 1, "compté");
    ft_destroy(ft);
}

static int appels_regle;
static FlowRuleResult regle_une_fois(const FlowData *d, const struct PortMap *pm, const struct RulesConfig *cfg) {
    (void)d; (void)pm; (void)cfg;
    FlowRuleResult r = { appels_regle++ == 0 ? LIMIT_REACHED : UNKNOW, RULE_FLOOD };
    return r;
}
static void t_regle_unknow_garde_le_verdict(void) {
    appels_regle = 0;
    FlowTable *ft = table_avec(8, 0, 0, regle_une_fois);
    uint8_t b[128];
    int n = syn(b, 1, 1000);
    feed(ft, b, n);
    feed(ft, b, n);
    feed(ft, b, n);
    FlowEntry *e = flow_of(ft, b, n);
    CHECK_EQ(appels_regle, 3, "la règle est appelée à CHAQUE paquet");
    if (e) CHECK_EQ(e -> data -> verdict, LIMIT_REACHED, "UNKNOW ne remet pas le verdict à zéro");
    if (e) CHECK_EQ(e -> data -> rule_reason, RULE_FLOOD, "la règle du verdict est gardée aussi");
    CHECK_EQ(ft_is_blocked(ft, IP4(10, 0, 0, 1), 1), 0, "LIMIT_REACHED ne bloque pas l'IP");
    ft_destroy(ft);
}

static void t_fin_tcp(void) {
    FlowTable *ft = table_avec(8, 0, 1, NULL);   /* close_on_tcp_end = 1 */
    uint8_t b[128];
    g_now = 10; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, SYN));
    g_now = 20; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 5000, SYN | ACK));
    CHECK_EQ(ft -> nbr_elements, 1, "poignée de main : le flux vit");
    g_now = 30; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, FIN | ACK));
    CHECK_EQ(ft -> nbr_elements, 1, "un seul FIN : pas fini");
    g_now = 40; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 5000, FIN | ACK));
    CHECK_EQ(ft -> nbr_elements, 0, "FIN des deux côtés : retiré");
    CHECK_EQ(got.n, 1, "envoyé au sink");
    CHECK_EQ(got.rec[0].reason, END_TCP_CLOSED, "raison : TCP terminé");
    CHECK_EQ(got.rec[0].data.end_time, 40, "end_time = dernier paquet");
    CHECK_EQ(got.rec[0].data.n_pkt_ltr + got.rec[0].data.n_pkt_rtl, 4, "4 paquets");
    g_now = 50; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 1), 6000, IP4(10, 0, 0, 2), 80, SYN));
    g_now = 60; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 6000, RST));
    CHECK_EQ(ft -> nbr_elements, 0, "RST : retiré tout de suite");
    CHECK_EQ(got.n, 2, "2 flux envoyés");
    CHECK(ft -> port_per_ip -> nbr_elements == 0, "PortMap libérée");
    ft_destroy(ft);
}

static void t_fin_tcp_desactive_par_defaut(void) {
    FlowTable *ft = table_avec(8, 0, 0, NULL);   /* close_on_tcp_end = 0 */
    uint8_t b[128];
    feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, SYN));
    feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 5000, RST));
    CHECK_EQ(ft -> nbr_elements, 1, "sans l'option, un RST ne retire rien");
    CHECK_EQ(got.n, 0, "rien envoyé");
    ft_destroy(ft);
}

static void t_delete_entry(void) {
    DChainedList *dcl = create_dcl(0);
    FlowEntry *e[4];
    for (int i = 0; i < 4; i++) { e[i] = calloc(1, sizeof(FlowEntry)); add_to_end(dcl, e[i], 0); }
    CHECK_EQ(delete_entry(NULL, e[0]), -1, "dcl NULL → -1");
    CHECK_EQ(delete_entry(dcl, NULL), -1, "entry NULL → -1");
    CHECK_EQ(delete_entry(dcl, e[1]), 0, "retirer un élément du milieu");
    CHECK_EQ(dcl -> n_elements, 3, "3 restants");
    CHECK_PTR(e[0] -> lru_next, e[2], "0 pointe maintenant sur 2");
    CHECK_PTR(e[2] -> lru_prev, e[0], "2 pointe en arrière sur 0");
    CHECK_EQ(delete_entry(dcl, e[0]), 0, "retirer la tête");
    CHECK_PTR(dcl -> head, e[2], "nouvelle tête");
    CHECK_EQ(delete_entry(dcl, e[3]), 0, "retirer la queue");
    CHECK_PTR(dcl -> tail, e[2], "nouvelle queue");
    CHECK_EQ(delete_entry(dcl, e[2]), 0, "retirer le dernier");
    CHECK_EQ(dcl -> n_elements, 0, "liste vide");
    CHECK(dcl -> head == NULL && dcl -> tail == NULL, "head et tail à NULL");
    free(dcl);
}

static void t_fuites_expiration_et_sink(void) {
    FlowTable *ft = table_avec(16, 50, 1, rules_check_all);
    uint8_t b[128];
    for (int i = 0; i < 3000; i++) {
        g_now = 1000 + (uint64_t)i * 7;
        int n;
        if (i % 4 == 0)      n = tcp4_pkt(b, IP4(10, 1, (uint8_t)(i >> 8), (uint8_t)i), (uint16_t)(1000 + i % 50), IP4(10, 0, 0, 2), (uint16_t)(i % 40), SYN);
        else if (i % 4 == 1) n = udp4_pkt(b, IP4(10, 2, 0, (uint8_t)i), 5000, IP4(10, 0, 0, 3), 53);
        else if (i % 4 == 2) n = tcp4_pkt(b, IP4(10, 1, 0, (uint8_t)i), 1000, IP4(10, 0, 0, 2), 80, (uint8_t)(i % 3 ? ACK : RST));
        else                 n = tcp6_pkt(b, (uint8_t)i, (uint16_t)(2000 + i % 7), 9, 443, FIN);
        feed(ft, b, n);
    }
    CHECK(ft -> nbr_elements <= 16, "jamais plus de 16 flux");
    CHECK(got.n > 0, "des flux sont partis par le sink");
    ft_destroy(ft);
}

static FlowTable *table_max(uint64_t idle_ms, uint64_t max_ms, uint8_t close_tcp) {
    FlowTable *ft = ft_create(8);
    struct FlowHooks h = {0};
    h.idle_ms = idle_ms; h.max_ms = max_ms; h.close_on_tcp_end = close_tcp; h.sink = sink_collect; h.ctx = &got;
    ft_set_hooks(ft, &h);
    memset(&got, 0, sizeof got);
    return ft;
}

static void t_duree_max_envoie_puis_repart_de_zero(void) {
    FlowTable *ft = table_max(100000, 5000, 0);
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, ACK);
    g_now = 1000; feed(ft, b, n);
    g_now = 3000; feed(ft, b, n);
    g_now = 5999; feed(ft, b, n);
    CHECK_EQ(got.n, 0, "5999 - 1000 = 4999 ms : pas encore");
    g_now = 6000; feed(ft, b, n);
    CHECK_EQ(got.n, 1, "6000 - 1000 = 5000 ms : instantané envoyé (limite incluse)");
    CHECK_EQ(got.rec[0].reason, END_MAX_DURATION, "raison : durée max");
    CHECK_EQ(got.rec[0].data.n_pkt_ltr, 4, "l'instantané contient les 4 paquets, dont celui qui déclenche");
    CHECK_EQ(got.rec[0].data.start_time, 1000, "start_time d'origine");
    CHECK_EQ(got.rec[0].data.end_time, 6000, "end_time = dernier paquet");
    CHECK_EQ(ft -> nbr_elements, 1, "le flux RESTE dans la table");
    FlowEntry *e = flow_of(ft, b, n);
    if (e) {
        CHECK_EQ(e -> data -> n_pkt_ltr, 0, "compteurs remis à zéro");
        CHECK_EQ(e -> data -> octets_data_ltr, 0, "octets remis à zéro");
        CHECK_EQ(e -> data -> flag_count.ack, 0, "flags remis à zéro");
        CHECK_EQ(e -> data -> start_time, 6000, "start_time = maintenant");
        CHECK_EQ(e -> data -> proto, TCP, "proto gardé");
        CHECK_MEM(e -> data -> header.ipv4_headers.initiator_ip, IP4(10, 0, 0, 1), 4, "initiateur gardé");
    }
    g_now = 7000; feed(ft, b, n);
    g_now = 11000; feed(ft, b, n);
    CHECK_EQ(got.n, 2, "5 s plus tard : un 2e instantané");
    CHECK_EQ(got.rec[1].data.n_pkt_ltr, 2, "2 paquets dans le 2e (celui de 7000 et celui de 11000)");
    CHECK_EQ(got.rec[1].data.start_time, 6000, "le 2e commence à 6000");
    ft_destroy(ft);
}

static void t_duree_max_flux_bavard(void) {
    /* idle 30 s, max 5 min, un paquet toutes les 10 s pendant 1 heure : exporté 12 fois, jamais par inactivité */
    FlowTable *ft = table_max(30000, 300000, 0);
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, ACK);
    for (int i = 0; i <= 360; i++) { g_now = (uint64_t)i * 10000; feed(ft, b, n); }
    CHECK_EQ(got.n, 12, "12 instantanés en 1 heure");
    int idle = 0;
    for (int i = 0; i < got.n && i < 16; i++) if (got.rec[i].reason == END_IDLE) idle++;
    CHECK_EQ(idle, 0, "aucun retrait pour inactivité");
    CHECK_EQ(ft -> nbr_elements, 1, "toujours le même flux");
    ft_destroy(ft);
}

static void t_duree_max_desactivee_et_sans_sink(void) {
    FlowTable *ft = table_max(0, 0, 0);          /* max_ms == 0 */
    uint8_t b[128];
    int n = tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, ACK);
    g_now = 1000; feed(ft, b, n);
    g_now = 99999999; feed(ft, b, n);
    CHECK_EQ(got.n, 0, "max_ms == 0 : jamais d'instantané");
    ft_destroy(ft);

    ft = ft_create(8);
    struct FlowHooks h = {0}; h.max_ms = 1000;   /* pas de sink */
    ft_set_hooks(ft, &h);
    g_now = 1000; feed(ft, b, n);
    g_now = 3000; feed(ft, b, n);
    FlowEntry *e = flow_of(ft, b, n);
    CHECK(e != NULL, "le flux existe");
    if (e) CHECK_EQ(e -> data -> n_pkt_ltr, 0, "sans sink, le flux repart quand même de zéro");
    ft_destroy(ft);
}

static void t_duree_max_et_fin_tcp(void) {
    FlowTable *ft = table_max(0, 1000, 1);
    uint8_t b[128];
    g_now = 100; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 1), 5000, IP4(10, 0, 0, 2), 80, SYN));
    g_now = 9000; feed(ft, b, tcp4_pkt(b, IP4(10, 0, 0, 2), 80, IP4(10, 0, 0, 1), 5000, RST));
    CHECK_EQ(got.n, 1, "RST ET durée dépassée : UN seul envoi");
    CHECK_EQ(got.rec[0].reason, END_TCP_CLOSED, "la fin TCP gagne");
    CHECK_EQ(ft -> nbr_elements, 0, "flux retiré");
    ft_destroy(ft);
}

static void t_create_with(void) {
    struct FlowHooks h = {0};
    h.idle_ms = 123; h.max_ms = 456; h.close_on_tcp_end = 1; h.sink = sink_collect; h.ctx = &got;
    FlowTable *ft = ft_create_with(4, &h);
    CHECK(ft != NULL, "ft_create_with");
    if (ft) {
        CHECK_EQ(ft -> hooks.idle_ms, 123, "idle_ms posé dès la création");
        CHECK_EQ(ft -> hooks.max_ms, 456, "max_ms posé dès la création");
        CHECK_EQ(ft -> hooks.close_on_tcp_end, 1, "close_on_tcp_end posé");
        CHECK_PTR(ft -> hooks.ctx, &got, "ctx posé");
        ft_destroy(ft);
    }
    ft = ft_create_with(4, NULL);
    CHECK(ft != NULL, "hooks NULL accepté : tout à 0");
    if (ft) { CHECK_EQ(ft -> hooks.idle_ms, 0, "rien d'actif"); ft_destroy(ft); }
    CHECK(ft_create_with(0, &h) == NULL, "taille 0 → NULL");
}

int main(int argc, char **argv) {
    tc_begin("test_integration.c", argc, argv);

    printf("\n── 1. conventions ──\n");
    RUN("conventions : action → -1 si arguments invalides",    t_conv_actions_echec);
    RUN_LEAKS("conventions : action → 0 si succès",            t_conv_actions_succes);
    RUN_LEAKS("conventions : question → 1 = oui, 0 = non",     t_conv_questions_oui_non);
    RUN_LEAKS("conventions : comparaison → 0 = égaux",         t_conv_comparaisons);
    RUN_LEAKS("conventions : pointeur → NULL = absent / échec", t_conv_pointeurs_null);
    RUN_LEAKS("conventions : drapeau v4 (1 = IPv4, 0 = IPv6)", t_conv_drapeau_v4);
    RUN("conventions : codes du parser (0 = ok)",              t_conv_codes_du_parser);

    printf("\n── 2. mémoire ──\n");
    RUN("mémoire : ParserResult (positions)",                  t_mem_parser_result);
    RUN("mémoire : unions du parser",                          t_mem_unions_du_parser);
    RUN("mémoire : FlowKey, FlowData, FlowEntry",              t_mem_flow);
    RUN("mémoire : FlowTable, Dict, PortMap",                  t_mem_table_dict_portmap);
    RUN("mémoire : valeurs des enums",                         t_mem_valeurs_des_enums);

    printf("\n── 3. de bout en bout (vrais octets) ──\n");
    RUN_LEAKS("e2e : poignée de main TCP (octets → flux)",     t_e2e_poignee_de_main_tcp);
    RUN_LEAKS("e2e : même flux avec VLAN et bourrage Ethernet", t_e2e_meme_flux_vlan_et_bourrage);
    RUN_LEAKS("e2e : paquets refusés (ARP, coupé, fragment...)", t_e2e_paquets_refuses);
    RUN_LEAKS("e2e : IPv6 et ICMPv6",                          t_e2e_ipv6_et_icmpv6);
    RUN_LEAKS("e2e : scan de 30 ports",                        t_e2e_scan_de_ports);
    RUN_LEAKS("e2e : IPv4 et IPv6 ne se mélangent pas",        t_e2e_v4_et_v6_ne_se_melangent_pas);
    RUN_LEAKS("e2e : éviction et refcount",                    t_e2e_eviction_et_refcount);
    RUN_LEAKS("e2e : PortMap libérée avec le dernier flux",    t_e2e_portmap_liberee_avec_le_dernier_flux);
    RUN_LEAKS("régression : ft_add d'un flux présent, table pleine", t_regression_ft_add_present_et_table_pleine);
    RUN_LEAKS("régression : ft_evict_oldest sur table vide",   t_regression_evict_table_vide);
    RUN_LEAKS("2000 paquets mélangés : pas de fuite",          t_fuites_beaucoup_de_paquets);

    printf("\n── 4. temps, expiration, sink, liste noire, règles ──\n");
    RUN_LEAKS("temps : start_time, end_time, octets",           t_temps_et_octets);
    RUN("temps : realtime_ms lisible par Python",               t_realtime_ms_lisible_par_python);
    RUN_LEAKS("ft_expire : inactif, limite incluse",            t_expire_inactif_et_limite);
    RUN_LEAKS("ft_expire : ft_process fait le ménage",          t_expire_ft_process_fait_le_menage);
    RUN_LEAKS("ft_expire : un paquet rafraîchit le flux",       t_expire_un_paquet_rafraichit);
    RUN_LEAKS("ft_expire : cas limites (0, NULL, horloge)",     t_expire_cas_limites);
    RUN_LEAKS("sink : copie à plat du flux",                    t_sink_copie_a_plat);
    RUN_LEAKS("sink : éviction et ft_destroy",                  t_sink_eviction_et_destroy);
    RUN_LEAKS("sink NULL : pas de copie, pas de plantage",      t_sans_sink_pas_de_copie);
    RUN_LEAKS("liste noire : bloquer, ignorer, débloquer",      t_liste_noire);
    RUN("règle scan : seuil",                                   t_regle_scan_unitaire);
    RUN_LEAKS("liste noire : la destination compte aussi",      t_liste_noire_destination);
    RUN_LEAKS("trafic normal : aucune règle ne se déclenche",   t_trafic_normal_pas_bloque);
    RUN_LEAKS("règle scan : bloque, envoie, retire, remet à 0", t_regle_scan_bloque_l_ip);
    RUN_LEAKS("règles : réglages modifiés à chaud",             t_regles_a_chaud);
    RUN_LEAKS("règles NULL / Xmas / FIN : bloquent et retirent", t_regles_scan_tcp_bloquent);
    RUN_LEAKS("liste noire partagée : 2 tables, métadonnées, TTL", t_blocklist_partagee_entre_tables);
    RUN_LEAKS("liste noire : les tables annoncent leur repos",  t_blocklist_les_tables_annoncent_leur_repos);
    RUN_LEAKS("liste noire : plus de slot de lecteur",          t_blocklist_trop_de_lecteurs);
    RUN_LEAKS("règle flood : marque sans bloquer",              t_regle_flood_marque_sans_bloquer);
    RUN_LEAKS("sans réglages : aucune règle",                   t_sans_cfg_aucune_regle);
    RUN_LEAKS("règle : UNKNOW garde le verdict",                t_regle_unknow_garde_le_verdict);
    RUN_LEAKS("TCP : FIN des deux côtés et RST",                t_fin_tcp);
    RUN_LEAKS("TCP : option désactivée par défaut",             t_fin_tcp_desactive_par_defaut);
    RUN_LEAKS("delete_entry : milieu, tête, queue",             t_delete_entry);
    RUN_LEAKS("3000 paquets avec expiration + sink : pas de fuite", t_fuites_expiration_et_sink);

    RUN_LEAKS("durée max : instantané puis remise à zéro",       t_duree_max_envoie_puis_repart_de_zero);
    RUN_LEAKS("durée max : flux bavard (10 s, 1 heure)",        t_duree_max_flux_bavard);
    RUN_LEAKS("durée max : désactivée, et sans sink",           t_duree_max_desactivee_et_sans_sink);
    RUN_LEAKS("durée max : la fin TCP gagne",                   t_duree_max_et_fin_tcp);
    RUN_LEAKS("ft_create_with : réglages dès la création",      t_create_with);

    return tc_end();
}
