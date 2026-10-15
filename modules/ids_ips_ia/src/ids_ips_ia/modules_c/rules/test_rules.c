/* test_rules.c : tests des règles et de leurs réglages (rules.c). Lancer : ./run_tests.sh rules
 * Ici on fabrique des FlowData à la main : pas de table, pas de paquets. Les règles dans une vraie table sont testées dans test_integration.c. */
#define _GNU_SOURCE
#include "../test_common.h"
#include "rules.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

static FlowData tcp_flow(uint32_t syn, uint32_t ack, uint32_t fin, uint32_t rst, uint32_t psh, uint32_t urg) {
    FlowData d;
    memset(&d, 0, sizeof d);
    d.proto = (uint8_t)TCP;
    d.flag_count.syn = syn; d.flag_count.ack = ack; d.flag_count.fin = fin;
    d.flag_count.rst = rst; d.flag_count.psh = psh; d.flag_count.urg = urg;
    d.n_pkt_ltr = 1;
    return d;
}

static FlowData datagram_flow(uint8_t proto, uint32_t pkts_ltr, uint32_t pkts_rtl, uint64_t start, uint64_t end) {
    FlowData d;
    memset(&d, 0, sizeof d);
    d.proto = proto; d.n_pkt_ltr = pkts_ltr; d.n_pkt_rtl = pkts_rtl; d.start_time = start; d.end_time = end;
    return d;
}

/* ───────────── réglages ───────────── */

static void t_defauts_et_noms(void) {
    RulesConfig cfg;
    memset(&cfg, 0x55, sizeof cfg);                   /* du bruit : rules_config_default doit tout écrire */
    rules_config_default(&cfg);
    int en; uint32_t th;
    for (int r = 1; r < RULE_COUNT; r++) {
        CHECK_EQ(rules_get(&cfg, r, &en, &th), 0, "rules_get d'une règle valide");
        CHECK_EQ(en, 1, "toutes les règles sont actives par défaut");
    }
    rules_get(&cfg, RULE_PORT_SCAN, &en, &th); CHECK_EQ(th, SCAN_PORT_THRESHOLD, "port_scan : 20 ports");
    rules_get(&cfg, RULE_FLOOD, &en, &th);     CHECK_EQ(th, FLOOD_PPS_THRESHOLD, "flood : seuil par défaut");
    rules_get(&cfg, RULE_NULL_SCAN, &en, &th); CHECK_EQ(th, 0, "null_scan : pas de seuil");
    CHECK_EQ(strcmp(rules_name(RULE_PORT_SCAN), "port_scan"), 0, "nom de RULE_PORT_SCAN");
    CHECK_EQ(strcmp(rules_name(RULE_FLOOD), "flood"), 0, "nom de RULE_FLOOD");
    CHECK(rules_name(RULE_NONE) == NULL, "RULE_NONE n'est pas une règle");
    CHECK(rules_name(RULE_COUNT) == NULL, "RULE_COUNT non plus");
    CHECK(rules_name(-1) == NULL, "ni -1");
    for (int r = 1; r < RULE_COUNT; r++) CHECK_EQ(rules_by_name(rules_name(r)), r, "rules_by_name est l'inverse de rules_name");
    CHECK_EQ(rules_by_name("n'existe_pas"), -1, "nom inconnu → -1");
    CHECK_EQ(rules_by_name(NULL), -1, "NULL → -1");
}

static void t_reglages_valides_et_invalides(void) {
    RulesConfig cfg;
    rules_config_default(&cfg);
    int en; uint32_t th;
    CHECK_EQ(rules_set_enabled(&cfg, RULE_XMAS_SCAN, 0), 0, "désactiver xmas_scan");
    rules_get(&cfg, RULE_XMAS_SCAN, &en, &th);
    CHECK_EQ(en, 0, "elle est désactivée");
    CHECK_EQ(rules_set_enabled(&cfg, RULE_XMAS_SCAN, 7), 0, "toute valeur non nulle active");
    rules_get(&cfg, RULE_XMAS_SCAN, &en, NULL);
    CHECK_EQ(en, 1, "activée (normalisé à 1)");
    CHECK_EQ(rules_set_threshold(&cfg, RULE_PORT_SCAN, 50), 0, "seuil de port_scan à 50");
    rules_get(&cfg, RULE_PORT_SCAN, NULL, &th);
    CHECK_EQ(th, 50, "50 relu");
    CHECK_EQ(rules_set_threshold(&cfg, RULE_PORT_SCAN, 0), -1, "seuil 0 refusé");
    rules_get(&cfg, RULE_PORT_SCAN, NULL, &th);
    CHECK_EQ(th, 50, "et l'ancien seuil est gardé");
    CHECK_EQ(rules_set_threshold(&cfg, RULE_NULL_SCAN, 5), -1, "null_scan n'a pas de seuil → -1");
    CHECK_EQ(rules_set_enabled(&cfg, RULE_NONE, 1), -1, "RULE_NONE → -1");
    CHECK_EQ(rules_set_enabled(&cfg, RULE_COUNT, 1), -1, "RULE_COUNT → -1");
    CHECK_EQ(rules_set_enabled(&cfg, 99, 1), -1, "99 → -1");
    CHECK_EQ(rules_set_enabled(NULL, RULE_PORT_SCAN, 1), -1, "cfg NULL → -1");
    CHECK_EQ(rules_set_threshold(NULL, RULE_PORT_SCAN, 5), -1, "cfg NULL → -1");
    CHECK_EQ(rules_get(NULL, RULE_PORT_SCAN, &en, &th), -1, "rules_get(NULL) → -1");
    CHECK_EQ(rules_get(&cfg, 99, &en, &th), -1, "rules_get(99) → -1");
    CHECK_EQ(rules_has_threshold(RULE_PORT_SCAN), 1, "port_scan a un seuil");
    CHECK_EQ(rules_has_threshold(RULE_FLOOD), 1, "flood a un seuil");
    CHECK_EQ(rules_has_threshold(RULE_FIN_SCAN), 0, "fin_scan n'en a pas");
    rules_config_default(NULL);                       /* ne plante pas */
}

/* ───────────── port_scan ───────────── */

static void t_port_scan(void) {
    RulesConfig cfg; rules_config_default(&cfg);
    struct PortMap pm; portmap_init(&pm);
    for (int p = 1; p <= 19; p++) portmap_add(&pm, (uint16_t)p);
    CHECK_EQ(rule_port_scan(NULL, &pm, &cfg).verdict, UNKNOW, "19 ports : pas d'avis");
    CHECK_EQ(rule_port_scan(NULL, &pm, &cfg).reason, RULE_NONE, "…et pas de règle");
    portmap_add(&pm, 20);
    FlowRuleResult r = rule_port_scan(NULL, &pm, &cfg);
    CHECK_EQ(r.verdict, BLOCK, "20 ports : BLOCK");
    CHECK_EQ(r.reason, RULE_PORT_SCAN, "RULE_PORT_SCAN");
    rules_set_threshold(&cfg, RULE_PORT_SCAN, 21);
    CHECK_EQ(rule_port_scan(NULL, &pm, &cfg).verdict, UNKNOW, "seuil relevé à 21 : plus de blocage");
    rules_set_threshold(&cfg, RULE_PORT_SCAN, 10);
    CHECK_EQ(rule_port_scan(NULL, &pm, &cfg).verdict, BLOCK, "seuil abaissé à 10 : blocage");
    rules_set_enabled(&cfg, RULE_PORT_SCAN, 0);
    CHECK_EQ(rule_port_scan(NULL, &pm, &cfg).verdict, UNKNOW, "désactivée : pas d'avis");
    CHECK_EQ(rule_port_scan(NULL, NULL, &cfg).verdict, UNKNOW, "sans PortMap : pas d'avis");
}

/* ───────────── NULL / Xmas / FIN ───────────── */

static void t_scans_tcp_detectes(void) {
    RulesConfig cfg; rules_config_default(&cfg);
    FlowData nul  = tcp_flow(0, 0, 0, 0, 0, 0);
    FlowData xmas = tcp_flow(0, 0, 1, 0, 1, 1);
    FlowData fin  = tcp_flow(0, 0, 1, 0, 0, 0);
    CHECK_EQ(rule_null_scan(&nul, NULL, &cfg).verdict, BLOCK, "NULL : BLOCK");
    CHECK_EQ(rule_null_scan(&nul, NULL, &cfg).reason, RULE_NULL_SCAN, "NULL : raison");
    CHECK_EQ(rule_xmas_scan(&xmas, NULL, &cfg).verdict, BLOCK, "Xmas : BLOCK");
    CHECK_EQ(rule_xmas_scan(&xmas, NULL, &cfg).reason, RULE_XMAS_SCAN, "Xmas : raison");
    CHECK_EQ(rule_fin_scan(&fin, NULL, &cfg).verdict, BLOCK, "FIN : BLOCK");
    CHECK_EQ(rule_fin_scan(&fin, NULL, &cfg).reason, RULE_FIN_SCAN, "FIN : raison");
    /* chaque règle ne voit que son scan */
    CHECK_EQ(rule_xmas_scan(&nul, NULL, &cfg).verdict, UNKNOW, "un NULL n'est pas un Xmas");
    CHECK_EQ(rule_fin_scan(&xmas, NULL, &cfg).verdict, UNKNOW, "un Xmas n'est pas un FIN seul (il a PSH et URG)");
    CHECK_EQ(rule_null_scan(&fin, NULL, &cfg).verdict, UNKNOW, "un FIN n'est pas un NULL");
}

static void t_trafic_tcp_normal_laisse_tranquille(void) {
    RulesConfig cfg; rules_config_default(&cfg);
    struct { const char *nom; FlowData d; } ok[] = {
        { "SYN seul (début de connexion)",    tcp_flow(1, 0, 0, 0, 0, 0) },
        { "SYN + SYN-ACK",                     tcp_flow(2, 1, 0, 0, 0, 0) },
        { "ACK seul (milieu de flux)",        tcp_flow(0, 5, 0, 0, 0, 0) },
        { "PSH + ACK (données)",              tcp_flow(0, 5, 0, 0, 3, 0) },
        { "FIN + ACK (fermeture normale)",    tcp_flow(0, 5, 2, 0, 0, 0) },
        { "RST seul (connexion refusée)",     tcp_flow(0, 0, 0, 1, 0, 0) },
        { "SYN puis FIN dans le même flux",   tcp_flow(1, 2, 1, 0, 0, 0) },
    };
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        FlowRuleResult r = rules_check_all(&ok[i].d, NULL, &cfg);
        CHECK_EQ(r.verdict, UNKNOW, ok[i].nom);
    }
    /* une règle TCP ignore ce qui n'est pas TCP, même avec des compteurs à zéro */
    FlowData udp = datagram_flow(UDP, 1, 0, 0, 0);
    CHECK_EQ(rule_null_scan(&udp, NULL, &cfg).verdict, UNKNOW, "un flux UDP n'est jamais un NULL scan");
    CHECK_EQ(rule_fin_scan(NULL, NULL, &cfg).verdict, UNKNOW, "data NULL → pas d'avis");
    FlowData nul = tcp_flow(0, 0, 0, 0, 0, 0);
    nul.flag_count.ece = 1;
    CHECK_EQ(rule_null_scan(&nul, NULL, &cfg).verdict, UNKNOW, "ECE présent : ce n'est pas « aucun drapeau »");
}

static void t_scans_tcp_desactivables(void) {
    RulesConfig cfg; rules_config_default(&cfg);
    FlowData nul = tcp_flow(0, 0, 0, 0, 0, 0), xmas = tcp_flow(0, 0, 1, 0, 1, 1), fin = tcp_flow(0, 0, 1, 0, 0, 0);
    rules_set_enabled(&cfg, RULE_NULL_SCAN, 0);
    rules_set_enabled(&cfg, RULE_XMAS_SCAN, 0);
    rules_set_enabled(&cfg, RULE_FIN_SCAN, 0);
    CHECK_EQ(rule_null_scan(&nul, NULL, &cfg).verdict, UNKNOW, "null_scan désactivée");
    CHECK_EQ(rule_xmas_scan(&xmas, NULL, &cfg).verdict, UNKNOW, "xmas_scan désactivée");
    CHECK_EQ(rule_fin_scan(&fin, NULL, &cfg).verdict, UNKNOW, "fin_scan désactivée");
    CHECK_EQ(rules_check_all(&nul, NULL, &cfg).verdict, UNKNOW, "rules_check_all : plus rien ne se déclenche");
    CHECK_EQ(rule_null_scan(&nul, NULL, NULL).verdict, UNKNOW, "cfg NULL : rien d'actif");
}

/* ───────────── flood ───────────── */

static void t_flood(void) {
    RulesConfig cfg; rules_config_default(&cfg);          /* 10000 paquets/s, mesuré sur 100 ms au moins */
    FlowData d = datagram_flow(UDP, 999, 0, 5000, 5000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, UNKNOW, "999 paquets en 0 ms (compté 100 ms) = 9990/s : sous le seuil");
    d.n_pkt_ltr = 1000;
    FlowRuleResult r = rule_flood(&d, NULL, &cfg);
    CHECK_EQ(r.verdict, LIMIT_REACHED, "1000 paquets sur la fenêtre minimale = 10000/s : LIMIT_REACHED");
    CHECK_EQ(r.reason, RULE_FLOOD, "RULE_FLOOD");
    d = datagram_flow(UDP, 1000, 0, 5000, 5400);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, UNKNOW, "1000 paquets en 400 ms = 2500/s : tranquille");
    d = datagram_flow(UDP, 50000, 0, 5000, 6000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, LIMIT_REACHED, "50000 paquets en 1 s : flood");
    d = datagram_flow(ICMP, 50000, 49000, 5000, 6000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, LIMIT_REACHED, "ICMP aussi, même avec des réponses (un ping flood est répondu)");
    d = datagram_flow(ICMPV6, 50000, 0, 5000, 6000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, LIMIT_REACHED, "ICMPv6 aussi");
    d = datagram_flow(TCP, 50000, 0, 5000, 6000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, UNKNOW, "TCP : pas concerné (un SYN flood demande des compteurs par IP)");
    d = datagram_flow(UDP, 50000, 0, 6000, 5000);        /* horloge qui recule : jamais de division par un nombre négatif */
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, LIMIT_REACHED, "end < start : durée comptée 100 ms, pas de plantage");
    d = datagram_flow(UDP, 50000, 0, 5000, 6000);
    rules_set_threshold(&cfg, RULE_FLOOD, 100000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, UNKNOW, "seuil relevé à 100000/s : plus de marquage");
    rules_set_threshold(&cfg, RULE_FLOOD, 1000);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, LIMIT_REACHED, "seuil abaissé à 1000/s : marquage");
    rules_set_enabled(&cfg, RULE_FLOOD, 0);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, UNKNOW, "désactivée");
    d.n_pkt_ltr = 4000000000u;                            /* très gros compteur : pas de débordement du calcul */
    rules_set_enabled(&cfg, RULE_FLOOD, 1);
    rules_set_threshold(&cfg, RULE_FLOOD, 4000000u);
    CHECK_EQ(rule_flood(&d, NULL, &cfg).verdict, LIMIT_REACHED, "4 milliards de paquets en 1 s : calcul en 64 bits");
}

/* ───────────── rules_check_all ───────────── */

static void t_check_all_priorites(void) {
    RulesConfig cfg; rules_config_default(&cfg);
    struct PortMap pm; portmap_init(&pm);
    for (int p = 1; p <= 25; p++) portmap_add(&pm, (uint16_t)p);
    FlowData udp = datagram_flow(UDP, 50000, 0, 5000, 6000);     /* flood ET scan de ports : BLOCK doit l'emporter */
    FlowRuleResult r = rules_check_all(&udp, &pm, &cfg);
    CHECK_EQ(r.verdict, BLOCK, "scan de ports + flood : BLOCK l'emporte");
    CHECK_EQ(r.reason, RULE_PORT_SCAN, "avec la raison du scan");
    rules_set_enabled(&cfg, RULE_PORT_SCAN, 0);
    r = rules_check_all(&udp, &pm, &cfg);
    CHECK_EQ(r.verdict, LIMIT_REACHED, "scan désactivé : reste le flood");
    CHECK_EQ(r.reason, RULE_FLOOD, "raison flood");
    rules_set_enabled(&cfg, RULE_FLOOD, 0);
    r = rules_check_all(&udp, &pm, &cfg);
    CHECK_EQ(r.verdict, UNKNOW, "tout désactivé : pas d'avis");
    CHECK_EQ(r.reason, RULE_NONE, "pas de raison");
    CHECK_EQ(rules_check_all(&udp, &pm, NULL).verdict, UNKNOW, "cfg NULL : pas d'avis");
    FlowData nul = tcp_flow(0, 0, 0, 0, 0, 0);
    rules_config_default(&cfg);
    CHECK_EQ(rules_check_all(&nul, &pm, &cfg).reason, RULE_NULL_SCAN, "NULL est testé avant le scan de ports (plus bon marché)");
}

/* ───────────── changements à chaud pendant que d'autres threads évaluent ───────────── */

struct Shared { RulesConfig cfg; atomic_int stop; atomic_int errors; };

static void *checker(void *a) {
    struct Shared *sh = a;
    struct PortMap pm; portmap_init(&pm);
    for (int p = 1; p <= 50; p++) portmap_add(&pm, (uint16_t)p);
    FlowData nul = tcp_flow(0, 0, 0, 0, 0, 0);
    while (!atomic_load(&sh -> stop)) {
        FlowRuleResult r = rules_check_all(&nul, &pm, &sh -> cfg);
        /* soit pas d'avis (aucune règle), soit un BLOCK par une des DEUX règles ; jamais un mélange */
        int ok = (r.verdict == UNKNOW && r.reason == RULE_NONE) ||
                 (r.verdict == BLOCK && (r.reason == RULE_NULL_SCAN || r.reason == RULE_PORT_SCAN));
        if (!ok) atomic_fetch_add(&sh -> errors, 1);
    }
    return NULL;
}

static void t_changements_a_chaud_en_parallele(void) {
    struct Shared sh;
    rules_config_default(&sh.cfg);
    atomic_init(&sh.stop, 0); atomic_init(&sh.errors, 0);
    pthread_t th[3];
    for (int i = 0; i < 3; i++) pthread_create(&th[i], NULL, checker, &sh);
    for (int i = 0; i < 200000; i++) {
        rules_set_enabled(&sh.cfg, RULE_NULL_SCAN, i & 1);
        rules_set_enabled(&sh.cfg, RULE_PORT_SCAN, (i >> 1) & 1);
        rules_set_threshold(&sh.cfg, RULE_PORT_SCAN, 1 + (uint32_t)(i % 100));
        int en; uint32_t t;
        rules_get(&sh.cfg, RULE_PORT_SCAN, &en, &t);
    }
    atomic_store(&sh.stop, 1);
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);
    CHECK_EQ(atomic_load(&sh.errors), 0, "200 000 changements pendant 3 lecteurs : jamais de résultat incohérent");
}

int main(int argc, char **argv) {
    tc_begin("test_rules.c", argc, argv);
    RUN_LEAKS("valeurs par défaut et noms",                 t_defauts_et_noms);
    RUN_LEAKS("réglages : valides et invalides",            t_reglages_valides_et_invalides);
    RUN_LEAKS("port_scan : seuil, désactivation",           t_port_scan);
    RUN_LEAKS("NULL / Xmas / FIN : détectés",               t_scans_tcp_detectes);
    RUN_LEAKS("trafic TCP normal : laissé tranquille",      t_trafic_tcp_normal_laisse_tranquille);
    RUN_LEAKS("NULL / Xmas / FIN : désactivables",          t_scans_tcp_desactivables);
    RUN_LEAKS("flood : débit, protocoles, limites",         t_flood);
    RUN_LEAKS("rules_check_all : priorités",                t_check_all_priorites);
    RUN_LEAKS("réglages à chaud, 3 lecteurs en parallèle",  t_changements_a_chaud_en_parallele);
    return tc_end();
}
