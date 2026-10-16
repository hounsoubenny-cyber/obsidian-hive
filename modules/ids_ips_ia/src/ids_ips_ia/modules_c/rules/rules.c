#include "rules.h"
#include <string.h>

/* ───────────── petits outils ───────────── */

static FlowRuleResult _result(FlowVerdict verdict, FlowRuleReason reason){
    FlowRuleResult r = { verdict, reason };
    return r;
}

static FlowRuleResult _no_opinion(void){
    return _result(UNKNOW, RULE_NONE);
}

static int _valid(int rule){
    return rule > (int)RULE_NONE && rule < (int)RULE_COUNT;
}

// Lectures « relaxed » : chaque réglage est indépendant, on n'a besoin que d'une valeur entière (jamais déchirée)
static int _enabled(const RulesConfig *cfg, FlowRuleReason rule){
    return cfg != NULL && atomic_load_explicit(&cfg -> rule[rule].enabled, memory_order_relaxed) != 0;
}

static uint32_t _threshold(const RulesConfig *cfg, FlowRuleReason rule){
    return atomic_load_explicit(&cfg -> rule[rule].threshold, memory_order_relaxed);
}

static int _is_tcp(const FlowData *d){
    return d != NULL && d -> proto == (uint8_t)TCP;
}

/* ───────────── les règles ───────────── */

// Scan de ports : une IP qui a touché `threshold` ports distincts ou plus
FlowRuleResult rule_port_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg){
    (void)data;
    if (!_enabled(cfg, RULE_PORT_SCAN) || ports == NULL) return _no_opinion();
    return ports -> count >= _threshold(cfg, RULE_PORT_SCAN) ? _result(BLOCK, RULE_PORT_SCAN) : _no_opinion();
}

// Scan NULL : un flux TCP où AUCUN drapeau n'a jamais été vu. Aucun trafic normal n'envoie un paquet TCP sans drapeau.
// (Les compteurs du flux comptent les deux sens : dès que la cible répond RST, ils ne sont plus à 0.
//  La règle tourne après chaque paquet, donc elle voit le premier paquet seul.)
FlowRuleResult rule_null_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg){
    (void)ports;
    if (!_enabled(cfg, RULE_NULL_SCAN) || !_is_tcp(data)) return _no_opinion();
    const struct _FlagSeens *f = &data -> flag_count;
    int none = f -> syn == 0 && f -> ack == 0 && f -> fin == 0 && f -> rst == 0 &&
               f -> psh == 0 && f -> urg == 0 && f -> ece == 0 && f -> cwr == 0;
    return none ? _result(BLOCK, RULE_NULL_SCAN) : _no_opinion();
}

// Scan Xmas : FIN + PSH + URG sans jamais de SYN, ACK ni RST (un vrai flux TCP a toujours des ACK)
FlowRuleResult rule_xmas_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg){
    (void)ports;
    if (!_enabled(cfg, RULE_XMAS_SCAN) || !_is_tcp(data)) return _no_opinion();
    const struct _FlagSeens *f = &data -> flag_count;
    int xmas = f -> fin > 0 && f -> psh > 0 && f -> urg > 0 && f -> syn == 0 && f -> ack == 0 && f -> rst == 0;
    return xmas ? _result(BLOCK, RULE_XMAS_SCAN) : _no_opinion();
}

// Scan FIN : un FIN tout seul. Une vraie fin de connexion est FIN + ACK ; un FIN sans ACK sert à sonder les ports.
FlowRuleResult rule_fin_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg){
    (void)ports;
    if (!_enabled(cfg, RULE_FIN_SCAN) || !_is_tcp(data)) return _no_opinion();
    const struct _FlagSeens *f = &data -> flag_count;
    int fin_only = f -> fin > 0 && f -> syn == 0 && f -> ack == 0 && f -> rst == 0 && f -> psh == 0 && f -> urg == 0;
    return fin_only ? _result(BLOCK, RULE_FIN_SCAN) : _no_opinion();
}

// Flood : trop de paquets par seconde envoyés par l'initiateur d'un flux UDP ou ICMP.
// Débit = n_pkt_ltr / durée, la durée comptant pour FLOOD_MIN_WINDOW_MS au moins. Ne bloque pas : marque le flux LIMIT_REACHED.
FlowRuleResult rule_flood(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg){
    (void)ports;
    if (!_enabled(cfg, RULE_FLOOD) || data == NULL) return _no_opinion();
    if (data -> proto != (uint8_t)UDP && data -> proto != (uint8_t)ICMP && data -> proto != (uint8_t)ICMPV6) return _no_opinion();
    uint64_t span = data -> end_time >= data -> start_time ? data -> end_time - data -> start_time : 0;
    if (span < FLOOD_MIN_WINDOW_MS) span = FLOOD_MIN_WINDOW_MS;
    uint64_t pps = (uint64_t)data -> n_pkt_ltr * 1000u / span;
    return pps >= _threshold(cfg, RULE_FLOOD) ? _result(LIMIT_REACHED, RULE_FLOOD) : _no_opinion();
}

// Ordre : les plus bon marché et les plus sûres d'abord
static const FlowRuleFn RULES[] = { 
    rule_null_scan, rule_xmas_scan, rule_fin_scan, rule_port_scan, rule_flood
 };

FlowRuleResult rules_check_all(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg){
    FlowRuleResult limit = _no_opinion();
    for (size_t i = 0; i < sizeof(RULES) / sizeof(RULES[0]); i++){
        FlowRuleResult r = RULES[i](data, ports, cfg);
        if (r.verdict == BLOCK) return r;                       // un blocage l'emporte sur tout
        if (r.verdict != UNKNOW && limit.verdict == UNKNOW) limit = r;
    }
    return limit;
}

/* ───────────── réglages ───────────── */

static const char *NAMES[RULE_COUNT] = { NULL, "port_scan", "null_scan", "xmas_scan", "fin_scan", "flood" };

void rules_config_default(RulesConfig *cfg){
    if (cfg == NULL) return;
    for (int i = 0; i < (int)RULE_COUNT; i++){
        atomic_store_explicit(&cfg -> rule[i].enabled, 0, memory_order_relaxed);
        atomic_store_explicit(&cfg -> rule[i].threshold, 0, memory_order_relaxed);
    }
    for (int i = 1; i < (int)RULE_COUNT; i++) atomic_store_explicit(&cfg -> rule[i].enabled, 1, memory_order_relaxed);
    atomic_store_explicit(&cfg -> rule[RULE_PORT_SCAN].threshold, SCAN_PORT_THRESHOLD, memory_order_relaxed);
    atomic_store_explicit(&cfg -> rule[RULE_FLOOD].threshold, FLOOD_PPS_THRESHOLD, memory_order_relaxed);
}

int rules_has_threshold(int rule){
    return rule == (int)RULE_PORT_SCAN || rule == (int)RULE_FLOOD;
}

int rules_set_enabled(RulesConfig *cfg, int rule, int enabled){
    if (cfg == NULL || !_valid(rule)) return -1;
    atomic_store_explicit(&cfg -> rule[rule].enabled, enabled ? 1 : 0, memory_order_relaxed);
    return 0;
}

int rules_set_threshold(RulesConfig *cfg, int rule, uint32_t threshold){
    if (cfg == NULL || !_valid(rule) || !rules_has_threshold(rule) || threshold == 0) return -1;
    atomic_store_explicit(&cfg -> rule[rule].threshold, threshold, memory_order_relaxed);
    return 0;
}

int rules_get(const RulesConfig *cfg, int rule, int *enabled, uint32_t *threshold){
    if (cfg == NULL || !_valid(rule)) return -1;
    if (enabled != NULL) *enabled = atomic_load_explicit(&cfg -> rule[rule].enabled, memory_order_relaxed) != 0;
    if (threshold != NULL) *threshold = atomic_load_explicit(&cfg -> rule[rule].threshold, memory_order_relaxed);
    return 0;
}

const char *rules_name(int rule){
    return _valid(rule) ? NAMES[rule] : NULL;
}

int rules_by_name(const char *name){
    if (name == NULL) return -1;
    for (int i = 1; i < (int)RULE_COUNT; i++){
        if (strcmp(NAMES[i], name) == 0) return i;
    }
    return -1;
}
