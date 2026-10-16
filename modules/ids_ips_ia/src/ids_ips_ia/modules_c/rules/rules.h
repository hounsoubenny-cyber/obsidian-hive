#ifndef RULES_H
#define RULES_H
#include <stdatomic.h>
#include <stdint.h>
#include "../flows/flow.h"
#include "../portmap/portmap.h"

/* ─────────────────────────────────────────────────────────────────────────────────────────────
 * Une règle = une fonction rapide qui LIT un flux et rend un FlowRuleResult { verdict, reason }.
 * Elle ne supprime rien et ne bloque rien elle-même : c'est la table de flux qui agit (flow_table.c, _after_packet).
 *   verdict UNKNOW         = « pas d'avis » (le verdict du flux ne change pas)
 *   verdict BLOCK          = l'IP initiatrice est bloquée, le flux est envoyé au sink (END_BLOCKED) puis retiré
 *   verdict LIMIT_REACHED  = le flux est marqué, rien d'autre (l'IP n'est pas bloquée)
 *
 * Réglages À CHAUD : chaque règle a un « activée » et un seuil, dans un RulesConfig dont tous les champs sont atomiques.
 * Un autre thread (Python, via l'engine) peut les changer pendant que la capture tourne ; l'effet est visible au paquet suivant.
 * Tableaux indexés par FlowRuleReason (la case RULE_NONE n'est pas utilisée).
 * ───────────────────────────────────────────────────────────────────────────────────────────── */

struct RuleSetting{
    _Atomic uint8_t enabled;        // 1 = règle active
    _Atomic uint32_t threshold;     // seuil (voir plus bas) ; 0 et ignoré pour une règle sans seuil
};

struct RulesConfig{
    struct RuleSetting rule[RULE_COUNT];
    _Atomic uint64_t block_ttl_ms;  // durée d'un blocage DÉCIDÉ PAR UNE RÈGLE, en ms (0 = pour toujours). Modifiable à chaud.
};
typedef struct RulesConfig RulesConfig;

// Une règle. data = le flux (après ce paquet), ports = la PortMap de l'IP initiatrice (peut être NULL), cfg = les réglages (NULL = rien d'actif)
typedef FlowRuleResult (*FlowRuleFn)(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);

/* Valeurs par défaut */
#define SCAN_PORT_THRESHOLD 20      // port_scan : ports distincts visités par une même IP avant de dire « scan »
#define FLOOD_PPS_THRESHOLD 10000   // flood : paquets par seconde de l'initiateur
#define FLOOD_MIN_WINDOW_MS 100     // flood : on mesure le débit sur 100 ms au moins (une rafale courte n'est pas un flood)

/* Les règles. Sens du seuil :
 *   port_scan : nombre de ports distincts          flood : paquets/seconde (UDP, ICMP, ICMPv6 ; verdict LIMIT_REACHED)
 *   null_scan, xmas_scan, fin_scan : pas de seuil, UN paquet suffit (verdict BLOCK) */
FlowRuleResult rule_port_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);
FlowRuleResult rule_null_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);
FlowRuleResult rule_xmas_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);
FlowRuleResult rule_fin_scan(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);
FlowRuleResult rule_flood(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);

// Lance toutes les règles ACTIVES. Un BLOCK l'emporte (retourné tout de suite) ; sinon le premier LIMIT_REACHED ; sinon « pas d'avis ».
// C'est cette fonction qui se met dans FlowHooks.check.
FlowRuleResult rules_check_all(const FlowData *data, const struct PortMap *ports, const struct RulesConfig *cfg);

/* Réglages (conventions du projet : action 0 = succès / -1 = échec · question 1 = oui / 0 = non).
 * rule = une valeur de FlowRuleReason entre 1 et RULE_COUNT - 1. Utilisables depuis n'importe quel thread. */
void rules_config_default(RulesConfig *cfg);                                 // tout remis aux valeurs par défaut
int rules_set_enabled(RulesConfig *cfg, int rule, int enabled);              // -1 si règle inconnue
int rules_set_threshold(RulesConfig *cfg, int rule, uint32_t threshold);     // -1 si règle inconnue, sans seuil, ou seuil == 0
int rules_get(const RulesConfig *cfg, int rule, int *enabled, uint32_t *threshold);   // -1 si règle inconnue ; pointeurs facultatifs (NULL permis)
void rules_set_block_ttl(RulesConfig *cfg, uint64_t ttl_ms);                 // 0 = pour toujours
uint64_t rules_get_block_ttl(const RulesConfig *cfg);
int rules_has_threshold(int rule);                                           // question : cette règle a-t-elle un seuil ?
const char *rules_name(int rule);                                            // « port_scan »... ; NULL si règle inconnue
int rules_by_name(const char *name);                                         // l'inverse ; -1 si inconnu
#endif
