#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H
#include <stdint.h>
#include "../dict/dict.h"
#include "../dchained_list/dchained_list.h"
#include "../portmap/portmap.h"
#include "../rules/rules.h"
#include "../ipset_m/ipset_m.h"

// Où part un flux qui quitte la table : le sink COPIE ce qu'il veut de *rec (rec disparaît au retour).
typedef void (*FlowSinkFn)(const FlowRecord *rec, void *ctx);

// Réglages de la table. Tout à 0 / NULL = rien d'actif (comportement de base).
struct FlowHooks{
    uint64_t idle_ms;           // un flux sans paquet depuis idle_ms est retiré ; 0 = pas d'expiration
    uint64_t max_ms;            // un flux qui dure depuis max_ms est envoyé au sink puis repart de zéro ; 0 = pas de limite
    uint8_t close_on_tcp_end;   // 1 = un RST (ou FIN des deux côtés) retire le flux tout de suite
    FlowRuleFn check;           // règle appelée après chaque paquet ; NULL = aucune (en général rules_check_all)
    const struct RulesConfig *rules_cfg;   // les réglages donnés tels quels à check ; peuvent changer à chaud (champs atomiques). Doit vivre aussi longtemps que la table
    FlowSinkFn sink;            // reçoit chaque flux qui part ; NULL = on jette sans copier
    void *ctx;                  // donné tel quel au sink (il n'y a pas de closure en C)
};

struct FlowTable{
    uint32_t size;              // capacité maximale (nombre de flux)
    uint32_t nbr_elements;      // nombre de flux actuellement dans la table
    Dict *flow_dict;            // clé de flux → FlowEntry (pour retrouver un flux vite)
    DChainedList *flow_dcl;     // même FlowEntry, rangées de la plus ancienne (head) à la plus récente (tail)
    Dict *port_per_ip;          // IP source → PortMap (ports distincts visités)
    uint32_t n_evicted;         // nombre de flux chassés (table pleine) depuis la création
    uint32_t n_blocked_pkts;    // paquets ignorés parce que leur IP (source ou destination) est bloquée
    uint32_t n_blocked_flows;   // flux retirés parce qu'une règle a bloqué leur IP (END_BLOCKED)
    struct FlowHooks hooks;
    IpSetM *blocklist;          // liste noire : la sienne (ft_create) ou celle de l'Engine (ft_use_blocklist), partagée par toutes les tables
    int reader;                 // numéro de lecteur de CETTE table (donc de sa thread de capture) dans la liste noire
    int owns_blocklist;         // 1 = elle l'a créée et la détruira
};

// Clé du dict port_per_ip. pad sert à ce que memcmp compare toujours les mêmes octets.
struct PortPerIpKey {
    uint8_t ip[16];
    uint8_t v4;                 // 1 = IPv4 (4 premiers octets de ip), 0 = IPv6
    uint8_t pad[3];
};

typedef struct FlowTable FlowTable;

FlowTable *ft_create(uint32_t size);                             // NULL si échec ; hooks à 0 (rien d'actif)
FlowTable *ft_create_with(uint32_t size, const struct FlowHooks *hooks);   // idem, avec les réglages dès la création ; NULL si échec
void ft_destroy(FlowTable *ptr);
FlowEntry *ft_get(FlowTable *ft, const void *key);               // NULL si absent
int ft_contains(FlowTable *ft, const void *key);                 // 1 = présent, 0 = absent
int ft_can_add(FlowTable *ft);                                   // 1 = il reste de la place, 0 = table pleine
int ft_add(FlowTable *ft, const void *key, const FlowEntry *entry);   // 0 = succès, -1 = échec
void ft_evict_oldest(FlowTable *ft);                             // chasse le flux le plus ancien (la tête de la file)
int ft_process(FlowTable *ft, ParserResult *pr, uint64_t now_ms);   // 0 = succès (même si l'IP est bloquée : paquet ignoré), -1 = refusé ou échec
int ft_set_hooks(FlowTable *ft, const struct FlowHooks *hooks);  // 0 = ok, -1 = échec
int ft_expire(FlowTable *ft, uint64_t now_ms);                   // nombre de flux retirés (>= 0), -1 si ft est NULL
int ft_block_ip(FlowTable *ft, const uint8_t *ip, int v4);       // 0 = ok, -1 = échec
int ft_unblock_ip(FlowTable *ft, const uint8_t *ip, int v4);     // 0 = ok, -1 = n'était pas bloquée
int ft_is_blocked(FlowTable *ft, const uint8_t *ip, int v4);     // 1 = bloquée, 0 = non
int ft_block_ip_meta(FlowTable *ft, const uint8_t *ip, int v4, const struct IpBlockMeta *meta);   // idem ft_block_ip, avec la raison, la date et l'expiration
int ft_use_blocklist(FlowTable *ft, IpSetM *shared);             // 0 = ok, -1 = refusé (plus de slot de lecteur : la table garde sa liste). À appeler AVANT que la thread de capture ne démarre
#endif
