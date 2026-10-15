#ifndef FLOW_H
#define FLOW_H
#include "../parser/parser.h"
#include "../dict/dict.h"
#include "../utils/utils.h"
#include <stdint.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * CONVENTIONS (les mêmes dans tous les modules)
 *   action (fait quelque chose)      : 0 = succès, -1 = échec
 *   question (oui / non)             : 1 = oui,    0 = non     (ft_contains, ft_can_add...)
 *   comparaison (comme memcmp)       : 0 = égaux,  autre chose = différents
 *   fonction qui rend un pointeur    : NULL = introuvable ou échec
 *   drapeau « v4 »                   : 1 = IPv4,   0 = IPv6
 * ───────────────────────────────────────────────────────────────────────────── */

enum FlowKeyType{
    FlowKeyIpv4Type,
    FlowKeyIpv6Type,
};

enum FlowVerdict{
    UNKNOW = 0,
    BLOCK = 1,
    LIMIT_REACHED = 2,
};

typedef enum FlowVerdict FlowVerdict;
typedef enum FlowKeyType FlowKeyType;

struct FlowKeyIpv4{
    FlowKeyType key;
    uint8_t ip_min[L_IPV4];
    uint8_t ip_max[L_IPV4];
    uint8_t port_min[L_PORT];
    uint8_t port_max[L_PORT];
    uint8_t proto;
};

struct FlowKeyIpv6{
    FlowKeyType key;
    uint8_t ip_min[L_IPV6];
    uint8_t ip_max[L_IPV6];
    uint8_t port_min[L_PORT];
    uint8_t port_max[L_PORT];
    uint8_t proto;
};

struct Ipv4EntryData{
    uint8_t initiator_ip[L_IPV4];
    uint8_t initiator_port[L_PORT];
    uint8_t receiver_ip[L_IPV4];
    uint8_t receiver_port[L_PORT];
};

struct Ipv6EntryData{
    uint8_t initiator_ip[L_IPV6];
    uint8_t initiator_port[L_PORT];
    uint8_t receiver_ip[L_IPV6];
    uint8_t receiver_port[L_PORT];
};

struct _FlagSeens{
    uint32_t rst;
    uint32_t syn;
    uint32_t ack;
    uint32_t fin;
    uint32_t urg;
    uint32_t cwr;
    uint32_t ece;
    uint32_t psh;
};

// ltr = left to rigth; rtl = rigth to left
struct FlowData{
    uint8_t v4;                 // 1 = IPv4 (on lit ipv4_headers), 0 = IPv6 (on lit ipv6_headers)
    union{
        struct Ipv4EntryData ipv4_headers;
        struct Ipv6EntryData ipv6_headers;
    } header;
    uint64_t start_time;        // ms depuis 1970 : premier paquet du flux (comme time.time() * 1000 en Python)
    uint64_t end_time;          // ms depuis 1970 : DERNIER paquet vu (mis à jour à chaque paquet)
    struct _FlagSeens flag_count;
    uint32_t n_pkt_ltr;
    uint32_t n_pkt_rtl;
    uint64_t octets_data_ltr;   // somme des pr.len (trame entière : Ethernet + IP + TCP + données)
    uint64_t octets_data_rtl;   // uint64 : un uint32 déborde à 4 Go
    uint8_t proto;
    FlowVerdict verdict;
};
typedef struct FlowData FlowData;

struct FlowEntry{
    void *key;
    FlowData* data;
    /* liens pour la liste LRU */
    struct FlowEntry *lru_prev;
    struct FlowEntry *lru_next;
    uint32_t dcl_pos;
};
typedef struct FlowEntry FlowEntry;

// Pourquoi un flux quitte la table (champ reason de FlowRecord)
enum FlowEndReason{
    END_IDLE = 1,               // inactif depuis trop longtemps
    END_TCP_CLOSED = 2,         // RST, ou FIN des deux côtés
    END_EVICTED = 3,            // table pleine : le plus ancien est chassé
    END_SHUTDOWN = 4,           // ft_destroy : on vide la table
    END_MAX_DURATION = 5,       // le flux dure depuis max_ms : on envoie un instantané, puis il repart de zéro (il RESTE dans la table)
    END_RULE_BLOCKED = 6,       // FLUX SIGNALER PAR UNE RÈGLE
};

// Copie À PLAT d'un flux qui part (aucun pointeur) : c'est ça qu'on envoie dans le ring, lisible par Python
struct FlowRecord{
    union { struct FlowKeyIpv4 k4; struct FlowKeyIpv6 k6; } key;   // le type est dans le 1er champ de la clé
    FlowData data;
    uint32_t reason;            // une valeur de FlowEndReason
};
typedef struct FlowRecord FlowRecord;
typedef struct FlowKeyIpv4 FlowKeyIpv4;
typedef struct FlowKeyIpv6 FlowKeyIpv6;

// Les 5 infos d'une conversation, lues dans un ParserResult (les pointeurs pointent DANS le ParserResult)
struct PacketTuple{
    int v4;                     // 1 = IPv4, 0 = IPv6
    const uint8_t *src_ip;
    const uint8_t *dst_ip;
    const uint8_t *src_port;    // vers des zéros si ni TCP ni UDP
    const uint8_t *dst_port;
    uint8_t proto;
};
typedef struct PacketTuple PacketTuple;

int pr_tuple(const ParserResult *pr, PacketTuple *t);   // 0 = ok, -1 = pas un paquet IP
int build_flow_key(void *key, const uint8_t *src_ip, const uint8_t *dst_ip, const uint8_t *src_port, const uint8_t *dst_port, uint8_t proto, int v4);   // 0 = ok, -1 = erreur
int build_flow_entry(FlowEntry *entry, const ParserResult *pr, void *key, int v4, uint64_t now_ms);   // 0 = ok, -1 = erreur
int entry_update(FlowEntry *entry, const ParserResult *pr, uint64_t now_ms);   // 0 = ok, -1 = erreur
int flow_hash(const void *key);                                // >= 0, ou -1 si clé invalide
int flow_key_compare(const void *key1, const void *key2);      // 0 = égales, 1 = différentes
void *flow_key_dup(const void *key);
void  flow_key_free(void *key);
void *flow_value_dup(const void *value);
void  flow_value_free(void *value);
Dict* create_ft_dict(uint32_t size);

#endif
