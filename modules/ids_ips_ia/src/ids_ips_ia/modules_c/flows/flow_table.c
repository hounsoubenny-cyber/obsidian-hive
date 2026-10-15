#include "flow_table.h"
#include "flow.h"
#include "../utils/utils.h"
#include <stdlib.h>
#include <string.h>

/* ───────────── le dict port_per_ip : clé = IP source, valeur = PortMap ───────────── */

static void *port_key_dup(const void *key){
    struct PortPerIpKey *copy = malloc(sizeof(struct PortPerIpKey));
    if (copy) *copy = *(const struct PortPerIpKey *)key;
    return copy;
}

static void port_key_free(void *key){
    free(key);
}

static int port_key_compare(const void *a, const void *b){
    return memcmp(a, b, sizeof(struct PortPerIpKey));   // 0 = égales
}

static int port_key_hash(const void *key){
    const struct PortPerIpKey *k = (const struct PortPerIpKey *)key;
    uint32_t h = 2166136261u;
    h = fnv1a_update(h, k -> ip, k -> v4 ? L_IPV4 : L_IPV6);
    h ^= k -> v4; h *= 16777619u;
    h = fmix32(h);
    return (int)(h & 0x7FFFFFFF);
}

// Remplit key à partir d'une IP de 4 octets (v4 = 1) ou de 16 octets (v4 = 0)
static void _make_ip_key(struct PortPerIpKey *key, const uint8_t *ip, int v4){
    memset(key, 0, sizeof(*key));
    key -> v4 = (uint8_t)v4;
    memcpy(key -> ip, ip, v4 ? L_IPV4 : L_IPV6);
}

// Appelée à la création d'un flux : compte ce flux pour son IP source, et note le port visité (TCP / UDP seulement)
static int _port_per_ip_add(FlowTable *ft, const struct PortPerIpKey *key, const PacketTuple *t){
    struct PortMap *pm = dict_getitem(ft -> port_per_ip, key);
    if (pm == NULL){
        pm = calloc(1, sizeof(struct PortMap));      // calloc : bitmap, count et refcount déjà à 0
        if (pm == NULL) return -1;
        if (dict_setitem(ft -> port_per_ip, key, pm) != 0){
            free(pm);
            return -1;
        }
    }
    pm -> refcount += 1;
    if (t -> proto == (uint8_t)TCP || t -> proto == (uint8_t)UDP){
        portmap_add(pm, port_to_u16(t -> dst_port));
    }
    return 0;
}

// Appelée à l'éviction d'un flux : quand le dernier flux d'une IP part, sa PortMap est libérée
static void _port_per_ip_release(FlowTable *ft, const struct PortPerIpKey *key){
    struct PortMap *pm = dict_getitem(ft -> port_per_ip, key);
    if (pm == NULL) return;
    if (pm -> refcount > 0) pm -> refcount -= 1;
    if (pm -> refcount == 0){
        dict_delitem(ft -> port_per_ip, key);         // le dict libère la PortMap (value_free = free)
    }
}

/* ───────────── création / destruction ───────────── */

FlowTable *ft_create(uint32_t size){
    if (size == 0) return NULL;
    Dict *flow_dict = create_ft_dict(size);
    Dict *port_per_ip = create_dict(size, port_key_hash, port_key_compare, port_key_dup, port_key_free, NULL, free);
    Dict *blocked = create_dict(64, port_key_hash, port_key_compare, port_key_dup, port_key_free, NULL, NULL);
    DChainedList *flow_dcl = create_dcl(size);
    FlowTable *ft = calloc(1, sizeof(FlowTable));    // calloc : hooks à 0 = rien d'actif
    if (flow_dict == NULL || port_per_ip == NULL || blocked == NULL || flow_dcl == NULL || ft == NULL){
        dict_clear(flow_dict); dict_clear(port_per_ip); dict_clear(blocked);   // dict_clear(NULL) ne fait rien
        free(flow_dcl); free(ft);
        return NULL;
    }
    ft -> flow_dcl = flow_dcl; ft -> flow_dict = flow_dict;
    ft -> port_per_ip = port_per_ip; ft -> blocked = blocked;
    ft -> size = size;
    return ft;
}

// Envoie au sink une copie à plat du flux (rien si pas de sink). Le flux n'est pas modifié.
static void _send_record(FlowTable *ft, const FlowEntry *entry, uint32_t reason){
    if (ft -> hooks.sink == NULL || entry -> data == NULL || entry -> key == NULL) return;
    FlowRecord rec;
    memset(&rec, 0, sizeof(rec));
    FlowKeyType type = *(const FlowKeyType *)entry -> key;
    memcpy(&rec.key, entry -> key, type == FlowKeyIpv4Type ? sizeof(FlowKeyIpv4) : sizeof(FlowKeyIpv6));
    rec.data = *entry -> data;
    rec.reason = reason;
    ft -> hooks.sink(&rec, ft -> hooks.ctx);
}

// Retire UN flux de partout (dict, file, PortMap) et le libère. S'il y a un sink, il reçoit d'abord une copie à plat.
// entry peut être n'importe où dans la file (tête, milieu, queue).
static void _ft_remove(FlowTable *ft, FlowEntry *entry, uint32_t reason){
    _send_record(ft, entry, reason);
    const FlowData *d = entry -> data;
    if (d != NULL){
        struct PortPerIpKey ip_key;
        _make_ip_key(&ip_key, d -> v4 ? d -> header.ipv4_headers.initiator_ip : d -> header.ipv6_headers.initiator_ip, d -> v4);
        _port_per_ip_release(ft, &ip_key);
    }
    dict_delitem(ft -> flow_dict, entry -> key);    // libère la copie de clé que le dict possédait
    free(entry -> data);                            // free(NULL) est permis
    flow_key_free(entry -> key);                    // la copie de clé que la FlowEntry possède
    if (reason == END_EVICTED) ft -> n_evicted += 1;
    ft -> nbr_elements -= 1;
    delete_entry(ft -> flow_dcl, entry);            // retire de la file ET libère la FlowEntry elle-même
}

static void _evict_oldest(FlowTable *ft, uint32_t reason){
    if (ft == NULL || ft -> flow_dcl == NULL || ft -> flow_dict == NULL) return;
    if (ft -> flow_dcl -> head == NULL) return;
    _ft_remove(ft, ft -> flow_dcl -> head, reason);
}

// Chasse le flux le plus ancien (la tête de la file) : table pleine
void ft_evict_oldest(FlowTable *ft){
    _evict_oldest(ft, END_EVICTED);
}

FlowTable *ft_create_with(uint32_t size, const struct FlowHooks *hooks){
    FlowTable *ft = ft_create(size);
    if (ft != NULL && hooks != NULL) ft -> hooks = *hooks;
    return ft;
}

void ft_destroy(FlowTable *ptr){
    if (ptr == NULL) return;
    while (ptr -> nbr_elements > 0 && ptr -> flow_dcl -> head != NULL) {
        _evict_oldest(ptr, END_SHUTDOWN);
    }
    if (ptr -> flow_dict != NULL) dict_clear(ptr -> flow_dict);
    if (ptr -> flow_dcl != NULL) free(ptr -> flow_dcl);
    if (ptr -> port_per_ip != NULL) dict_clear(ptr -> port_per_ip);
    if (ptr -> blocked != NULL) dict_clear(ptr -> blocked);
    free(ptr);
}

int ft_set_hooks(FlowTable *ft, const struct FlowHooks *hooks){
    if (ft == NULL || hooks == NULL) return -1;
    ft -> hooks = *hooks;
    return 0;
}

// Le ménage : la tête de la file est le flux au dernier paquet le plus ancien. On la retire tant qu'elle est trop vieille,
// et on s'arrête au premier flux assez récent (tous les suivants le sont aussi). Retourne le nombre de flux retirés.
int ft_expire(FlowTable *ft, uint64_t now_ms){
    if (ft == NULL) return -1;
    if (ft -> hooks.idle_ms == 0) return 0;         // expiration désactivée
    int n = 0;
    while (ft -> flow_dcl -> head != NULL){
        const FlowData *d = ft -> flow_dcl -> head -> data;
        if (d == NULL) break;
        if (now_ms < d -> end_time) break;          // l'horloge a reculé : on ne retire rien
        if (now_ms - d -> end_time < ft -> hooks.idle_ms) break;
        _ft_remove(ft, ft -> flow_dcl -> head, END_IDLE);
        n += 1;
    }
    return n;
}

/* ───────────── liste noire ───────────── */

static char BLOCKED_MARK = 1;                       // valeur du dict : seule la clé compte

int ft_block_ip(FlowTable *ft, const uint8_t *ip, int v4){
    if (ft == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return -1;
    struct PortPerIpKey key;
    _make_ip_key(&key, ip, v4);
    return dict_setitem(ft -> blocked, &key, &BLOCKED_MARK);
}

int ft_unblock_ip(FlowTable *ft, const uint8_t *ip, int v4){
    if (ft == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return -1;
    struct PortPerIpKey key;
    _make_ip_key(&key, ip, v4);
    return dict_delitem(ft -> blocked, &key);
}

int ft_is_blocked(FlowTable *ft, const uint8_t *ip, int v4){
    if (ft == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return 0;
    if (ft -> blocked -> nbr_elements == 0) return 0;   // liste vide (le cas courant) : on évite le hachage, c'est le chemin chaud
    struct PortPerIpKey key;
    _make_ip_key(&key, ip, v4);
    return dict_getitem(ft -> blocked, &key) != NULL;
}

/* ───────────── lecture ───────────── */

FlowEntry *ft_get(FlowTable *ft, const void *key){
    if (ft == NULL || key == NULL) return NULL;
    return (FlowEntry *)dict_getitem(ft -> flow_dict, key);
}

int ft_contains(FlowTable *ft, const void *key){
    return ft_get(ft, key) != NULL;                 // question : 1 = oui, 0 = non
}

int ft_can_add(FlowTable *ft){
    if (ft == NULL) return 0;
    return ft -> nbr_elements < ft -> size;         // question : 1 = oui, 0 = non
}

/* ───────────── écriture ───────────── */

// Range entry dans le dict ET dans la file. Si la clé existe déjà, on remet juste le flux en dernier.
int ft_add(FlowTable *ft, const void *key, const FlowEntry *entry){
    if (ft == NULL || key == NULL || entry == NULL) return -1;

    if (ft_contains(ft, key)){                      // déjà présent : rien à chasser
        int r1 = move_to_end(ft -> flow_dcl, (FlowEntry *)entry);
        int r2 = dict_setitem(ft -> flow_dict, key, (FlowEntry *)entry);
        return (r1 == 0 && r2 == 0) ? 0 : -1;
    }
    while (ft_can_add(ft) == 0){                    // table pleine : on chasse le plus ancien
        ft_evict_oldest(ft);
    }
    int r1 = dict_setitem(ft -> flow_dict, key, (FlowEntry *)entry);
    int r2 = add_to_end(ft -> flow_dcl, (FlowEntry *)entry, 0);
    ft -> nbr_elements += 1;
    return (r1 == 0 && r2 == 0) ? 0 : -1;
}

// Après chaque paquet : la règle donne un FlowRuleResult. Un verdict (hors UNKNOW) est gardé dans le flux avec la règle qui l'a donné.
// BLOCK : l'IP initiatrice va sur la liste noire, sa PortMap est remise à zéro (si l'admin la débloque, elle repart de 0 au lieu
// d'être re-bloquée au paquet suivant), et le flux est envoyé au sink (END_BLOCKED) puis retiré : plus rien ne le fera vivre.
// Ensuite : un flux TCP fini est retiré ; un flux trop long est envoyé puis repart de zéro.
// À appeler en DERNIER : le flux peut être libéré ici.
static void _after_packet(FlowTable *ft, FlowEntry *entry, uint64_t now_ms){
    FlowData *d = entry -> data;
    if (ft -> hooks.check != NULL){
        struct PortPerIpKey ip_key;
        const uint8_t *ip = d -> v4 ? d -> header.ipv4_headers.initiator_ip : d -> header.ipv6_headers.initiator_ip;
        _make_ip_key(&ip_key, ip, d -> v4);
        FlowRuleResult r = ft -> hooks.check(d, (const struct PortMap *)dict_getitem(ft -> port_per_ip, &ip_key), ft -> hooks.rules_cfg);
        if (r.verdict != UNKNOW){                   // UNKNOW = pas d'avis : on garde l'ancien verdict (et sa règle)
            d -> verdict = r.verdict;
            d -> rule_reason = (uint8_t)r.reason;
        }
        if (r.verdict == BLOCK){
            ft_block_ip(ft, ip, d -> v4);           // si la liste noire est pleine (-1), le flux part quand même : Python bloquera
            struct PortMap *pm = dict_getitem(ft -> port_per_ip, &ip_key);
            if (pm != NULL) portmap_reset(pm);      // remet les ports et le compteur à 0 ; garde refcount (les autres flux de l'IP existent encore)
            ft -> n_blocked_flows += 1;
            _ft_remove(ft, entry, END_BLOCKED);     // envoie au sink PUIS retire ; entry et d n'existent plus après
            return;
        }
    }
    if (ft -> hooks.close_on_tcp_end && d -> proto == (uint8_t)TCP && (d -> flag_count.rst > 0 || d -> flag_count.fin >= 2)){
        _ft_remove(ft, entry, END_TCP_CLOSED);
        return;                                     // le flux n'existe plus : rien d'autre à faire
    }
    // Durée max : on envoie un instantané (ce paquet y est compté), puis le flux repart de zéro mais RESTE dans la table.
    // L'initiateur, le proto et le verdict sont gardés ; la PortMap de l'IP n'est pas touchée.
    if (ft -> hooks.max_ms > 0 && now_ms >= d -> start_time && now_ms - d -> start_time >= ft -> hooks.max_ms){
        _send_record(ft, entry, END_MAX_DURATION);
        memset(&d -> flag_count, 0, sizeof(d -> flag_count));
        d -> n_pkt_ltr = 0;
        d -> n_pkt_rtl = 0;
        d -> octets_data_ltr = 0;
        d -> octets_data_rtl = 0;
        d -> start_time = now_ms;
        d -> end_time = now_ms;
    }
}

// Le point d'entrée : un paquet parsé arrive. now_ms = heure réelle en ms (realtime_ms() en prod, une fausse heure dans les tests).
// Ordre : IP bloquée (source OU destination) ? → ménage → fiche → règles.
// 0 = succès (un paquet d'une IP bloquée est ignoré, pas une erreur), -1 = refusé.
// La destination compte aussi : sinon les réponses de la victime à un attaquant bloqué (RST, SYN-ACK retransmis) créeraient de faux flux
// « initiés par la victime », dont les ports visités sont ceux de l'attaquant.
int ft_process(FlowTable *ft, ParserResult *pr, uint64_t now_ms){
    if (ft == NULL || pr == NULL) return -1;
    if (pr -> code != (uint8_t)SUCCES) return -1;

    PacketTuple t;
    if (pr_tuple(pr, &t) != 0) return -1;           // pas de l'IP (ARP...) : on refuse

    if (ft_is_blocked(ft, t.src_ip, t.v4) || ft_is_blocked(ft, t.dst_ip, t.v4)){   // IP bloquée : on ne stocke RIEN pour elle
        ft -> n_blocked_pkts += 1;
        return 0;
    }
    ft_expire(ft, now_ms);

    // La clé locale vit sur la pile : une boîte assez grande pour une clé v4 OU v6
    union { FlowKeyIpv4 k4; FlowKeyIpv6 k6; } key;
    if (build_flow_key(&key, t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.proto, t.v4) != 0)
        return -1;

    // Flux déjà connu : on met à jour sa fiche et on le passe en dernier dans la file
    FlowEntry *existing = ft_get(ft, &key);
    if (existing != NULL){
        if (entry_update(existing, pr, now_ms) != 0) return -1;
        move_to_end(ft -> flow_dcl, existing);
        _after_packet(ft, existing, now_ms);
        return 0;
    }

    // Nouveau flux
    FlowEntry *new_entry = (FlowEntry *)calloc(1, sizeof(FlowEntry));
    if (new_entry == NULL) return -1;
    void *key_copy = flow_key_dup(&key);            // la FlowEntry possède SA copie (le dict en fait une autre)
    if (key_copy == NULL || build_flow_entry(new_entry, pr, key_copy, t.v4, now_ms) != 0){
        flow_key_free(key_copy);
        free(new_entry);
        return -1;
    }
    if (ft_add(ft, key_copy, new_entry) != 0){      // ft_add gère l'éviction, le dict et la file
        free(new_entry -> data);
        flow_key_free(key_copy);
        free(new_entry);
        return -1;
    }

    // Le flux est en place : on le compte pour son IP source et on note le port visité
    struct PortPerIpKey ip_key;
    _make_ip_key(&ip_key, t.src_ip, t.v4);
    if (_port_per_ip_add(ft, &ip_key, &t) != 0) return -1;
    _after_packet(ft, new_entry, now_ms);
    return 0;
}
