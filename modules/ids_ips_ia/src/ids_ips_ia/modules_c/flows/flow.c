#include "flow.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void FlowKey_print(const void *k){
    if (k == NULL){
        printf("FlowKeyType: NULL\n");
        return;
    }

    /* Le premier champ de chaque struct est l'enum "key".
     * On lit son int pour savoir quoi caster. */
    FlowKeyType tag = *(const FlowKeyType *)k;

    if (tag == FlowKeyIpv4Type){
        const FlowKeyIpv4 *v4 = (const FlowKeyIpv4 *)k;
        printf("FlowKeyType{ipv4, proto=%u,\n", v4->proto);
        printf("  ip_min  = %u.%u.%u.%u\n",
               v4->ip_min[0], v4->ip_min[1], v4->ip_min[2], v4->ip_min[3]);
        printf("  ip_max  = %u.%u.%u.%u\n",
               v4->ip_max[0], v4->ip_max[1], v4->ip_max[2], v4->ip_max[3]);
        printf("  port_min = %u, port_max = %u}\n",
               ((uint16_t)v4->port_min[0] << 8) | v4->port_min[1],
               ((uint16_t)v4->port_max[0] << 8) | v4->port_max[1]);
    }
    else if (tag == FlowKeyIpv6Type){
        const FlowKeyIpv6 *v6 = (const FlowKeyIpv6 *)k;
        printf("FlowKeyType{ipv6, proto=%u,\n", v6->proto);
        printf("  ip_min  = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
               v6->ip_min[0], v6->ip_min[1], v6->ip_min[2],  v6->ip_min[3],
               v6->ip_min[4], v6->ip_min[5], v6->ip_min[6],  v6->ip_min[7],
               v6->ip_min[8], v6->ip_min[9], v6->ip_min[10], v6->ip_min[11],
               v6->ip_min[12], v6->ip_min[13], v6->ip_min[14], v6->ip_min[15]);
        printf("  ip_max  = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
               v6->ip_max[0], v6->ip_max[1], v6->ip_max[2],  v6->ip_max[3],
               v6->ip_max[4], v6->ip_max[5], v6->ip_max[6],  v6->ip_max[7],
               v6->ip_max[8], v6->ip_max[9], v6->ip_max[10], v6->ip_max[11],
               v6->ip_max[12], v6->ip_max[13], v6->ip_max[14], v6->ip_max[15]);
        printf("  port_min = %u, port_max = %u}\n",
               ((uint16_t)v6->port_min[0] << 8) | v6->port_min[1],
               ((uint16_t)v6->port_max[0] << 8) | v6->port_max[1]);
    }
    else {
        printf("FlowKeyType{tag inconnu = %d}\n", (int)tag);
    }
}

/* ───────────── lire un ParserResult ───────────── */

// Les 5 infos d'une conversation, lues dans un ParserResult. Retourne 0 = ok, -1 = pas un paquet IP (ARP, NULL...).
// Les pointeurs pointent DANS pr (rien n'est copié). Pour ICMP et les autres protocoles, les ports pointent vers des zéros.
int pr_tuple(const ParserResult *pr, PacketTuple *t){
    static const uint8_t zero_port[L_PORT] = {0, 0};
    if (pr == NULL || t == NULL) return -1;
    if (pr -> type == IPV4){
        t -> v4 = 1;
        t -> src_ip = pr -> ip_data.ipv4.src_ip;
        t -> dst_ip = pr -> ip_data.ipv4.dst_ip;
        t -> proto = pr -> ip_data.ipv4.proto;
    } else if (pr -> type == IPV6){
        t -> v4 = 0;
        t -> src_ip = pr -> ip_data.ipv6.src_ip;
        t -> dst_ip = pr -> ip_data.ipv6.dst_ip;
        t -> proto = pr -> ip_data.ipv6.next_header;
    } else {
        return -1;
    }
    t -> src_port = zero_port;
    t -> dst_port = zero_port;
    if (t -> proto == (uint8_t)TCP){
        t -> src_port = pr -> data.tcp.src_port;
        t -> dst_port = pr -> data.tcp.dst_port;
    } else if (t -> proto == (uint8_t)UDP){
        t -> src_port = pr -> data.udp.src_port;
        t -> dst_port = pr -> data.udp.dst_port;
    }
    return 0;
}

// Ajoute 1 à chaque compteur dont le bit est levé dans l'octet de flags TCP
static void _count_flags(struct _FlagSeens *c, uint8_t f){
    c -> syn += (f & SYN) ? 1 : 0;
    c -> ack += (f & ACK) ? 1 : 0;
    c -> fin += (f & FIN) ? 1 : 0;
    c -> rst += (f & RST) ? 1 : 0;
    c -> psh += (f & PSH) ? 1 : 0;
    c -> urg += (f & URG) ? 1 : 0;
    c -> ece += (f & ECE) ? 1 : 0;
    c -> cwr += (f & CWR) ? 1 : 0;
}

/* ───────────── la clé de flux ───────────── */

// Clé canonique : A→B et B→A donnent la même clé. Retourne 0 = ok, -1 = erreur.
// Le côté « min » est celui qui a la plus petite IP (si les IP sont égales : le plus petit port).
// Le port suit son IP : port_min est le port de la machine qui a ip_min.
int build_flow_key(void *key, const uint8_t *src_ip, const uint8_t *dst_ip, const uint8_t *src_port, const uint8_t *dst_port, uint8_t proto, int v4){
    if ((v4 != 0 && v4 != 1) || key == NULL){
        return -1;
    }
    int len = v4 ? L_IPV4 : L_IPV6;
    int r = memcmp(src_ip, dst_ip, len);
    if (r == 0){
        r = memcmp(src_port, dst_port, L_PORT);   // IP identiques : on départage avec les ports
    }
    int src_is_min = r <= 0;                      // égalité complète : src = min, arbitraire
    const uint8_t *ip_min = src_is_min ? src_ip : dst_ip;
    const uint8_t *ip_max = src_is_min ? dst_ip : src_ip;
    const uint8_t *port_min = src_is_min ? src_port : dst_port;
    const uint8_t *port_max = src_is_min ? dst_port : src_port;

    if (v4){
        FlowKeyIpv4 *ptr = key;
        memset(ptr, 0, sizeof(FlowKeyIpv4));
        ptr -> key = FlowKeyIpv4Type;
        memcpy(ptr -> ip_min, ip_min, len);
        memcpy(ptr -> ip_max, ip_max, len);
        memcpy(ptr -> port_min, port_min, L_PORT);
        memcpy(ptr -> port_max, port_max, L_PORT);
        ptr -> proto = proto;
    } else {
        FlowKeyIpv6 *ptr = key;
        memset(ptr, 0, sizeof(FlowKeyIpv6));
        ptr -> key = FlowKeyIpv6Type;
        memcpy(ptr -> ip_min, ip_min, len);
        memcpy(ptr -> ip_max, ip_max, len);
        memcpy(ptr -> port_min, port_min, L_PORT);
        memcpy(ptr -> port_max, port_max, L_PORT);
        ptr -> proto = proto;
    }
    return 0;
}

/* ───────────── la fiche du flux ───────────── */

// Remplit entry avec le PREMIER paquet du flux. Retourne 0 = ok, -1 = erreur (entry n'est alors pas modifiée).
// L'émetteur de ce paquet devient l'initiateur du flux.
int build_flow_entry(FlowEntry *entry, const ParserResult *pr, void *key, int v4, uint64_t now_ms){
    if (entry == NULL || pr == NULL){
        return -1;
    }
    if (pr -> code != (uint8_t)SUCCES){
        return -1;
    }
    if (v4 != 0 && v4 != 1){
        return -1;
    }
    PacketTuple t;
    if (pr_tuple(pr, &t) != 0 || t.v4 != v4){     // le paquet doit être de la version annoncée par v4
        return -1;
    }

    FlowData *d = (FlowData *)calloc(1, sizeof(FlowData));   // calloc : tout est déjà à 0 (compteurs, end_time...)
    if (d == NULL){
        return -1;
    }
    entry -> data = d;
    entry -> key = key;
    d -> v4 = (uint8_t)v4;
    d -> verdict = UNKNOW;
    d -> n_pkt_ltr = 1;                           // ce premier paquet va de l'initiateur vers le receveur
    d -> start_time = now_ms;
    d -> end_time = now_ms;
    d -> octets_data_ltr = pr -> len;             // le premier paquet compte aussi
    d -> proto = t.proto;

    if (v4){
        memcpy(d -> header.ipv4_headers.initiator_ip,   t.src_ip,   L_IPV4);
        memcpy(d -> header.ipv4_headers.initiator_port, t.src_port, L_PORT);
        memcpy(d -> header.ipv4_headers.receiver_ip,    t.dst_ip,   L_IPV4);
        memcpy(d -> header.ipv4_headers.receiver_port,  t.dst_port, L_PORT);
    } else {
        memcpy(d -> header.ipv6_headers.initiator_ip,   t.src_ip,   L_IPV6);
        memcpy(d -> header.ipv6_headers.initiator_port, t.src_port, L_PORT);
        memcpy(d -> header.ipv6_headers.receiver_ip,    t.dst_ip,   L_IPV6);
        memcpy(d -> header.ipv6_headers.receiver_port,  t.dst_port, L_PORT);
    }
    if (t.proto == (uint8_t)TCP){
        _count_flags(&d -> flag_count, pr -> data.tcp.flags);
    }
    return 0;
}

// Un paquet de plus pour un flux qui existe déjà. Retourne 0 = ok, -1 = erreur.
int entry_update(FlowEntry *entry, const ParserResult *pr, uint64_t now_ms){
    if (entry == NULL || pr == NULL){
        return -1;
    }
    if (pr -> code != (uint8_t)SUCCES){
        return -1;
    }
    if (entry -> key == NULL || entry -> data == NULL){
        return -1;
    }
    FlowData *d = entry -> data;
    PacketTuple t;
    if (pr_tuple(pr, &t) != 0 || t.v4 != d -> v4){
        return -1;
    }

    // Sens du paquet : ltr s'il vient de l'initiateur (même IP ET même port source), sinon rtl
    int len = d -> v4 ? L_IPV4 : L_IPV6;
    const uint8_t *initiator_ip   = d -> v4 ? d -> header.ipv4_headers.initiator_ip   : d -> header.ipv6_headers.initiator_ip;
    const uint8_t *initiator_port = d -> v4 ? d -> header.ipv4_headers.initiator_port : d -> header.ipv6_headers.initiator_port;
    int ltr = memcmp(t.src_ip, initiator_ip, len) == 0 && memcmp(t.src_port, initiator_port, L_PORT) == 0;
    if (ltr){
        d -> n_pkt_ltr += 1;
        d -> octets_data_ltr += pr -> len;
    } else {
        d -> n_pkt_rtl += 1;
        d -> octets_data_rtl += pr -> len;
    }
    d -> end_time = now_ms;                       // dernier paquet vu

    // Les flags TCP comptent dans les deux sens
    if (d -> proto == (uint8_t)TCP && t.proto == (uint8_t)TCP){
        _count_flags(&d -> flag_count, pr -> data.tcp.flags);
    }
    return 0;
}

/* ───────────── fonctions données au dict ───────────── */

// Convention des comparaisons (comme memcmp / strcmp) : 0 = égales, autre chose = différentes
int flow_key_compare(const void *key1, const void *key2){
    if (key1 == NULL || key2 == NULL){
        return 1;
    }
    FlowKeyType type1 = *(const FlowKeyType *)key1;
    FlowKeyType type2 = *(const FlowKeyType *)key2;
    if (type1 != type2){                          // une clé v4 n'est jamais égale à une clé v6
        return 1;
    }
    if (type1 == FlowKeyIpv4Type){
        const FlowKeyIpv4 *a = key1, *b = key2;
        return !(
            memcmp(a -> ip_min, b -> ip_min, L_IPV4) == 0 &&
            memcmp(a -> ip_max, b -> ip_max, L_IPV4) == 0 &&
            memcmp(a -> port_min, b -> port_min, L_PORT) == 0 &&
            memcmp(a -> port_max, b -> port_max, L_PORT) == 0 &&
            a -> proto == b -> proto
        );
    }
    const FlowKeyIpv6 *a = key1, *b = key2;
    return !(
        memcmp(a -> ip_min, b -> ip_min, L_IPV6) == 0 &&
        memcmp(a -> ip_max, b -> ip_max, L_IPV6) == 0 &&
        memcmp(a -> port_min, b -> port_min, L_PORT) == 0 &&
        memcmp(a -> port_max, b -> port_max, L_PORT) == 0 &&
        a -> proto == b -> proto
    );
}

void flow_key_free(void *key){
    free(key);                                    // free(NULL) ne fait rien : pas besoin de tester
}

void flow_value_free(void *value){
    free(value);
}

// Copie une clé v4 ou v6 sur le tas. NULL si key est NULL, si le type est inconnu, ou si malloc échoue.
void *flow_key_dup(const void *key){
    if (key == NULL) return NULL;
    FlowKeyType type = *(const FlowKeyType *)key;
    size_t size;
    if (type == FlowKeyIpv4Type){
        size = sizeof(FlowKeyIpv4);
    } else if (type == FlowKeyIpv6Type){
        size = sizeof(FlowKeyIpv6);
    } else {
        return NULL;
    }
    void *copy = malloc(size);
    if (copy != NULL){
        memcpy(copy, key, size);
    }
    return copy;
}

// Copie SUPERFICIELLE : les pointeurs key et data sont recopiés, pas ce qu'ils pointent
void *flow_value_dup(const void *value){
    if (value == NULL) return NULL;
    FlowEntry *copy = (FlowEntry *)malloc(sizeof(FlowEntry));
    if (copy != NULL){
        *copy = *(const FlowEntry *)value;
    }
    return copy;
}

// Retourne un hash >= 0, ou -1 si la clé est NULL ou de type inconnu
int flow_hash(const void *key){
    if (key == NULL) return -1;

    FlowKeyType type = *(const FlowKeyType *)key;
    uint32_t h = 2166136261u;

    if (type == FlowKeyIpv4Type){
        const FlowKeyIpv4 *v = (const FlowKeyIpv4 *)key;
        h = fnv1a_update(h, v -> ip_min,   L_IPV4);
        h = fnv1a_update(h, v -> ip_max,   L_IPV4);
        h = fnv1a_update(h, v -> port_min, L_PORT);
        h = fnv1a_update(h, v -> port_max, L_PORT);
        h ^= v -> proto;
        h *= 16777619u;
    } else if (type == FlowKeyIpv6Type){
        const FlowKeyIpv6 *v = (const FlowKeyIpv6 *)key;
        h = fnv1a_update(h, v -> ip_min,   L_IPV6);   // 16 octets, pas 4
        h = fnv1a_update(h, v -> ip_max,   L_IPV6);
        h = fnv1a_update(h, v -> port_min, L_PORT);
        h = fnv1a_update(h, v -> port_max, L_PORT);
        h ^= v -> proto;
        h *= 16777619u;
    } else {
        return -1;
    }

    h = fmix32(h);
    return (int)(h & 0x7FFFFFFF);                 // bit de signe à 0 : jamais négatif
}

// Le dict copie les clés (key_dup) mais garde les valeurs telles quelles (pas de value_dup) : une FlowEntry n'existe qu'une fois
Dict *create_ft_dict(uint32_t size){
    if (size == 0){
        return NULL;
    }
    return create_dict(size, flow_hash, flow_key_compare, flow_key_dup, flow_key_free, NULL, NULL);
}
