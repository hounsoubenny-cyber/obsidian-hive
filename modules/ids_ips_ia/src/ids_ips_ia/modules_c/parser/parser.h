#ifndef PARSER_H      // CORRECTION : garde d'inclusion, évite les erreurs si le .h est inclus 2 fois
#define PARSER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

enum PARSER_RETURN_CODE {
    SUCCES = 0,
    ERROR = 1,          // CORRECTION : sert maintenant aux arguments invalides (pkt == NULL)
    TOO_LITTLE = 2,     // paquet trop court pour ce qu'on doit lire
    INCOHERENCE = 3,    // le paquet se contredit (IHL < 5, longueur IP < en-tête, version != type...)
    NOT_HANDLE = 4,     // protocole valide mais non géré (ARP, ESP, GRE...)
    FRAGMENT = 5        // CORRECTION : fragment qui n'est pas le premier, il n'y a pas d'en-tête TCP/UDP dedans
};
typedef enum PARSER_RETURN_CODE PARSER_RETURN_CODE;

enum PKT_TYPE {
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    VLAN = 0x8100,
    QINQ = 0x88A8,      // Tag VLAN "extérieur" des opérateurs
    ARP = 0x0806,
};
typedef enum PKT_TYPE PKT_TYPE;

enum DATA_LEN{
    L_IPV4 = 4,
    L_IPV6 = 16,
    L_PORT = 2,
    L_MAC = 6,
    L_TYPE = 2,
    L_ARP = 28,
};
typedef enum DATA_LEN DATA_LEN ;

// Limites contre les paquets "piégés" (tags ou en-têtes empilés à l'infini)
enum PARSER_LIMITS {
    MAX_VLAN = 4,
    MAX_EXT_HEADERS = 8,
};

enum FLAGS {
    ACK = 0x10,
    RST = 0x04,
    SYN = 0x02,
    FIN = 0x01,
    PSH = 0x08,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80
};
typedef enum FLAGS FLAGS;

enum PROTOCOLS {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPV6 = 58,        // le "ping" d'IPv6 porte 58, pas 1
};
typedef enum PROTOCOLS PROTOCOLS;

struct IPV4_DATA{
    uint8_t src_ip[L_IPV4];
    uint8_t dst_ip[L_IPV4];
    uint8_t proto;
};

struct IPV6_DATA{
    uint8_t src_ip[L_IPV6];
    uint8_t dst_ip[L_IPV6];
    uint8_t next_header;
};

struct TCP_DATA{
    uint8_t src_port[L_PORT];
    uint8_t dst_port[L_PORT];
    uint8_t flags;
};

struct ICMP_DATA{
    int type;
    int code;
};
struct UDP_DATA {
    uint8_t src_port[L_PORT];
    uint8_t dst_port[L_PORT];
};

//  ARP, "qui a cette IP ? / c'est moi". Pas de couche IP : le corps suit directement Ethernet.
enum ARP_OP {
    ARP_REQUEST = 1,
    ARP_REPLY = 2,
};
struct ARP_DATA {
    uint16_t op;                    // 1 = demande, 2 = réponse
    uint8_t sender_mac[L_MAC];      // celui qui parle (à comparer avec la MAC source d'Ethernet : l'usurpation ARP)
    uint8_t sender_ip[L_IPV4];
    uint8_t target_mac[L_MAC];      // 00:00:00:00:00:00 dans une demande (c'est justement ce qu'on cherche)
    uint8_t target_ip[L_IPV4];
};
typedef struct ARP_DATA ARP_DATA;

typedef struct ICMP_DATA ICMP_DATA;
typedef struct UDP_DATA UDP_DATA;
typedef struct IPV4_DATA IPV4_DATA;
typedef struct IPV6_DATA IPV6_DATA;
typedef struct TCP_DATA TCP_DATA;

struct ParserResult{
    uint32_t len;
    uint8_t code;
    int n_vlan;
    int ip_start;
    uint16_t type;
    uint8_t ihl;        // IPv4 uniquement : reste 0 en IPv6
    uint8_t version;
    uint8_t src_mac[L_MAC];
    uint8_t dst_mac[L_MAC];
    union {
        IPV4_DATA ipv4;
        IPV6_DATA ipv6;
    } ip_data;      // lire ipv4 si version == 4, ipv6 si version == 6
    union {
        TCP_DATA tcp;
        ICMP_DATA icmp;
        UDP_DATA udp;
        ARP_DATA arp;
    } data;         // valide seulement si code == SUCCES : lire selon le protocole (ip_data.*.proto / next_header), ou arp si type == ARP
};

typedef struct ParserResult ParserResult;

ParserResult parse(const uint8_t *pkt, const int len);

#endif