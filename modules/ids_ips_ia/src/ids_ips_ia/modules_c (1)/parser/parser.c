#include "parser.h"
#include <stdint.h>
#include <string.h>

// L'en tête ethernet fait 14 octets (0 a 13) : destination 0-5, source 6-11, type 12-13
// Une en-tête IP fait au minimu 20 octets (ihl minimum = 5)
// protocole sur 1 octet se trouve ip_start + 9, src_ip a +12 sur 4 octets et dst_ip a + 16 sur 4 octets
// ipv6 en tête = 40 octets
// src_ip a +8 sur 16 octes, dst_ip a + 24 sur 16 octets
// next_header, équivalent de proto, a + 6 sur 1 octet
// next_header peut être 0, 43, 44, 60 qui indique un autre next_header, taille (valeur + 1) * 8 octets, donc boucler
// TCP: taille min 20 octets, max 60
// UDP: taille min 8 octets, max 8
// ICMP: taille min 8 octets, max VARIABLE

// ─── Règle d'or de ce fichier ───────────────────────────────────────────────────────────────
// AVANT chaque lecture d'octet, on a vérifié que cet octet existe (len, ou end plus bas).
// ET chaque boucle a un nombre de tours maximum.
// ────────────────────────────────────────────────────────────────────────────────────────────

// CORRECTION : tes 3 blocs TCP / UDP / ICMP étaient écrits 2 fois (IPv4 et IPv6). Un seul endroit
// = un seul endroit à corriger.
// `start` = début de la couche 4, `end` = fin des octets LÉGITIMES (fin du paquet IP d'après son
// propre champ longueur, jamais au-delà de len). On ne lit jamais au-delà de `end` :
// c'est ce qui évite de lire le bourrage Ethernet comme si c'était du TCP.

//=============================================================================================
// Mnémonique : "Je lis N octets → j'avance de N."
/* 

    ETHERNET

Offset  Champ              Taille   Exemple
------  -----------------  -------  ----------------
0       Destination MAC    6 o      00 11 22 33 44 55
6       Source MAC         6 o      66 77 88 99 AA BB
12      EtherType          2 o      08 00 (IPv4)
                                  / 86 DD (IPv6)
                                  / 08 06 (ARP)
                                  / 81 00 (VLAN)
------  -----------------  -------
        Total              14 o

    VLAN APRÈS LA MAC

Offset  Champ              Taille   Exemple
------  -----------------  -------  ----------------
12      TPID (type VLAN)   2 o      81 00
14      TCI                2 o      PCP(3) DEI(1) VID(12)
                                     ex: 00 64 → VLAN id 100
16      EtherType interne  2 o      08 00 (le vrai type)
------  -----------------  -------
        Total VLAN        4 o


   ARP

Offset  Champ                Taille   Valeur typique (Ethernet/IPv4)
------  -------------------  -------  ---------------------------
0       Hardware Type        2 o      0x0001 (Ethernet)
2       Protocol Type        2 o      0x0800 (IPv4)
4       Hardware Length      1 o      6 (MAC = 6 octets)
5       Protocol Length      1 o      4 (IPv4 = 4 octets)
6       Operation            2 o      1 = request, 2 = reply
8       Sender MAC           6 o      MAC de l'émetteur
14      Sender IP            4 o      IP de l'émetteur
18      Target MAC           6 o      MAC du destinataire (00:00... si inconnu)
24      Target IP            4 o      IP du destinataire
------  -------------------  -------
        Total                28 o

    IPV4

Offset  Champ                   Taille   Exemple
------  ----------------------  -------  ----------------
0       Version (4) + IHL (4)   1 o      45 (v4, IHL=5 → 20 o)   IHL = La taille de l'en-tête IP seul
1       DSCP + ECN              1 o      00
2       Total Length            2 o      00 28 (40 o)       La taille de l'en-tête IP + les données (tcp, udp, ...)
4       Identification          2 o      00 00
6       Flags (3) + Frag Off    2 o      00 00              
8       TTL                     1 o      40 (64)
9       Protocol                1 o      06 (TCP) / 11 (UDP)
                                         / 01 (ICMP)
10      Header Checksum         2 o      00 00
12      Source IP               4 o      C0 A8 00 01
16      Destination IP          4 o      C0 A8 00 02
20      Options (si IHL > 5)    0-40 o   (variable)
------  ----------------------  -------
        Total min               20 o
        Total max               60 o

offset 6 de ip

Bit :  15 14 13 | 12 11 10 9 8 7 6 5 4 3 2 1 0
      └───────┘ └───────────────────────────────┘
       Flags           Fragment Offset
       (3 bits)        (13 bits)


    IPV6
Offset  Champ                   Taille   Exemple
------  ----------------------  -------  ----------------
0       Version (4) + TC (8)    4 o      60 00 00 00
        + Flow Label (20)
4       Payload Length          2 o      00 14
6       Next Header             1 o      06 (TCP) / 11 (UDP)
                                         / 3A (ICMPv6)
                                         / 2C (Fragment)
                                         / 00 (Hop-by-Hop)
7       Hop Limit               1 o      40
8       Source Address          16 o     20 01 0D B8 ...
24      Destination Address     16 o     20 01 0D B8 ...
------  ----------------------  -------
        Total                   40 o


    Extension headers (après les 40 o, avant TCP/UDP/ICMPv6) :

Champ           Taille           Exemple
--------------  ---------------  ----------------
Next Header     1 o              code suivant
Hdr Ext Len     1 o              (sauf Fragment)
Données         variable         (multiple de 8)
--------------  ---------------
Total           (Len+1)×8        sauf Fragment = 8 fixe

    TCP
Offset  Champ                   Taille   Exemple
------  ----------------------  -------  ----------------
0       Source Port             2 o      1F 90 (8080)
2       Destination Port        2 o      00 50 (80)
4       Sequence Number         4 o      00 00 00 01
8       Acknowledgment Number   4 o      00 00 00 02
12      Data Offset(4) + Res(4) 1 o      50 (offset = 5 → 20 o)
13      Flags                   1 o      02 (SYN) / 12 (SYN+ACK)
                                         / 10 (ACK) / 11 (FIN+ACK)
14      Window                  2 o      FF FF
16      Checksum                2 o      00 00
18      Urgent Pointer          2 o      00 00
20      Options (si off > 5)    0-40 o   (variable)
------  ----------------------  -------
        Total min               20 o
        Total max               60 o

    UDP
Offset  Champ                   Taille   Exemple
------  ----------------------  -------  ----------------
0       Source Port             2 o      00 35 (53)
2       Destination Port        2 o      30 39 (12345)
4       Length                  2 o      00 08 (8 = en-tête + data)
6       Checksum                2 o      00 00
------  ----------------------  -------
        Total                   8 o

    ICMP / ICMPv6 (8 octets minimum)
Offset  Champ                   Taille   Exemple
------  ----------------------  -------  ----------------
0       Type                    1 o      08 (echo req v4)
                                         / 00 (echo reply v4)
                                         / 80 (echo req v6)
                                         / 81 (echo reply v6)
1       Code                    1 o      00
2       Checksum                2 o      00 00
4       Reste (dépend du type)  4 o      Identifier + Sequence
                                         (pour echo)
------  ----------------------  -------
        Total min               8 o


    PAQUET COMPLET — VLAN + IPv4 + TCP

┌─────────────────────────────────────────────────────────┐
│                      ETHERNET (18 o)                    │
├──────────────┬──────────────┬──────────┬──────────┬─────┤
│ Dst MAC (6)  │ Src MAC (6)  │ TPID(2)  │ TCI(2)   │ 08  │
│ 00 11 22 33  │ 66 77 88 99  │ 81 00    │ 00 64    │ 00  │
│ 44 55        │ AA BB        │          │          │     │
└──────────────┴──────────────┴──────────┴──────────┴─────┘
     offsets    0-5            12-13      14-15      16-17
                                                        │
                                                        ▼
┌─────────────────────────────────────────────────────────┐
│                       IPv4 (20 o)                       │
├────┬────┬──────┬──────┬───────┬─────┬──────────────────┤
│45  │00  │0028  │0000  │0000   │40   │06    │0000       │
│v+ihl│dscp│len  │id    │flags  │ttl  │proto │checksum   │
├────┴────┴──────┴──────┴───────┴─────┴──────────────────┤
│ Src IP: C0 A8 00 01  │  Dst IP: C0 A8 00 02             │
└─────────────────────────────────────────────────────────┘
   offsets    18-37 (20 octets)
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│                       TCP (20 o)                        │
├─────────┬─────────┬───────────┬───────────┬────┬───────┤
│1F 90    │00 50    │00000001   │00000002   │50  │02     │
│sport    │dport    │seq        │ack        │off │flags  │
├─────────┼─────────┼───────────┴───────────┴────┴───────┤
│FFFF     │0000     │0000                                 │
│window   │checksum │urgent                               │
└─────────┴─────────┴─────────────────────────────────────┘
   offsets    38-57 (20 octets)


        PAQUET COMPLET — IPv6 + Fragment + TCP

┌─────────────────────────────────────────────────────────┐
│                     ETHERNET (14 o)                     │
├──────────────────────┬──────────────────────┬───────────┤
│ Dst MAC (6)          │ Src MAC (6)          │ 86 DD     │
│ 00 11 22 33 44 55    │ 66 77 88 99 AA BB    │ (IPv6)    │
└──────────────────────┴──────────────────────┴───────────┘
    offsets 0-5           6-11                 12-13
                                                    │
                                                    ▼
┌─────────────────────────────────────────────────────────┐
│                    IPv6 (40 o)                          │
├────┬──────┬──────┬──────┬───────────────────────────────┤
│60  │0014  │2C    │40    │  (version + payload + NH + HL)│
│    │      │(Frag)│      │                               │
├────┴──────┴──────┴──────┴───────────────────────────────┤
│ Src: 20 01 0D B8 ... 00 01  (16 o)                      │
│ Dst: 20 01 0D B8 ... 00 02  (16 o)                      │
└─────────────────────────────────────────────────────────┘
    offsets 14-53 (40 octets)
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│              FRAGMENT HEADER (8 o fixes)                │
├─────────┬─────────┬───────────┬─────────────────────────┤
│06       │00       │0001       │DE AD BE EF              │
│(NH=TCP) │reserved │off+flags  │identification           │
└─────────┴─────────┴───────────┴─────────────────────────┘
    offsets 54-61 (8 octets)
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│                       TCP (20 o)                        │
├─────────┬─────────┬───────────┬───────────┬────┬───────┤
│1F 90    │00 50    │00000001   │00000002   │50  │12     │
└─────────┴─────────┴───────────┴───────────┴────┴───────┘
    offsets 62-81 (20 octets)
*/


// CORRECTION : petite fonction pour lire 2 octets (big endian). Évite de réécrire (a << 8) | b
// partout (et d'oublier une parenthèse).
static inline uint16_t be16(const uint8_t *p){
    return (uint16_t)((p[0] << 8) | p[1]);
}


static PARSER_RETURN_CODE parse_l4(
    ParserResult *r, const uint8_t *pkt, int start, int end,
    uint8_t proto, int is_v6
){
    int avail = end - start;                 // octets disponibles pour la couche 4 (>= 0, garanti par l'appelant)

    if (proto == TCP){
        if (avail < 20) return TOO_LITTLE;
        // CORRECTION : "data offset" = moitié haute de l'octet 12, en mots de 4 octets (comme l'IHL)
        int tcp_len = (pkt[start + 12] >> 4) * 4;
        if (tcp_len < 20) return INCOHERENCE;   // un en-tête TCP fait au moins 20 octets
        if (tcp_len > avail) return TOO_LITTLE; // il annonce plus d'octets qu'il n'y en a
        TCP_DATA tcp_data = {0};
        memcpy(tcp_data.src_port, pkt + start, 2);
        memcpy(tcp_data.dst_port, pkt + start + 2, 2);
        tcp_data.flags = pkt[start + 13];
        r->data.tcp = tcp_data;
        return SUCCES;
    }

    if (proto == UDP){
        if (avail < 8) return TOO_LITTLE;
        UDP_DATA udp_data = {0};
        memcpy(udp_data.src_port, pkt + start, 2);
        memcpy(udp_data.dst_port, pkt + start + 2, 2);
        r->data.udp = udp_data;
        return SUCCES;
    }

    // en IPv4 le ping est le protocole 1 (ICMP), en IPv6 c'est 58 (ICMPv6)
    if (proto == (is_v6 ? ICMPV6 : ICMP)){
        if (avail < 8) return TOO_LITTLE;
        ICMP_DATA icmp_data = {0};
        icmp_data.type = pkt[start];
        icmp_data.code = pkt[start + 1];
        r->data.icmp = icmp_data;
        return SUCCES;
    }

    return NOT_HANDLE;                       // autre protocole (ESP, GRE, SCTP...) : on ne l'analyse pas
}

ParserResult parse(const uint8_t *pkt, const int len){
    // memset plutôt que "= {0}" : il met aussi à zéro les octets de remplissage de la
    // struct, donc deux paquets identiques donnent exactement les mêmes octets (utile pour hacher/comparer).
    ParserResult result;
    memset(&result, 0, sizeof result);
    result.len = len;
    // pkt == NULL plantE dans memcpy ET VEUT DIRE VIDE
    if (pkt == NULL){
        result.code = (uint8_t)ERROR;
        return result;
    }
    if (len < 14){
        result.code = (uint8_t)TOO_LITTLE;
        return result;
    }

    // les MAC sont (dst avant src) inversées. Dans Ethernet la DESTINATION vient en premier.
    memcpy(result.dst_mac, pkt, 6);          // 0 a 5
    memcpy(result.src_mac, pkt + 6, 6);      // 6 a 11
    uint16_t type = be16(pkt + 12);          // 12 a 13
    int start = 14;                          // premier octet après le type
    int n_vlan = 0;

    // CORRECTION : la boucle VLAN lisait sans vérifier len, et pouvait tourner sans fin.
    // on gère aussi 0x88A8 (QinQ).
    /*
        QinQ = "Q-in-Q" = 802.1Q in 802.1Q. C'est un empilement de VLAN.
        2 tags VLAN
    */
    while (type == VLAN || type == QINQ){
        if (n_vlan >= MAX_VLAN){             // trop de tags empilés : paquet piégé
            result.n_vlan = n_vlan;
            result.code = (uint8_t)INCOHERENCE;
            return result;
        }
        if (len < start + 4){                // un tag = 2 octets (TCI) + 2 octets (vrai type)
            result.n_vlan = n_vlan;
            result.code = (uint8_t)TOO_LITTLE;
            return result;
        }
        n_vlan += 1;
        type = be16(pkt + start + 2);        // on saute le TCI (2 octets) et on lit le vrai type
        start += 4;
    }
    result.n_vlan = n_vlan;
    result.ip_start = start;
    result.type = type;

    // ARP, pas de couche IP : un corps de 28 octets suit directement Ethernet (et les tags VLAN).
    // Le bourrage Ethernet vient après : on ne lit donc que 28 octets, quelle que soit len.
    if (type == ARP){
        if (len < start + L_ARP){
            result.code = (uint8_t)TOO_LITTLE;
            return result;
        }
        // octets +0/+1 = type de matériel (1 = Ethernet), +2/+3 = type de protocole (0x0800 = IPv4)
        if (be16(pkt + start) != 1 || be16(pkt + start + 2) != IPV4){
            result.code = (uint8_t)NOT_HANDLE;   // ARP pour autre chose que IPv4 sur Ethernet : rare, non géré
            return result;
        }
        // octets +4/+5 = tailles d'adresses : 6 (MAC) et 4 (IPv4). Sinon le corps n'a pas la forme attendue.
        if (pkt[start + 4] != L_MAC || pkt[start + 5] != L_IPV4){
            result.code = (uint8_t)INCOHERENCE;
            return result;
        }
        ARP_DATA arp_data = {0};
        arp_data.op = be16(pkt + start + 6);                  // +6/+7 : 1 = demande, 2 = réponse
        memcpy(arp_data.sender_mac, pkt + start + 8, 6);      // +8  : MAC de celui qui parle
        memcpy(arp_data.sender_ip, pkt + start + 14, 4);      // +14 : son IP
        memcpy(arp_data.target_mac, pkt + start + 18, 6);     // +18 : MAC cherchée (zéros dans une demande)
        memcpy(arp_data.target_ip, pkt + start + 24, 4);      // +24 : IP cherchée
        result.data.arp = arp_data;
        // 1 et 2 sont les seuls cas courants ; les autres opérations (RARP...) restent non gérées
        result.code = (uint8_t)((arp_data.op == ARP_REQUEST || arp_data.op == ARP_REPLY) ? SUCCES : NOT_HANDLE);
        return result;
    }

    // On teste le TYPE en premier. Avant, un paquet d'un autre type (LLDP...) était
    // lu comme s'il contenait de l'IP : mauvais code de retour.
    if (type != IPV4 && type != IPV6){
        result.code = (uint8_t)NOT_HANDLE;
        return result;
    }

    if (len < start + 1){                    // Il faut au moins 1 octet pour lire la version
        result.code = (uint8_t)TOO_LITTLE;
        return result;
    }
    uint8_t version_ihl = pkt[start];
    result.version = version_ihl >> 4;
    if (result.version != 4 && result.version != 6){  // Ni ipv4 et ipv6
        result.code = (uint8_t)NOT_HANDLE;
        return result;
    }
    if (
        (result.version == 4 && type != IPV4) ||
        (result.version == 6 && type != IPV6)
    ){
        result.code = (uint8_t)INCOHERENCE;
        return result;
    }

    // ───────────────────────────── IPv4 ─────────────────────────────
    if (type == IPV4){
        if (len < start + 20){               // TOO_LITTLE (et non ERROR) quand c'est trop court
            result.code = (uint8_t)TOO_LITTLE;
            return result;
        }
        result.ihl = version_ihl & 0x0F;
        if (result.ihl < 5){                 // IHL MIN 5
            result.code = (uint8_t)INCOHERENCE;
            return result;
        }
        int hdr_len = result.ihl * 4;
        if (len < start + hdr_len){          // l'en-tête annoncé ne tient pas dans le paquet
            result.code = (uint8_t)TOO_LITTLE;
            return result;
        }

        // On lit la longueur totale IP (octets +2 et +3). Elle dit où le paquet IP
        // SE TERMINE vraiment : après, c'est du bourrage Ethernet, qui ne doit jamais être lu comme du TCP.
        int total_len = be16(pkt + start + 2);
        if (total_len < hdr_len){            // il annonce moins que son propre en-tête : il ment (en tete + data < en tete, absurde)
            result.code = (uint8_t)INCOHERENCE;
            return result;
        }
        int end = start + total_len;
        if (end > len) end = len;            // capture coupée (snaplen) : on travaille avec ce qu'on a

        IPV4_DATA ipv4_data = {0};
        ipv4_data.proto = pkt[start + 9];
        memcpy(ipv4_data.src_ip, pkt + start + 12, 4);
        memcpy(ipv4_data.dst_ip, pkt + start + 16, 4);
        result.ip_data.ipv4 = ipv4_data;     // les IP restent lisibles même si on s'arrête plus bas

        // CORRECTION : fragments. Octets +6 et +7 : 3 bits de flags puis 13 bits de décalage.
        // Décalage(fragment offset) != 0 = pas le premier fragment : il n'y a PAS d'en-tête TCP/UDP, lire des ports = inventer.
        // be16(pkt + start + 6) & 0x1FFF == 0 si premier fragment
        if (be16(pkt + start + 6) & 0x1FFF){
            result.code = (uint8_t)FRAGMENT;
            return result;
        }

        result.code = (uint8_t)parse_l4(&result, pkt, start + hdr_len, end, ipv4_data.proto, 0);
        return result;
    }

    // ───────────────────────────── IPv6 ─────────────────────────────
    // (ici type == IPV6 : on a éliminé tous les autres cas plus haut)
    if (len < start + 40){
        result.code = (uint8_t)TOO_LITTLE;
        return result;
    }
    IPV6_DATA ipv6_data = {0};
    memcpy(ipv6_data.src_ip, pkt + start + 8, 16);
    memcpy(ipv6_data.dst_ip, pkt + start + 24, 16);

    // Longueur de la charge utile IPv6 (octets +4 et +5) : même rôle que la longueur IPv4.
    // 0 veut dire "inconnue" (jumbogramme) : dans ce cas on se fie à len.
    int payload_len = be16(pkt + start + 4);
    int end = len;
    if (payload_len != 0 && start + 40 + payload_len < len) end = start + 40 + payload_len;

    int nh = pkt[start + 6];                 // prochain en-tête, annoncé par l'en-tête IPv6
    int pos = start + 40;                    // début de ce qui suit l'en-tête IPv6
    int n_ext = 0;

    // Cette boucle lisait sans vérifier, utilisait le MAUVAIS type pour calculer la taille,
    // et pouvait tourner sans fin. Maintenant : bornée, vérifiée, et la taille dépend de l'en-tête COURANT.
    while (nh == 0 || nh == 43 || nh == 44 || nh == 60){
        if (n_ext >= MAX_EXT_HEADERS){       // chaîne anormalement longue : paquet piégé
            result.ip_data.ipv6 = ipv6_data;
            result.code = (uint8_t)INCOHERENCE;
            return result;
        }
        n_ext += 1;
        if (end - pos < 8){                  // une extension fait au moins 8 octets : sinon on lirait hors paquet
            result.ip_data.ipv6 = ipv6_data;
            result.code = (uint8_t)TOO_LITTLE;
            return result;
        }
        int cur = nh;                        // type de CETTE extension (celle qu'on lit maintenant)
        nh = pkt[pos];                       // son 1er octet = le prochain en-tête
        // fragment (44) : toujours 8 octets. Les autres : (octet +1 + 1) * 8
        int size = (cur == 44) ? 8 : (pkt[pos + 1] + 1) * 8;
        if (size > end - pos){               // elle annonce plus d'octets qu'il n'en reste
            result.ip_data.ipv6 = ipv6_data;
            result.code = (uint8_t)TOO_LITTLE;
            return result;
        }
        // fragment : octets +2 et +3 = 13 bits de décalage, 2 bits réservés, 1 bit "d'autres suivent".
        // Décalage != 0 : pas le premier fragment, donc pas d'en-tête TCP/UDP ici.
        if (cur == 44 && (be16(pkt + pos + 2) & 0xFFF8)){
            ipv6_data.next_header = (uint8_t)nh;
            result.ip_data.ipv6 = ipv6_data;
            result.code = (uint8_t)FRAGMENT;
            return result;
        }
        pos += size;
    }
    ipv6_data.next_header = (uint8_t)nh;     // le vrai protocole, après les extensions
    result.ip_data.ipv6 = ipv6_data;

    // on ne remplit plus result.ihl ici : l'IHL n'existe pas en IPv6 (il restait à 15
    // avec 0x6F, qui est un morceau de la "classe de trafic").
    result.code = (uint8_t)parse_l4(&result, pkt, pos, end, (uint8_t)nh, 1);
    return result;
}