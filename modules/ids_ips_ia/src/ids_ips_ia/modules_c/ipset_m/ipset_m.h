#ifndef IPSET_M_H
#define IPSET_M_H
#include <stdint.h>

/* ─────────────────────────────────────────────────────────────────────────────────────────────
 * IpSetM : la liste noire PARTAGÉE et REDIMENSIONNABLE (la « mère »).
 *
 * Une seule liste pour toutes les threads de capture ET pour Python :
 *   · le MAÎTRE : un Dict (IP → métadonnées), protégé par un mutex. C'est la vérité : il donne la raison, la date,
 *     la liste des IP bloquées, l'expiration, et c'est de lui qu'on reconstruit la table de lecture.
 *   · la TABLE DE LECTURE : un IpSet (ipset.c, inchangé), lu SANS VERROU par les threads de capture à chaque paquet.
 *
 * Quand la table de lecture est pleine (ou pleine de cases supprimées), l'écrivain en construit une neuve depuis le
 * maître, la publie d'UN SEUL store atomique (« la bascule »), et met l'ancienne de côté (« retired »).
 * Chaque table possède ses propres fiches : une table et tout ce qu'elle contient sont libérés ensemble.
 *
 * QUAND LIBÉRER L'ANCIENNE TABLE ? (QSBR : quiescent-state based reclamation)
 *   Un lecteur n'écrit rien sur l'objet qu'il lit. Il dit seulement « je ne tiens aucune table » entre deux paquets
 *   (ipset_m_quiescent). L'écrivain libère une table retirée quand TOUS les lecteurs ont dit « je ne tiens rien »
 *   au moins une fois APRÈS la bascule. Le signe de vie vit donc chez le lecteur (dans son slot), jamais dans
 *   l'objet qu'on veut libérer : c'est ce qui évite la course « le lecteur a chargé le pointeur mais n'a pas encore signé ».
 *   Coût par lecture : un chargement atomique. Coût par paquet : deux chargements, un store seulement quand la table a changé.
 *
 * MODE D'EMPLOI
 *   Thread de capture :  id = ipset_m_register(m)  (une fois, au démarrage)
 *                        à chaque tour de boucle, entre deux paquets : ipset_m_quiescent(m, id)
 *                        avant un appel qui peut dormir longtemps (poll) : ipset_m_offline(m, id) ; après : ipset_m_online(m, id)
 *                        chemin chaud : ipset_m_contains(m, id, ip, v4)
 *                        à la fin : ipset_m_unregister(m, id)
 *   Python / toute autre thread : ipset_m_add / ipset_m_remove / ipset_m_is_blocked / ipset_m_list ... (mutex, jamais sans verrou)
 *   Un lecteur qui oublie ipset_m_quiescent ne casse rien, mais retarde la libération des anciennes tables.
 *   S'il y en a trop en attente (IPSET_M_MAX_RETIRED), une croissance est refusée (ipset_m_add répond -1).
 *
 * Conventions : action 0 = succès / -1 = échec · question 1 = oui / 0 = non
 * ───────────────────────────────────────────────────────────────────────────────────────────── */

#define IPSET_M_MAX_READERS 32          /* threads de capture inscrites en même temps */
#define IPSET_M_MAX_RETIRED 32          /* anciennes tables en attente de libération */
#define IPSET_M_MAX_ITEMS (1u << 22)    /* ~4 millions d'IP au plus (la table de lecture pèse alors ~64 Mo) */

#define IPM_SRC_AUTO 1                  /* bloquée par une règle */
#define IPM_SRC_MANUAL 2                /* bloquée par un admin (Python) */

/* Ce qu'on sait d'une IP bloquée (le maître le garde). Pas d'horloge ici : l'appelant donne les dates, en millisecondes. */
struct IpBlockMeta{
    uint8_t rule;                       /* FlowRuleReason qui a bloqué (0 = aucune / manuel) */
    uint8_t source;                     /* IPM_SRC_AUTO ou IPM_SRC_MANUAL */
    uint64_t blocked_at_ms;
    uint64_t until_ms;                  /* 0 = pour toujours ; sinon débloquée par ipset_m_expire(now >= until_ms) */
};

struct IpBlockInfo{                     /* une ligne de ipset_m_list */
    uint8_t v4;
    uint8_t ip[16];
    struct IpBlockMeta meta;
};

struct IpSetMStats{
    uint32_t count;                     /* IP bloquées */
    uint32_t capacity;                  /* capacité demandée à la table de lecture courante */
    uint32_t readers;                   /* lecteurs inscrits */
    uint32_t retired_pending;           /* anciennes tables pas encore libérées */
    uint64_t swaps;                     /* nombre de bascules (croissances + reconstructions) */
    uint64_t grows;                     /* dont : croissances (capacité doublée) */
    uint64_t freed_tables;              /* anciennes tables libérées */
    uint64_t refused;                   /* ajouts refusés (plus de place possible) */
};

typedef struct IpSetM IpSetM;

IpSetM *ipset_m_create(uint32_t initial_items);     /* NULL si échec · capacité de départ (au moins 64), elle grandit seule */
void ipset_m_destroy(IpSetM *m);                    /* plus aucune thread ne doit l'utiliser */

/* ── lecteurs (threads de capture) ── */
int  ipset_m_register(IpSetM *m);                   /* numéro de lecteur (0 à IPSET_M_MAX_READERS - 1), ou -1 si plein */
void ipset_m_unregister(IpSetM *m, int reader);
void ipset_m_quiescent(IpSetM *m, int reader);      /* « je ne tiens aucune table » : à appeler entre deux paquets */
void ipset_m_offline(IpSetM *m, int reader);        /* « je dors, ne m'attendez pas » */
void ipset_m_online(IpSetM *m, int reader);         /* « je reviens » */
int  ipset_m_contains(IpSetM *m, int reader, const uint8_t *ip, int v4);   /* sans verrou · reader < 0 : voie sûre avec mutex */

/* ── écrivains, et toute thread non inscrite (Python) ── */
int  ipset_m_add(IpSetM *m, const uint8_t *ip, int v4, const struct IpBlockMeta *meta);   /* meta NULL = AUTO, sans date · déjà là : métadonnées remplacées */
int  ipset_m_remove(IpSetM *m, const uint8_t *ip, int v4);                                /* 0 = débloquée, -1 = n'était pas bloquée */
int  ipset_m_is_blocked(IpSetM *m, const uint8_t *ip, int v4);                            /* avec mutex : lit le maître */
int  ipset_m_get(IpSetM *m, const uint8_t *ip, int v4, struct IpBlockMeta *out);          /* 1 = bloquée (out rempli si non NULL), 0 = non */
uint32_t ipset_m_count(const IpSetM *m);
uint32_t ipset_m_list(IpSetM *m, struct IpBlockInfo *out, uint32_t max);                  /* copie au plus max lignes dans TON buffer, rend le nombre copié */
/* Copie TOUTES les IP bloquées avec leurs métadonnées, d'un seul coup et de façon cohérente (une photo prise sous le lock),
 * triées : les plus récemment bloquées d'abord (puis par IP, pour un ordre toujours le même). La liste est allouée pour toi :
 * libère-la avec ipset_m_snapshot_free. 0 = ok (aucune IP : *out = NULL et *n = 0) · -1 = échec (mémoire, arguments). */
int  ipset_m_snapshot(IpSetM *m, struct IpBlockInfo **out, uint32_t *n);
void ipset_m_snapshot_free(struct IpBlockInfo *list);   /* ipset_m_snapshot_free(NULL) ne fait rien */
uint32_t ipset_m_expire(IpSetM *m, uint64_t now_ms);                                      /* débloque celles dont until_ms est passé ; rend leur nombre */
uint32_t ipset_m_reclaim(IpSetM *m);                                                      /* libère les anciennes tables devenues inutiles ; rend leur nombre */
void ipset_m_stats(IpSetM *m, struct IpSetMStats *out);
#endif
