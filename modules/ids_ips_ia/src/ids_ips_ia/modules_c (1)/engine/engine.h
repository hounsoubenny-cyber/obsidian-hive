#ifndef ENGINE_H
#define ENGINE_H
#include <stdint.h>
#include <stddef.h>
#include "../flows/flow.h"          /* FlowRecord : ce que Python lit dans les rings (176 octets) */

/* ─────────────────────────────────────────────────────────────────────────────────────────────
 * Le moteur : c'est CE fichier que Python appelle (via Cython). Il assemble tout le reste.
 *
 *   une interface  =  UNE thread de capture  =  sa capture, sa table de flux, son ring
 *   les listes d'IP à ignorer sont partagées par toutes les threads
 *
 * Conventions (celles du projet) : action 0 = succès / -1 = échec · question 1 = oui / 0 = non
 * Après un -1, engine_last_error() donne une phrase lisible (valable pour la thread qui vient d'échouer).
 * Toutes les fonctions peuvent être appelées depuis plusieurs threads Python : un verrou interne les sérialise.
 * ───────────────────────────────────────────────────────────────────────────────────────────── */

#define ENGINE_MAX_CAPTURES 16      /* interfaces capturées en même temps */
#define ENGINE_IFNAME_MAX   32      /* nom d'interface, \0 compris */
#define ENGINE_RING_NAME_MAX 64     /* nom du segment partagé, \0 compris */

#define IGNORE_SRC  1               /* ignorer les paquets dont la SOURCE est dans la liste */
#define IGNORE_DST  2               /* ignorer les paquets dont la DESTINATION est dans la liste */
#define IGNORE_BOTH 3

enum EngineState{
    ENGINE_SLOT_FREE = 0,
    ENGINE_RUNNING   = 1,           /* la thread capture */
    ENGINE_STOPPED   = 2,           /* arrêtée proprement ; le ring reste lisible jusqu'à engine_release */
    ENGINE_FAILED    = 3,           /* la thread s'est arrêtée toute seule sur une erreur : engine_stop puis engine_release */
};

/* Ce que Python règle. Toujours commencer par engine_config_default() : on ne change que ce qu'on veut. */
struct EngineConfig{
    const char *ifname;             /* "eth0", "lo"... (obligatoire) */
    const char *ring_prefix;        /* le ring s'appelle /<prefix>_<ifname> dans /dev/shm. NULL = "ids" */
    int use_mmsg;                   /* 1 = cap_recv_mmsg (par lots, plus rapide) · 0 = cap_recv (1 trame par appel) */
    int promisc;                    /* 1 = voir aussi les trames qui ne sont pas pour cette machine */
    uint32_t buffer_mb;             /* tampon de réception du noyau, en Mo */
    uint32_t table_size;            /* nombre maximal de flux suivis en même temps */
    uint64_t idle_ms;               /* un flux sans paquet depuis idle_ms est envoyé au ring et retiré (0 = jamais) */
    uint64_t max_ms;                /* un flux qui dure depuis max_ms est envoyé, puis repart de zéro (0 = jamais) */
    int close_on_tcp_end;           /* 1 = un RST ou deux FIN retire le flux tout de suite */
    int scan_rule;                  /* 1 = règle « scan de ports » active (BLOCK + IP en liste noire) */
    uint64_t ring_size;             /* taille du segment du ring, en octets (la place utile = ring_size - 256) */
    uint32_t batch_size;            /* use_mmsg : trames lues par appel système */
    uint32_t max_turns;             /* use_mmsg : lots maximum avant de rendre la main */
    int poll_ms;                    /* délai d'attente d'une trame ; c'est aussi le temps maximum d'un engine_stop */
};

/* Un point de situation (engine_stats, engine_list) */
struct EngineStats{
    char ifname[ENGINE_IFNAME_MAX];
    char ring_name[ENGINE_RING_NAME_MAX];
    int state;                      /* enum EngineState */
    uint64_t frames_in;             /* trames reçues */
    uint64_t frames_ok;             /* acceptées par la table de flux */
    uint64_t frames_failed;         /* refusées (ARP, paquet coupé, fragment...) */
    uint64_t frames_ignored;        /* écartées par les listes d'IP à ignorer */
    uint64_t blocked_pkts;          /* ignorées parce que l'IP est en liste noire (règle de scan) */
    uint64_t flows_exported;        /* flux écrits dans le ring */
    uint64_t flows_lost;            /* flux perdus parce que le ring était plein (Python trop lent) */
    uint64_t flows_evicted;         /* flux chassés parce que la table était pleine */
    uint64_t kernel_recv;           /* trames vues par le noyau sur ce socket */
    uint64_t kernel_drop;           /* trames jetées par le noyau : le programme était trop lent */
    uint64_t active_flows;          /* flux actuellement dans la table */
    uint64_t ring_size;             /* place utile du ring, en octets */
    uint64_t ring_used;             /* octets en attente de lecture */
    uint64_t ring_free;
    uint64_t ring_dropped;          /* écritures refusées par le ring (même chose que flows_lost, vue du ring) */
};

typedef struct Engine Engine;

void engine_config_default(struct EngineConfig *cfg);
uint32_t engine_record_size(void);                              /* sizeof(FlowRecord) : Python vérifie que son dtype a la même taille */
const char *engine_last_error(void);

Engine *engine_create(void);                                    /* NULL si échec */
void engine_destroy(Engine *e);                                 /* arrête tout ce qui tourne, supprime tous les rings */

/* Cycle de vie d'une capture :   engine_start → (engine_read...) → engine_stop → (engine_read jusqu'à vide) → engine_release */
int engine_start(Engine *e, const struct EngineConfig *cfg);    /* 0 = elle tourne. Les erreurs (droits, interface...) sont renvoyées ICI */
int engine_stop(Engine *e, const char *ifname);                 /* arrête la thread, envoie les flux restants au ring. Le ring reste lisible */
int engine_release(Engine *e, const char *ifname);              /* ferme et SUPPRIME le ring. Capture arrêtée seulement */

/* Lire le ring : copie jusqu'à max flux dans out. Retourne le nombre lu (>= 0, 0 = rien de neuf) ou -1.
 * Fonctionne aussi sur une capture arrêtée (pour finir de vider). Un seul lecteur à la fois par ring (garanti par le verrou). */
int engine_read(Engine *e, const char *ifname, FlowRecord *out, int max);

int engine_stats(Engine *e, const char *ifname, struct EngineStats *out);
int engine_list(Engine *e, struct EngineStats *out, int max);   /* nombre de captures présentes (>= 0), au plus max remplies */
int engine_ring_name(Engine *e, const char *ifname, char *out, size_t size);   /* pour qui veut lire /dev/shm lui-même */

/* Listes d'IP à ignorer, partagées par toutes les captures. ip = texte ("10.0.0.1", "2001:db8::1"). which = IGNORE_*. */
int engine_ignore_add(Engine *e, const char *ip, int which);
int engine_ignore_remove(Engine *e, const char *ip, int which);   /* -1 si l'IP n'y était pas */
int engine_ignore_contains(Engine *e, const char *ip, int which); /* question : 1 / 0 (0 aussi si le texte n'est pas une IP) */
uint32_t engine_ignore_count(Engine *e, int which);               /* which = IGNORE_SRC ou IGNORE_DST */
#endif
