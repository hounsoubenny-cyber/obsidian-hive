#include "ipset.h"
#include "../utils/utils.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

// Une fiche : IMMUABLE dès qu'elle est publiée dans une case. Pour une IPv4, ip[4..15] sont à 0.
struct IpEntry{
    uint8_t v4;
    uint8_t ip[16];
};

// Marqueur « case supprimée » : la case n'est plus vide (la chaîne de recherche continue) mais ne contient plus rien.
// Une TOMB n'est gardée que si elle est NÉCESSAIRE : si la case d'après est vide, la chaîne s'arrête là de toute façon,
// et ipset_remove remet la case (et les TOMB qui la précèdent) à vide. Sans ce nettoyage, chaque IP différente retirée
// laisserait une TOMB pour toujours, et la table finirait « pleine » alors qu'elle est presque vide.
static struct IpEntry TOMB;

struct IpSet{
    uint32_t mask;                      // nombre de cases - 1 (le nombre de cases est une puissance de 2)
    uint32_t max_cells_used;            // on ne remplit jamais plus de la moitié des cases : il reste toujours une case vide
    _Atomic(struct IpEntry *) *cells;   // NULL = vide · &TOMB = supprimée · sinon : une fiche
    _Atomic uint32_t n_items;           // IP présentes (lisible sans verrou)
    pthread_mutex_t lock;               // protège ce qui suit : un seul écrivain à la fois
    uint32_t n_used;                    // cases non vides (fiches + supprimées)
    struct IpEntry **retired;           // fiches retirées : on NE les libère PAS tout de suite (un lecteur peut encore les lire)
    size_t n_retired, cap_retired;
};

static uint32_t _hash(const uint8_t *ip, int v4){
    uint32_t h = 2166136261u;
    h = fnv1a_update(h, ip, v4 ? 4 : 16);
    h ^= (uint32_t)v4;
    h *= 16777619u;
    return fmix32(h);
}

static int _same(const struct IpEntry *e, const uint8_t *ip, int v4){
    return e -> v4 == (uint8_t)v4 && memcmp(e -> ip, ip, v4 ? 4 : 16) == 0;
}

IpSet *ipset_create(uint32_t max_items){
    if (max_items == 0 || max_items > (1u << 27)) return NULL;
    uint32_t cells = 16;
    while (cells < max_items * 2) cells <<= 1;                   // au moins 2 fois plus de cases que d'IP
    IpSet *s = calloc(1, sizeof(IpSet));
    if (s == NULL) return NULL;
    s -> cells = calloc(cells, sizeof(_Atomic(struct IpEntry *)));   // calloc : toutes les cases sont NULL (vides)
    if (s -> cells == NULL){ free(s); return NULL; }
    s -> mask = cells - 1;
    s -> max_cells_used = cells / 2;
    pthread_mutex_init(&s -> lock, NULL);
    return s;
}

void ipset_destroy(IpSet *s){
    if (s == NULL) return;
    for (uint32_t i = 0; i <= s -> mask; i++){
        struct IpEntry *e = atomic_load_explicit(&s -> cells[i], memory_order_relaxed);
        if (e != NULL && e != &TOMB) free(e);
    }
    for (size_t i = 0; i < s -> n_retired; i++) free(s -> retired[i]);
    free(s -> retired);
    free((void *)s -> cells);
    pthread_mutex_destroy(&s -> lock);
    free(s);
}

/* ───────────── lecture : sans verrou ───────────── */

int ipset_contains(const IpSet *s, const uint8_t *ip, int v4){
    if (s == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return 0;
    uint32_t i = _hash(ip, v4) & s -> mask;
    for (uint32_t n = 0; n <= s -> mask; n++){
        // acquire : si on voit la fiche, on voit aussi tout ce qui y a été écrit avant sa publication
        struct IpEntry *e = atomic_load_explicit(&s -> cells[i], memory_order_acquire);
        if (e == NULL) return 0;                                 // case vide : l'IP n'est pas plus loin
        if (e != &TOMB && _same(e, ip, v4)) return 1;
        i = (i + 1) & s -> mask;                                 // case occupée par une autre IP : on avance
    }
    return 0;
}

uint32_t ipset_count(const IpSet *s){
    if (s == NULL) return 0;
    return atomic_load_explicit(&s -> n_items, memory_order_relaxed);
}

/* ───────────── écriture : sous verrou ───────────── */

int ipset_add(IpSet *s, const uint8_t *ip, int v4){
    if (s == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return -1;
    pthread_mutex_lock(&s -> lock);

    // 1) on parcourt toute la chaîne : l'IP est-elle déjà là ? Et y a-t-il une case « supprimée » à réutiliser ?
    uint32_t i = _hash(ip, v4) & s -> mask;
    int64_t tomb = -1;
    for (uint32_t n = 0; n <= s -> mask; n++){
        struct IpEntry *e = atomic_load_explicit(&s -> cells[i], memory_order_relaxed);
        if (e == NULL) break;
        if (e == &TOMB){
            if (tomb < 0) tomb = i;
        } else if (_same(e, ip, v4)){
            pthread_mutex_unlock(&s -> lock);
            return 0;                                            // déjà présente : rien à faire
        }
        i = (i + 1) & s -> mask;
    }
    // 2) où la mettre : dans une case supprimée de la chaîne, sinon dans la case vide où la chaîne s'arrête
    uint32_t target = tomb >= 0 ? (uint32_t)tomb : i;
    if (tomb < 0 && s -> n_used >= s -> max_cells_used){
        pthread_mutex_unlock(&s -> lock);
        return -1;                                               // plein
    }
    struct IpEntry *e = calloc(1, sizeof(struct IpEntry));
    if (e == NULL){
        pthread_mutex_unlock(&s -> lock);
        return -1;
    }
    e -> v4 = (uint8_t)v4;
    memcpy(e -> ip, ip, v4 ? 4 : 16);
    // 3) on publie : release = tout ce qu'on vient d'écrire dans la fiche est visible AVANT que le pointeur le soit
    atomic_store_explicit(&s -> cells[target], e, memory_order_release);
    if (tomb < 0) s -> n_used++;
    atomic_fetch_add_explicit(&s -> n_items, 1, memory_order_relaxed);
    pthread_mutex_unlock(&s -> lock);
    return 0;
}

int ipset_remove(IpSet *s, const uint8_t *ip, int v4){
    if (s == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return -1;
    pthread_mutex_lock(&s -> lock);
    uint32_t i = _hash(ip, v4) & s -> mask;
    for (uint32_t n = 0; n <= s -> mask; n++){
        struct IpEntry *e = atomic_load_explicit(&s -> cells[i], memory_order_relaxed);
        if (e == NULL) break;
        if (e != &TOMB && _same(e, ip, v4)){
            // La fiche est mise de côté, PAS libérée : un lecteur qui l'a déjà lue peut encore la consulter.
            // Elle sera libérée à ipset_destroy. (Coût : 17 octets par IP retirée.)
            if (s -> n_retired == s -> cap_retired){
                size_t cap = s -> cap_retired ? s -> cap_retired * 2 : 16;
                struct IpEntry **r = realloc(s -> retired, cap * sizeof(*r));
                if (r == NULL){
                    pthread_mutex_unlock(&s -> lock);
                    return -1;
                }
                s -> retired = r;
                s -> cap_retired = cap;
            }
            s -> retired[s -> n_retired++] = e;
            uint32_t next = (i + 1) & s -> mask;
            if (atomic_load_explicit(&s -> cells[next], memory_order_relaxed) == NULL){
                // La case d'après est vide : aucune chaîne ne passe par i pour aller plus loin (une chaîne n'a jamais de trou).
                // Un lecteur qui arrive en i s'arrêtait déjà sur la case vide d'après : en la vidant, il s'arrête une case plus tôt,
                // sans rien perdre. On vide i, puis on remonte : chaque TOMB juste avant une case vide peut l'être à son tour.
                atomic_store_explicit(&s -> cells[i], NULL, memory_order_release);
                s -> n_used--;
                uint32_t j = (i - 1) & s -> mask;
                for (uint32_t k = 0; k < s -> mask; k++){          // au plus un tour de table
                    if (atomic_load_explicit(&s -> cells[j], memory_order_relaxed) != &TOMB) break;
                    atomic_store_explicit(&s -> cells[j], NULL, memory_order_release);
                    s -> n_used--;
                    j = (j - 1) & s -> mask;
                }
            } else {
                // Une autre IP peut dépendre de cette case pour être retrouvée : elle devient TOMB (la chaîne continue)
                atomic_store_explicit(&s -> cells[i], &TOMB, memory_order_release);
            }
            atomic_fetch_sub_explicit(&s -> n_items, 1, memory_order_relaxed);
            pthread_mutex_unlock(&s -> lock);
            return 0;
        }
        i = (i + 1) & s -> mask;
    }
    pthread_mutex_unlock(&s -> lock);
    return -1;                                                   // n'était pas là
}
