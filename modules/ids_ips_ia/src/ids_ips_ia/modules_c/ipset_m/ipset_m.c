#include "ipset_m.h"
#include "../ipset/ipset.h"
#include "../dict/dict.h"
#include "../utils/utils.h"
#include <pthread.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Les opérations atomiques ci-dessous sont VOLONTAIREMENT « seq_cst » (l'ordre par défaut) : le schéma
 * « l'écrivain publie puis regarde les lecteurs / le lecteur se signale puis regarde la table » demande
 * que ces deux paires soient ordonnées entre elles. Sur x86 un chargement seq_cst coûte un simple mov. */

#define IP4_LEN 4
#define IP6_LEN 16
#define MIN_ITEMS 64
#define MIN_REMOVALS_BEFORE_REBUILD 256

/* ───────────── le maître : clé = IP, valeur = IpBlockMeta (le dict la libère) ───────────── */

struct MKey{
    uint8_t v4;
    uint8_t ip[IP6_LEN];
};

static void *_key_dup(const void *key){
    struct MKey *copy = malloc(sizeof(struct MKey));
    if (copy) *copy = *(const struct MKey *)key;
    return copy;
}

static void _key_free(void *key){
    free(key);
}

static int _key_compare(const void *a, const void *b){
    return memcmp(a, b, sizeof(struct MKey));        // 0 = égales
}

static int _key_hash(const void *key){
    const struct MKey *k = (const struct MKey *)key;
    uint32_t h = 2166136261u;
    h = fnv1a_update(h, k -> ip, k -> v4 ? IP4_LEN : IP6_LEN);
    h ^= k -> v4; h *= 16777619u;
    h = fmix32(h);
    return (int)(h & 0x7FFFFFFF);
}

// Remplit key à partir d'une IP de 4 octets (v4 = 1) ou de 16 octets (v4 = 0) ; le reste à zéro (memcmp reste juste)
static void _make_key(struct MKey *key, const uint8_t *ip, int v4){
    memset(key, 0, sizeof(*key));
    key -> v4 = (uint8_t)v4;
    memcpy(key -> ip, ip, v4 ? IP4_LEN : IP6_LEN);
}

/* ───────────── la mère ───────────── */

struct Reader{
    alignas(64) _Atomic uint64_t seen;      // 0 = hors jeu (libre ou « offline ») · sinon : dernière époque annoncée. Sa propre ligne de cache.
    uint8_t used;                           // slot pris ? (sous lock)
};

struct Retired{
    IpSet *table;
    uint64_t epoch;                         // libérable quand chaque lecteur actif a annoncé une époque >= celle-ci
};

struct IpSetM{
    pthread_mutex_t lock;                   // écrivains, inscriptions, maître
    Dict *master;                           // IP → IpBlockMeta (sous lock)
    _Atomic(IpSet *) current;               // la table de lecture : LA bascule
    _Atomic uint64_t epoch;                 // +1 à chaque bascule ; démarre à 1 (0 est réservé à « hors jeu »)
    _Atomic uint32_t n_items;
    uint32_t capacity;                      // ce qu'on a demandé à ipset_create pour la table courante
    uint32_t removed_since_build;           // retraits depuis la dernière reconstruction (les fiches retirées de l'IpSet ne sont libérées qu'avec lui)
    uint32_t n_retired;
    struct Retired retired[IPSET_M_MAX_RETIRED];
    uint64_t swaps, grows, freed, refused;
    struct Reader readers[IPSET_M_MAX_READERS];
};

/* ───────────── libération des anciennes tables ───────────── */

// demande aux lecteurs si on peut free cet epoch
// Une table retirée à l'époque `epoch` est libérable si chaque lecteur actif a annoncé au moins cette époque
static int _safe_to_free(IpSetM *m, uint64_t epoch){
    for (int i = 0; i < IPSET_M_MAX_READERS; i++){
        if (!m -> readers[i].used) continue;         // pas utilisé, on passe
        uint64_t seen = atomic_load(&m -> readers[i].seen);  // son deernier epoch annoncé
        if (seen != 0 && seen < epoch) return 0;     // ce lecteur peut encore tenir cette table, ex: je suis a 1(seen), on peut spprimer (2)?
    }
    return 1;
}

static uint32_t _reclaim(IpSetM *m){
    uint32_t freed = 0;
    for (uint32_t i = 0; i < m -> n_retired;){
        if (_safe_to_free(m, m -> retired[i].epoch)){
            ipset_destroy(m -> retired[i].table);     // détruit aussi ses fiches : elle ne les partage avec aucune autre table
            m -> retired[i] = m -> retired[--m -> n_retired];
            m -> freed += 1;
            freed += 1;
        } else {
            i++;
        }
    }
    return freed;
}

/* ───────────── la bascule ───────────── */

// Construit une table neuve depuis le maître, la publie, met l'ancienne de côté. 0 = ok, -1 = impossible (rien n'a changé).
// À appeler avec le lock.
static int _rebuild(IpSetM *m, uint32_t new_cap){
    if (m -> n_retired >= IPSET_M_MAX_RETIRED){
        _reclaim(m);
        if (m -> n_retired >= IPSET_M_MAX_RETIRED) return -1;      // des lecteurs retardent trop : on ne bascule pas
    }
    uint32_t count = atomic_load(&m -> n_items);
    if (new_cap < count) new_cap = count * 2;
    if (new_cap < MIN_ITEMS) new_cap = MIN_ITEMS;
    if (new_cap > IPSET_M_MAX_ITEMS) return -1;
    IpSet *fresh = ipset_create(new_cap);
    if (fresh == NULL) return -1;
    for (uint32_t i = 0; i < m -> master -> size; i++){
        for (Entry *e = m -> master -> ptr[i]; e != NULL; e = e -> next){
            const struct MKey *k = (const struct MKey *)e -> key;
            if (ipset_add(fresh, k -> ip, k -> v4) != 0){
                ipset_destroy(fresh);                              // personne ne l'a vue : on peut la détruire tout de suite
                return -1;
            }
        }
    }
    IpSet *old = atomic_load(&m -> current);
    atomic_store(&m -> current, fresh);                            // LA bascule : un lecteur voit l'ancienne OU la neuve, jamais un mélange
    uint64_t epoch = atomic_fetch_add(&m -> epoch, 1) + 1;         // après la bascule : un lecteur qui annonce cette époque verra la neuve
    m -> retired[m -> n_retired].table = old;
    m -> retired[m -> n_retired].epoch = epoch;
    m -> n_retired += 1;
    if (new_cap > m -> capacity) m -> grows += 1;
    m -> capacity = new_cap;
    m -> removed_since_build = 0;
    m -> swaps += 1;
    return 0;
}

/* ───────────── création / destruction ───────────── */

IpSetM *ipset_m_create(uint32_t initial_items){
    if (initial_items < MIN_ITEMS) initial_items = MIN_ITEMS;
    if (initial_items > IPSET_M_MAX_ITEMS) return NULL;
    IpSetM *m = aligned_alloc(64, sizeof(struct IpSetM));          // 64 : chaque slot de lecteur reste sur sa propre ligne de cache
    if (m == NULL) return NULL;
    memset(m, 0, sizeof(*m));
    m -> master = create_dict(64, _key_hash, _key_compare, _key_dup, _key_free, NULL, free);
    IpSet *table = ipset_create(initial_items);
    if (m -> master == NULL || table == NULL || pthread_mutex_init(&m -> lock, NULL) != 0){
        dict_clear(m -> master);                                   // dict_clear(NULL) ne fait rien
        ipset_destroy(table);
        free(m);
        return NULL;
    }
    atomic_init(&m -> current, table);
    atomic_init(&m -> epoch, 1);
    atomic_init(&m -> n_items, 0);
    for (int i = 0; i < IPSET_M_MAX_READERS; i++) atomic_init(&m -> readers[i].seen, 0);
    m -> capacity = initial_items;
    return m;
}

void ipset_m_destroy(IpSetM *m){
    if (m == NULL) return;
    for (uint32_t i = 0; i < m -> n_retired; i++) ipset_destroy(m -> retired[i].table);
    ipset_destroy(atomic_load(&m -> current));
    dict_clear(m -> master);
    pthread_mutex_destroy(&m -> lock);
    free(m);
}

/* ───────────── lecteurs ───────────── */

int ipset_m_register(IpSetM *m){
    if (m == NULL) return -1;
    int id = -1;
    pthread_mutex_lock(&m -> lock);
    for (int i = 0; i < IPSET_M_MAX_READERS; i++){
        if (!m -> readers[i].used){
            m -> readers[i].used = 1;
            atomic_store(&m -> readers[i].seen, atomic_load(&m -> epoch));
            id = i;
            break;
        }
    }
    pthread_mutex_unlock(&m -> lock);
    return id;
}

void ipset_m_unregister(IpSetM *m, int reader){
    if (m == NULL || reader < 0 || reader >= IPSET_M_MAX_READERS) return;
    pthread_mutex_lock(&m -> lock);
    atomic_store(&m -> readers[reader].seen, 0);
    m -> readers[reader].used = 0;
    pthread_mutex_unlock(&m -> lock);
}

void ipset_m_quiescent(IpSetM *m, int reader){
    if (m == NULL || reader < 0 || reader >= IPSET_M_MAX_READERS) return;
    struct Reader *r = &m -> readers[reader];
    uint64_t seen = atomic_load_explicit(&r -> seen, memory_order_relaxed);   // seule cette thread l'écrit
    if (seen == 0) return;                                                    // « offline » le reste jusqu'à ipset_m_online
    uint64_t epoch = atomic_load(&m -> epoch);
    if (seen != epoch) atomic_store(&r -> seen, epoch);                       // un store seulement quand une bascule a eu lieu
}

void ipset_m_offline(IpSetM *m, int reader){
    if (m == NULL || reader < 0 || reader >= IPSET_M_MAX_READERS) return;
    atomic_store(&m -> readers[reader].seen, 0);
}

void ipset_m_online(IpSetM *m, int reader){
    if (m == NULL || reader < 0 || reader >= IPSET_M_MAX_READERS) return;
    atomic_store(&m -> readers[reader].seen, atomic_load(&m -> epoch));
}

int ipset_m_contains(IpSetM *m, int reader, const uint8_t *ip, int v4){
    if (m == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return 0;
    if (reader < 0 || reader >= IPSET_M_MAX_READERS) return ipset_m_is_blocked(m, ip, v4);   // thread non inscrite : voie sûre
    const IpSet *table = atomic_load(&m -> current);       // un SEUL chargement : mask et cases voyagent ensemble dans la table
    return ipset_contains(table, ip, v4);
}

/* ───────────── écrivains ───────────── */

// Retire une IP du maître et de la table de lecture. Avec le lock. 0 = retirée, -1 = n'y était pas.
static int _delete_locked(IpSetM *m, const struct MKey *key){
    if (dict_delitem(m -> master, key) != 0) return -1;
    atomic_store(&m -> n_items, atomic_load(&m -> n_items) - 1);
    ipset_remove(atomic_load(&m -> current), key -> ip, key -> v4);
    m -> removed_since_build += 1;
    return 0;
}

// Les fiches retirées de l'IpSet ne sont libérées qu'avec lui : on reconstruit de temps en temps pour qu'elles ne s'accumulent pas
static void _maybe_rebuild_after_removals(IpSetM *m){
    uint32_t limit = m -> capacity / 2;
    if (limit < MIN_REMOVALS_BEFORE_REBUILD) limit = MIN_REMOVALS_BEFORE_REBUILD;
    if (m -> removed_since_build >= limit) _rebuild(m, m -> capacity);   // si ça échoue, on réessaiera au prochain retrait
}

int ipset_m_add(IpSetM *m, const uint8_t *ip, int v4, const struct IpBlockMeta *meta){
    if (m == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return -1;
    struct IpBlockMeta none = { 0, IPM_SRC_AUTO, 0, 0 };
    struct IpBlockMeta *rec = malloc(sizeof(*rec));
    if (rec == NULL) return -1;
    *rec = meta != NULL ? *meta : none;
    struct MKey key;
    _make_key(&key, ip, v4);

    pthread_mutex_lock(&m -> lock);
    _reclaim(m);                                                   // le balayage paresseux : on nettoie au coup d'écriture
    int existed = dict_getitem(m -> master, &key) != NULL;
    if (dict_setitem(m -> master, &key, rec) != 0){                // le dict libère l'ancienne valeur si la clé existait
        pthread_mutex_unlock(&m -> lock);
        free(rec);
        return -1;
    }
    if (!existed) atomic_store(&m -> n_items, atomic_load(&m -> n_items) + 1);
    if (ipset_add(atomic_load(&m -> current), ip, v4) != 0){       // table de lecture pleine : on en construit une neuve depuis le maître
        uint32_t count = atomic_load(&m -> n_items);
        uint32_t new_cap = (uint64_t)count * 4 >= (uint64_t)m -> capacity * 3 ? m -> capacity * 2 : m -> capacity;   // proche du plein : on double ; sinon on nettoie les cases supprimées
        if (_rebuild(m, new_cap) != 0){
            if (!existed){                                         // on annule : le maître et la table de lecture doivent rester d'accord, c'est nous qui avons add, on retire
                dict_delitem(m -> master, &key);
                atomic_store(&m -> n_items, atomic_load(&m -> n_items) - 1);
            }
            m -> refused += 1;
            pthread_mutex_unlock(&m -> lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m -> lock);
    return 0;
}

int ipset_m_remove(IpSetM *m, const uint8_t *ip, int v4){
    if (m == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return -1;
    struct MKey key;
    _make_key(&key, ip, v4);
    pthread_mutex_lock(&m -> lock);
    _reclaim(m);
    int r = _delete_locked(m, &key);
    if (r == 0) _maybe_rebuild_after_removals(m);
    pthread_mutex_unlock(&m -> lock);
    return r;
}

uint32_t ipset_m_expire(IpSetM *m, uint64_t now_ms){
    if (m == NULL) return 0;
    uint32_t removed = 0;
    pthread_mutex_lock(&m -> lock);
    _reclaim(m);
    uint32_t n = 0;                                                // passe 1 : combien ? (on ne supprime pas pendant qu'on parcourt)
    for (uint32_t i = 0; i < m -> master -> size; i++)
        for (Entry *e = m -> master -> ptr[i]; e != NULL; e = e -> next){
            const struct IpBlockMeta *meta = (const struct IpBlockMeta *)e -> value;
            if (meta -> until_ms != 0 && meta -> until_ms <= now_ms) n++;
        }
    if (n > 0){
        struct MKey *keys = malloc(sizeof(struct MKey) * n);
        if (keys != NULL){
            uint32_t j = 0;                                        // passe 2 : on note les clés
            for (uint32_t i = 0; i < m -> master -> size && j < n; i++)
                for (Entry *e = m -> master -> ptr[i]; e != NULL && j < n; e = e -> next){
                    const struct IpBlockMeta *meta = (const struct IpBlockMeta *)e -> value;
                    if (meta -> until_ms != 0 && meta -> until_ms <= now_ms) keys[j++] = *(const struct MKey *)e -> key;
                }
            for (uint32_t i = 0; i < j; i++)
                if (_delete_locked(m, &keys[i]) == 0) removed++;
            free(keys);
            if (removed > 0) _maybe_rebuild_after_removals(m);
        }
    }
    pthread_mutex_unlock(&m -> lock);
    return removed;
}

/* ───────────── questions (avec mutex : n'importe quelle thread) ───────────── */

int ipset_m_get(IpSetM *m, const uint8_t *ip, int v4, struct IpBlockMeta *out){
    if (m == NULL || ip == NULL || (v4 != 0 && v4 != 1)) return 0;
    struct MKey key;
    _make_key(&key, ip, v4);
    pthread_mutex_lock(&m -> lock);
    const struct IpBlockMeta *meta = (const struct IpBlockMeta *)dict_getitem(m -> master, &key);
    int found = meta != NULL;
    if (found && out != NULL) *out = *meta;
    pthread_mutex_unlock(&m -> lock);
    return found;
}

int ipset_m_is_blocked(IpSetM *m, const uint8_t *ip, int v4){
    return ipset_m_get(m, ip, v4, NULL);
}

uint32_t ipset_m_count(const IpSetM *m){
    return m == NULL ? 0 : atomic_load(&((IpSetM *)m) -> n_items);
}

uint32_t ipset_m_list(IpSetM *m, struct IpBlockInfo *out, uint32_t max){
    if (m == NULL || out == NULL || max == 0) return 0;
    uint32_t n = 0;
    pthread_mutex_lock(&m -> lock);
    for (uint32_t i = 0; i < m -> master -> size && n < max; i++){
        for (Entry *e = m -> master -> ptr[i]; e != NULL && n < max; e = e -> next){
            const struct MKey *k = (const struct MKey *)e -> key;
            memset(&out[n], 0, sizeof(out[n]));
            out[n].v4 = k -> v4;
            memcpy(out[n].ip, k -> ip, sizeof(out[n].ip));
            out[n].meta = *(const struct IpBlockMeta *)e -> value;
            n++;
        }
    }
    pthread_mutex_unlock(&m -> lock);
    return n;
}

// Ordre de la photo : plus récente d'abord ; à date égale, par type puis par octets de l'IP (toujours le même ordre)
static int _info_compare(const void *a, const void *b){
    const struct IpBlockInfo *x = (const struct IpBlockInfo *)a;
    const struct IpBlockInfo *y = (const struct IpBlockInfo *)b;
    if (x -> meta.blocked_at_ms != y -> meta.blocked_at_ms) return x -> meta.blocked_at_ms < y -> meta.blocked_at_ms ? 1 : -1;
    if (x -> v4 != y -> v4) return x -> v4 < y -> v4 ? 1 : -1;
    return memcmp(x -> ip, y -> ip, sizeof(x -> ip));
}

int ipset_m_snapshot(IpSetM *m, struct IpBlockInfo **out, uint32_t *n){
    if (m == NULL || out == NULL || n == NULL) return -1;
    *out = NULL;
    *n = 0;
    pthread_mutex_lock(&m -> lock);
    uint32_t count = atomic_load(&m -> n_items);                  // sous le lock : c'est exactement le nombre d'entrées du maître
    if (count == 0){
        pthread_mutex_unlock(&m -> lock);
        return 0;
    }
    struct IpBlockInfo *list = malloc(sizeof(struct IpBlockInfo) * count);
    if (list == NULL){
        pthread_mutex_unlock(&m -> lock);
        return -1;
    }
    uint32_t k = 0;
    for (uint32_t i = 0; i < m -> master -> size && k < count; i++){
        for (Entry *e = m -> master -> ptr[i]; e != NULL && k < count; e = e -> next){
            const struct MKey *key = (const struct MKey *)e -> key;
            memset(&list[k], 0, sizeof(list[k]));
            list[k].v4 = key -> v4;
            memcpy(list[k].ip, key -> ip, sizeof(list[k].ip));
            list[k].meta = *(const struct IpBlockMeta *)e -> value;
            k++;
        }
    }
    pthread_mutex_unlock(&m -> lock);
    qsort(list, k, sizeof(list[0]), _info_compare);               // le tri se fait HORS du lock : les écrivains n'attendent pas
    *out = list;
    *n = k;
    return 0;
}

void ipset_m_snapshot_free(struct IpBlockInfo *list){
    free(list);
}

uint32_t ipset_m_reclaim(IpSetM *m){
    if (m == NULL) return 0;
    pthread_mutex_lock(&m -> lock);
    uint32_t freed = _reclaim(m);
    pthread_mutex_unlock(&m -> lock);
    return freed;
}

void ipset_m_stats(IpSetM *m, struct IpSetMStats *out){
    if (m == NULL || out == NULL) return;
    pthread_mutex_lock(&m -> lock);
    memset(out, 0, sizeof(*out));
    out -> count = atomic_load(&m -> n_items);
    out -> capacity = m -> capacity;
    for (int i = 0; i < IPSET_M_MAX_READERS; i++) out -> readers += m -> readers[i].used ? 1 : 0;
    out -> retired_pending = m -> n_retired;
    out -> swaps = m -> swaps;
    out -> grows = m -> grows;
    out -> freed_tables = m -> freed;
    out -> refused = m -> refused;
    pthread_mutex_unlock(&m -> lock);
}
