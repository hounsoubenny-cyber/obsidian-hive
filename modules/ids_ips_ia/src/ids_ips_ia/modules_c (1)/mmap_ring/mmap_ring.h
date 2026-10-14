#ifndef MMAP_RING_H
#define MMAP_RING_H
#include <stdint.h>

/* Ring d'OCTETS en mémoire partagée : UN écrivain (le C) et UN lecteur (Python), sans verrou.
 *
 * Disposition du segment, la même côté Python :
 *   octet 0   n_write    nombre d'octets écrits depuis le début (ne revient jamais à 0)
 *   octet 64  n_read     nombre d'octets lus
 *   octet 128 r_size     capacité de la zone de données (= taille du segment - 256) ; écrit EN DERNIER à la création
 *   octet 192 n_dropped  écritures refusées parce que le ring était plein
 *   octet 256 data       la zone de données
 *
 * Conventions : action 0 = succès / -1 = échec · question 1 = oui / 0 = non
 * ring_write et ring_read : -1 veut dire « erreur » OU « plein / pas assez d'octets » (on ne bloque jamais). */

#define RING_MAX_SIZE (1ULL << 32)   /* taille maximale d'un segment : 4 Gio */

struct Ring{
    _Alignas(64) _Atomic uint64_t n_write;    /* 0   → 8   */
    _Alignas(64) _Atomic uint64_t n_read;     /* 64  → 72  */
    _Alignas(64) _Atomic uint64_t r_size;     /* 128 → 136 */
    _Alignas(64) _Atomic uint64_t n_dropped;  /* 192 → 200 */
    uint8_t _pad[56];                          /* 200 → 256 */
    uint8_t data[];                            /* 256 → ... */
};
typedef struct Ring Ring;

struct RingStats{
    uint64_t n_write, n_read;
    uint64_t writer_pos, reader_pos;
    uint64_t free, used;
    uint64_t size, n_dropped;
    uint64_t total_size;
    uint8_t is_error;
};
typedef struct RingStats RingStats;

/* write_header = 1 : ÉCRIVAIN. Crée le segment (droits 0600), réserve sa mémoire (posix_fallocate) et remet le header à zéro.
 *                    Si le segment existe déjà, il doit avoir exactement la taille `size`, sinon NULL.
 * write_header = 0 : LECTEUR. Le segment doit exister (jamais créé ici). size = 0 : « prends sa taille » ; sinon il doit
 *                    avoir exactement cette taille. NULL aussi si le header n'est pas encore initialisé : réessaie un peu
 *                    plus tard si l'écrivain démarre en même temps.
 * Un échec ne supprime jamais un segment qui existait déjà. */
Ring *rgm_open(const char *name, uint64_t size, int write_header);

int rgm_write_atomic_n_write(Ring *ring, uint64_t value);
int rgm_write_atomic_n_read(Ring *ring, uint64_t value);
int rgm_write_atomic_n_dropped(Ring *ring, uint64_t value);
int rgm_load_atomic_n_read(Ring *ring, uint64_t *out);
int rgm_load_atomic_n_write(Ring *ring, uint64_t *out);
int rgm_load_atomic_size(Ring *ring, uint64_t *out);
int rgm_load_atomic_n_dropped(Ring *ring, uint64_t *out);

int ring_write(struct Ring *ring, const void *value, uint64_t size);
int ring_read(struct Ring *ring, void *out, uint64_t size);
void ring_close(struct Ring *r);          /* démappe ; ne supprime PAS le segment */
void ring_destroy(const char *name);      /* shm_unlink : supprime le segment */
RingStats ring_stats(Ring *ring);
int stats_is_error(RingStats *stats);     /* question : 1 = stats en erreur, 0 = stats valides */
#endif
