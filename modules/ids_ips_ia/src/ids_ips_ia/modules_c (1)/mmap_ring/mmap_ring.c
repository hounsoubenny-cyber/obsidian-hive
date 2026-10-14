#define _GNU_SOURCE
#include "mmap_ring.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static inline uint64_t _min_u64(uint64_t a, uint64_t b){
    return a < b ? a : b;
}

static void _write_atomic(_Atomic uint64_t *field, uint64_t value){
    atomic_store_explicit(field, value, memory_order_release);
}

static uint64_t _read_atomic(_Atomic uint64_t *field){
    return atomic_load_explicit(field, memory_order_acquire);
}

/* Copie len octets dans la zone circulaire à partir de pos ; si ça dépasse la fin, la suite revient au début.
 * 0 = fait, -1 = arguments impossibles (on n'avance alors AUCUN compteur : ring_write ne l'ignore plus). */
static int _write_at(uint64_t pos, uint64_t len, const void *data, uint8_t *buffer, uint64_t size){
    if (buffer == NULL || data == NULL || pos >= size || len > size) return -1;
    uint64_t first = _min_u64(len, size - pos);                  /* ce qui tient avant la fin de la zone */
    memcpy(buffer + pos, data, first);
    memcpy(buffer, (const uint8_t *)data + first, len - first);  /* le reste, au début */
    return 0;
}

static int _read_at(uint64_t pos, uint64_t len, void *out, const uint8_t *buffer, uint64_t size){
    if (buffer == NULL || out == NULL || pos >= size || len > size) return -1;
    uint64_t first = _min_u64(len, size - pos);
    memcpy(out, buffer + pos, first);
    memcpy((uint8_t *)out + first, buffer, len - first);
    return 0;
}

/* ───────────── accès atomiques : 0 = ok, -1 = erreur ; la valeur lue est rendue dans *out ───────────── */

int rgm_write_atomic_n_write(Ring *ring, uint64_t value){
    if (ring == NULL) return -1;
    _write_atomic(&ring -> n_write, value);
    return 0;
}

int rgm_write_atomic_n_read(Ring *ring, uint64_t value){
    if (ring == NULL) return -1;
    _write_atomic(&ring -> n_read, value);
    return 0;
}

int rgm_write_atomic_n_dropped(Ring *ring, uint64_t value){
    if (ring == NULL) return -1;
    _write_atomic(&ring -> n_dropped, value);
    return 0;
}

int rgm_load_atomic_n_read(Ring *ring, uint64_t *out){
    if (ring == NULL || out == NULL) return -1;
    *out = _read_atomic(&ring -> n_read);
    return 0;
}

int rgm_load_atomic_n_write(Ring *ring, uint64_t *out){
    if (ring == NULL || out == NULL) return -1;
    *out = _read_atomic(&ring -> n_write);
    return 0;
}

int rgm_load_atomic_size(Ring *ring, uint64_t *out){
    if (ring == NULL || out == NULL) return -1;
    *out = _read_atomic(&ring -> r_size);
    return 0;
}

int rgm_load_atomic_n_dropped(Ring *ring, uint64_t *out){
    if (ring == NULL || out == NULL) return -1;
    *out = _read_atomic(&ring -> n_dropped);
    return 0;
}

/* ───────────── ouverture ───────────── */

static int _valid_name(const char *name){
    return name != NULL && name[0] == '/' && name[1] != '\0' && strchr(name + 1, '/') == NULL;
}

static int _size_too_big(uint64_t size){
    if (size > RING_MAX_SIZE) return 1;                          /* plafond absolu */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0){
        uint64_t ram = (uint64_t)pages * (uint64_t)page_size;
        if (size > ram / 2) return 1;                            /* plus de la moitié de la RAM : refusé */
    }
    return 0;
}

Ring *rgm_open(const char *name, uint64_t size, int write_header){
    if (!_valid_name(name)) return NULL;

    int fd = -1;
    int created = 0;                                             /* 1 = ce segment, c'est NOUS qui l'avons créé */

    if (write_header == 1){
        if (size <= sizeof(Ring) || _size_too_big(size)) return NULL;

        /* O_EXCL : « crée-le, mais SEULEMENT s'il n'existe pas ». L'existence est testée et la création faite
         * en une seule opération du noyau : personne ne peut s'intercaler entre les deux. */
        fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd >= 0){
            created = 1;
        } else if (errno == EEXIST){                             /* il existe déjà : on le réutilise, s'il a la bonne taille */
            fd = shm_open(name, O_RDWR, 0);
            if (fd < 0) return NULL;
            struct stat st;
            if (fstat(fd, &st) < 0 || (uint64_t)st.st_size != size){
                close(fd);
                return NULL;
            }
        } else {
            return NULL;
        }
        if (created && ftruncate(fd, (off_t)size) < 0){          /* on ne supprime que ce que NOUS avons créé */
            close(fd);
            shm_unlink(name);
            return NULL;
        }
        /* posix_fallocate : RÉSERVE vraiment la mémoire. Sans lui, ftruncate donne un fichier « troué » et un
         * /dev/shm trop petit (Docker : 64 Mo) ferait planter (SIGBUS) bien plus tard. Ici : erreur immédiate (ENOSPC). */
        if (posix_fallocate(fd, 0, (off_t)size) != 0){
            close(fd);
            if (created) shm_unlink(name);
            return NULL;
        }
    } else {
        fd = shm_open(name, O_RDWR, 0);                          /* pas de O_CREAT : un lecteur ne crée jamais rien */
        if (fd < 0) return NULL;
        struct stat st;
        if (fstat(fd, &st) < 0){
            close(fd);
            return NULL;
        }
        uint64_t real = (uint64_t)st.st_size;
        /* trop petit pour contenir le header : r_size serait lu au-delà de la fin du fichier, et size - sizeof(Ring) serait négatif */
        if (real <= sizeof(Ring) || real > RING_MAX_SIZE || (size != 0 && size != real)){
            close(fd);
            return NULL;
        }
        size = real;
    }

    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);                                                   /* le mapping reste valable sans le fd */
    if (p == MAP_FAILED){
        if (created) shm_unlink(name);
        return NULL;
    }

    Ring *ring = (Ring *)p;
    if (write_header == 1){
        _write_atomic(&ring -> n_write, 0);
        _write_atomic(&ring -> n_dropped, 0);
        _write_atomic(&ring -> n_read, 0);
        _write_atomic(&ring -> r_size, size - sizeof(Ring));     /* EN DERNIER : r_size != 0 veut dire « header prêt » */
    } else {
        uint64_t rsize = _read_atomic(&ring -> r_size);
        if (rsize == 0 || rsize != size - sizeof(Ring)){
            munmap(p, size);
            return NULL;
        }
    }
    return ring;
}

void ring_close(struct Ring *r){
    if (r == NULL) return;
    uint64_t rsize = 0;
    if (rgm_load_atomic_size(r, &rsize) != 0) return;
    /* r_size vient de la mémoire PARTAGÉE : un autre processus peut y avoir écrit n'importe quoi. Démapper une mauvaise
     * longueur détruirait la mémoire d'un voisin ; on préfère laisser fuir ce mapping. */
    if (rsize == 0 || rsize > RING_MAX_SIZE) return;
    munmap(r, sizeof(Ring) + rsize);
}

void ring_destroy(const char *name){
    if (!_valid_name(name)) return;
    shm_unlink(name);
}

/* ───────────── stats ───────────── */

int stats_is_error(RingStats *stats){
    if (stats == NULL) return 1;
    return stats -> is_error == 1 ? 1 : 0;
}

RingStats ring_stats(Ring *ring){
    RingStats stats;
    memset(&stats, 0, sizeof stats);
    stats.is_error = 1;
    if (ring == NULL) return stats;

    uint64_t n_read = 0, n_write = 0, size = 0, n_dropped = 0;
    if (rgm_load_atomic_n_read(ring, &n_read) != 0) return stats;
    if (rgm_load_atomic_n_write(ring, &n_write) != 0) return stats;
    if (rgm_load_atomic_size(ring, &size) != 0) return stats;
    if (rgm_load_atomic_n_dropped(ring, &n_dropped) != 0) return stats;

    /* header incohérent : on le dit au lieu de planter (division par zéro, free négatif, écriture hors du segment) */
    if (size == 0 || size > RING_MAX_SIZE) return stats;
    if (n_read > n_write) return stats;
    if (n_write - n_read > size) return stats;

    stats.is_error = 0;
    stats.n_read = n_read;
    stats.n_write = n_write;
    stats.size = size;
    stats.used = n_write - n_read;
    stats.free = size - stats.used;
    stats.reader_pos = n_read % size;
    stats.writer_pos = n_write % size;
    stats.n_dropped = n_dropped;
    stats.total_size = sizeof(Ring) + size;
    return stats;
}

/* ───────────── écriture / lecture ───────────── */

int ring_write(struct Ring *ring, const void *value, uint64_t size){
    if (ring == NULL || value == NULL) return -1;
    RingStats stats = ring_stats(ring);
    if (stats_is_error(&stats)) return -1;
    if (stats.free < size){                                      /* plein : on compte la perte, on ne bloque jamais */
        rgm_write_atomic_n_dropped(ring, stats.n_dropped + 1);
        return -1;
    }
    if (_write_at(stats.writer_pos, size, value, ring -> data, stats.size) != 0) return -1;
    rgm_write_atomic_n_write(ring, stats.n_write + size);        /* on publie APRÈS la copie (release) */
    return 0;
}

int ring_read(struct Ring *ring, void *out, uint64_t size){
    if (ring == NULL || out == NULL) return -1;
    RingStats stats = ring_stats(ring);
    if (stats_is_error(&stats)) return -1;
    if (stats.used < size) return -1;
    if (_read_at(stats.reader_pos, size, out, ring -> data, stats.size) != 0) return -1;
    rgm_write_atomic_n_read(ring, stats.n_read + size);          /* on rend la place APRÈS la copie (release) */
    return 0;
}
