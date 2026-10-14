/* test_mmap_ring.c : tests du ring en mémoire partagée (mmap_ring.c)
 *
 * Lancer :  ./run_tests.sh mmap_ring        (voir la ligne SRC[mmap_ring] dans run_tests.sh)
 * Ils n'ont besoin d'aucun droit particulier : les segments vivent dans /dev/shm sous un nom unique (/rt_<pid>_<tag>).
 *
 * ─────────────────────────────── LE CONTRAT QUE CES TESTS VÉRIFIENT ───────────────────────────────
 * Si ton code s'écarte d'une ligne ci-dessous, c'est soit un bug du code, soit un point du contrat à rediscuter.
 *
 *  rgm_open(name, size, write_header)
 *    · name : non vide, commence par '/', pas d'autre '/'. Sinon NULL.
 *    · write_header = 1 (créateur / écrivain) : size doit être > sizeof(Ring) (256), sinon NULL.
 *        Crée le segment, RÉSERVE sa mémoire (posix_fallocate), remet les compteurs à 0 et pose r_size = size - 256.
 *        Droits du segment : 0600 (aucun droit pour le groupe ni les autres). Si le segment existe déjà, il doit
 *        avoir exactement la taille `size` (sinon NULL, et il n'est pas touché) ; ses compteurs sont remis à 0.
 *    · write_header = 0 (lecteur) : le segment doit EXISTER (le lecteur ne crée jamais rien).
 *        size = 0 veut dire « prends la taille du segment » ; sinon size doit être exactement la taille du segment.
 *        Le header doit déjà être initialisé (r_size == taille du segment - 256), sinon NULL.
 *        Il ne change NI la taille du segment NI les compteurs. Un segment trop petit pour contenir le header → NULL.
 *    · un échec ne détruit JAMAIS un segment qui existait déjà.
 *  Disposition mémoire (lue aussi par Python) : n_write@0, n_read@64, r_size@128, n_dropped@192, data@256.
 *  ring_write(ring, data, n) : 0 = écrit · -1 = erreur OU ring plein (dans ce cas n_dropped += 1, rien n'est écrit)
 *  ring_read(ring, out, n)   : 0 = lu · -1 = erreur OU pas assez d'octets disponibles (rien n'est lu)
 *  rgm_load_atomic_XXX(ring, &out) et rgm_write_atomic_XXX(ring, v) : 0 = ok · -1 = erreur (la valeur est dans *out)
 *  stats_is_error(&stats) : une QUESTION → 1 = oui, 0 = non
 *  ring_stats : is_error = 1 si ring NULL ou si le header est incohérent (r_size == 0, n_read > n_write,
 *               ou plus d'octets utilisés que la taille). Elle ne plante jamais, même sur un header mal initialisé.
 *  ring_close(NULL) et ring_destroy(nom invalide ou absent) ne font rien. ring_close ne supprime pas le segment.
 *  r_size lu dans la mémoire partagée n'est pas digne de confiance : démesuré (> 4 Gio) → ring_stats en erreur et
 *  ring_close ne démappe rien.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */
#define _GNU_SOURCE
#include "../test_common.h"
#include "mmap_ring.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ═══════════════════════════ outils ═══════════════════════════ */

static char g_name[64];
static const char *uniq(const char *tag) {          /* nom de segment unique par test et par process */
    snprintf(g_name, sizeof g_name, "/rt_%d_%s", (int)getpid(), tag);
    return g_name;
}

static int shm_exists(const char *name) {
    int fd = shm_open(name, O_RDONLY, 0);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static long long shm_size(const char *name) {
    int fd = shm_open(name, O_RDONLY, 0);
    if (fd < 0) return -1;
    struct stat st;
    long long r = fstat(fd, &st) == 0 ? (long long)st.st_size : -1;
    close(fd);
    return r;
}

static long long shm_reserved_bytes(const char *name) {      /* octets réellement alloués (st_blocks) */
    int fd = shm_open(name, O_RDONLY, 0);
    if (fd < 0) return -1;
    struct stat st;
    long long r = fstat(fd, &st) == 0 ? (long long)st.st_blocks * 512 : -1;
    close(fd);
    return r;
}

static int count_fds(void) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd");
    int n = 0;
    FILE *f = NULL; (void)f;
    char cmd[128];
    snprintf(cmd, sizeof cmd, "ls %s | wc -l", path);
    FILE *p = popen(cmd, "r");
    if (p == NULL) return -1;
    if (fscanf(p, "%d", &n) != 1) n = -1;
    pclose(p);
    return n;
}

static void fill(uint8_t *b, size_t n, uint32_t seed) {
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(seed * 131u + i * 7u + 1u);
}

/* un « faux » ring en mémoire normale, header à zéro : pour tester les headers mal initialisés ou corrompus */
static Ring *fake_ring(uint64_t r_size) {
    Ring *r = aligned_alloc(64, 4096);
    memset(r, 0, 4096);
    r -> r_size = r_size;
    return r;
}

/* un ring de test : capacité = capacity octets */
static Ring *make(const char *tag, uint64_t capacity) {
    const char *name = uniq(tag);
    ring_destroy(name);
    return rgm_open(name, sizeof(Ring) + capacity, 1);
}

/* ═══════════════════════════ 1. disposition mémoire ═══════════════════════════ */

static void t_layout(void) {
    CHECK_EQ(sizeof(Ring), 256, "sizeof(Ring) == 256 : 4 compteurs, un par ligne de cache de 64 octets");
    CHECK_EQ(offsetof(Ring, n_write), 0, "n_write à l'octet 0");
    CHECK_EQ(offsetof(Ring, n_read), 64, "n_read à l'octet 64");
    CHECK_EQ(offsetof(Ring, r_size), 128, "r_size à l'octet 128");
    CHECK_EQ(offsetof(Ring, n_dropped), 192, "n_dropped à l'octet 192");
    CHECK_EQ(offsetof(Ring, data), 256, "data commence à l'octet 256");
    CHECK_EQ(_Alignof(Ring), 64, "alignement 64");
    CHECK(ATOMIC_LLONG_LOCK_FREE == 2, "atomiques 64 bits sans verrou caché (indispensable entre deux processus)");
}

/* ═══════════════════════════ 2. ouverture : arguments ═══════════════════════════ */

static void t_open_arguments(void) {
    CHECK(rgm_open(NULL, 4096, 1) == NULL, "nom NULL → NULL");
    CHECK(rgm_open("", 4096, 1) == NULL, "nom vide → NULL");
    CHECK(rgm_open("sans_slash", 4096, 1) == NULL, "nom sans « / » au début → NULL");
    CHECK(rgm_open("/a/b", 4096, 1) == NULL, "« / » au milieu du nom → NULL");
    CHECK(rgm_open("/rt_zero", 0, 1) == NULL, "créer avec size 0 → NULL");
    CHECK(rgm_open("/rt_petit", 100, 1) == NULL, "size < sizeof(Ring) → NULL (pas de dépassement d'entier non signé)");
    CHECK(rgm_open("/rt_exact", sizeof(Ring), 1) == NULL, "size == sizeof(Ring) : aucune place pour les données → NULL");
    CHECK(!shm_exists("/rt_zero") && !shm_exists("/rt_petit") && !shm_exists("/rt_exact"),
          "un échec de validation ne laisse aucun segment derrière lui");
}

static void t_open_taille_minimale(void) {
    Ring *r = make("min", 1);
    CHECK(r != NULL, "size = 257 : un ring d'UN octet de capacité");
    if (r == NULL) return;
    uint8_t a = 0xAB, b = 0;
    CHECK_EQ(ring_write(r, &a, 1), 0, "écrire 1 octet");
    CHECK_EQ(ring_write(r, &a, 1), -1, "le 2e octet ne rentre pas : plein");
    CHECK_EQ(ring_read(r, &b, 1), 0, "lire 1 octet");
    CHECK_EQ(b, 0xAB, "valeur relue");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_header_initial(void) {
    Ring *r = make("hdr", 3840);                 /* 256 + 3840 = 4096 */
    CHECK(r != NULL, "création 4096 octets");
    if (r == NULL) return;
    uint64_t v = 99;
    CHECK_EQ(rgm_load_atomic_n_write(r, &v), 0, "load n_write → 0");  CHECK(v == 0, "n_write == 0");
    CHECK_EQ(rgm_load_atomic_n_read(r, &v), 0, "load n_read → 0");    CHECK(v == 0, "n_read == 0");
    CHECK_EQ(rgm_load_atomic_n_dropped(r, &v), 0, "load n_dropped → 0"); CHECK(v == 0, "n_dropped == 0");
    CHECK_EQ(rgm_load_atomic_size(r, &v), 0, "load r_size → 0");      CHECK(v == 3840, "r_size == 4096 - 256");
    RingStats s = ring_stats(r);
    CHECK_EQ(stats_is_error(&s), 0, "stats : pas d'erreur");
    CHECK(s.size == 3840 && s.free == 3840 && s.used == 0, "size == free == 3840, used == 0");
    CHECK(s.total_size == 4096, "total_size == taille du segment (4096)");
    CHECK(s.writer_pos == 0 && s.reader_pos == 0, "positions à 0");
    CHECK_EQ(shm_size(g_name), 4096, "le segment fait 4096 octets");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_droits_du_segment(void) {
    Ring *r = make("perm", 100);
    CHECK(r != NULL, "création");
    if (r == NULL) return;
    int fd = shm_open(g_name, O_RDONLY, 0);
    struct stat st;
    CHECK(fd >= 0 && fstat(fd, &st) == 0, "fstat du segment");
    if (fd >= 0) {
        CHECK((st.st_mode & 077) == 0, "aucun droit pour le groupe ni pour les autres (0600) : le ring contient des flux réseau");
        close(fd);
    }
    ring_close(r);
    ring_destroy(g_name);
}

/* ═══════════════════════════ 3. écriture / lecture ═══════════════════════════ */

static void t_ecriture_lecture(void) {
    Ring *r = make("rw", 100);
    CHECK(r != NULL, "création");
    if (r == NULL) return;
    uint8_t in[10], out[10];
    fill(in, 10, 1);
    CHECK_EQ(ring_write(r, in, 10), 0, "écrire 10 octets");
    RingStats s = ring_stats(r);
    CHECK(s.n_write == 10 && s.used == 10 && s.free == 90, "n_write 10, used 10, free 90");
    CHECK_EQ(ring_read(r, out, 10), 0, "lire 10 octets");
    CHECK_MEM(out, in, 10, "mêmes octets");
    s = ring_stats(r);
    CHECK(s.n_read == 10 && s.used == 0 && s.free == 100, "n_read 10, used 0, free 100");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_arguments_nuls(void) {
    Ring *r = make("nuls", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint8_t b[4] = {1, 2, 3, 4};
    CHECK_EQ(ring_write(NULL, b, 4), -1, "ring_write(ring NULL) → -1");
    CHECK_EQ(ring_write(r, NULL, 4), -1, "ring_write(data NULL) → -1");
    CHECK_EQ(ring_read(NULL, b, 4), -1, "ring_read(ring NULL) → -1");
    CHECK_EQ(ring_read(r, NULL, 4), -1, "ring_read(out NULL) → -1");
    RingStats s = ring_stats(r);
    CHECK(s.n_write == 0 && s.n_read == 0 && s.n_dropped == 0, "rien n'a bougé");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_lecture_vide_ou_trop_grande(void) {
    Ring *r = make("vide", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint8_t in[10], out[20];
    fill(in, 10, 2);
    CHECK_EQ(ring_read(r, out, 1), -1, "lire dans un ring vide → -1");
    ring_write(r, in, 10);
    CHECK_EQ(ring_read(r, out, 11), -1, "lire plus que ce qui est écrit → -1");
    RingStats s = ring_stats(r);
    CHECK(s.n_read == 0 && s.used == 10, "rien n'a été consommé par la lecture ratée");
    CHECK_EQ(ring_read(r, out, 10), 0, "lire exactement ce qui est là");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_octets_bruts_dans_data(void) {
    Ring *r = make("raw", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint8_t a[5] = {1, 2, 3, 4, 5}, b[3] = {6, 7, 8}, out[8];
    ring_write(r, a, 5);
    CHECK_MEM(r -> data, a, 5, "les 5 octets sont au tout début de data (octet 256 du segment)");
    ring_write(r, b, 3);
    CHECK_MEM(r -> data + 5, b, 3, "les 3 suivants juste après");
    CHECK_EQ(ring_read(r, out, 8), 0, "lecture des 8");
    CHECK(memcmp(out, a, 5) == 0 && memcmp(out + 5, b, 3) == 0, "dans l'ordre : FIFO");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_enroulement(void) {
    Ring *r = make("wrap", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint8_t a[80], b[60], out[80];
    fill(a, 80, 3); fill(b, 60, 4);
    CHECK_EQ(ring_write(r, a, 80), 0, "écrire 80");
    CHECK_EQ(ring_read(r, out, 80), 0, "lire 80");
    CHECK_EQ(ring_write(r, b, 60), 0, "écrire 60 : 20 octets à la fin, 40 au début");
    CHECK_MEM(r -> data + 80, b, 20, "les 20 premiers octets sont à la fin de data");
    CHECK_MEM(r -> data, b + 20, 40, "les 40 suivants sont revenus au début de data");
    RingStats s = ring_stats(r);
    CHECK(s.writer_pos == 40 && s.reader_pos == 80, "writer_pos = 140 % 100 = 40, reader_pos = 80");
    CHECK_EQ(ring_read(r, out, 60), 0, "lire 60 à travers la frontière");
    CHECK_MEM(out, b, 60, "octets intacts après l'enroulement");
    s = ring_stats(r);
    CHECK(s.reader_pos == 40 && s.writer_pos == 40 && s.used == 0, "positions identiques, ring vide");
    ring_close(r);
    ring_destroy(g_name);
}

/* ═══════════════════════════ 4. ring plein ═══════════════════════════ */

static void t_plein(void) {
    Ring *r = make("full", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint8_t a[60], b[50], c[40], d[1] = {9}, out[100];
    fill(a, 60, 5); fill(b, 50, 6); fill(c, 40, 7);
    CHECK_EQ(ring_write(r, a, 60), 0, "60 sur 100");
    CHECK_EQ(ring_write(r, b, 50), -1, "50 de plus ne rentrent pas → -1");
    RingStats s = ring_stats(r);
    CHECK(s.n_dropped == 1, "n_dropped == 1");
    CHECK(s.n_write == 60 && s.used == 60, "rien n'a été écrit par l'écriture refusée");
    CHECK_EQ(ring_write(r, c, 40), 0, "40 : exactement plein");
    s = ring_stats(r);
    CHECK(s.free == 0 && s.used == 100, "free 0, used 100");
    CHECK_EQ(ring_write(r, d, 1), -1, "1 octet de plus → -1");
    s = ring_stats(r);
    CHECK(s.n_dropped == 2, "n_dropped == 2");
    CHECK_EQ(ring_read(r, out, 100), 0, "tout relire");
    CHECK(memcmp(out, a, 60) == 0 && memcmp(out + 60, c, 40) == 0, "le contenu refusé (b) n'est pas là, le reste est intact");
    CHECK_EQ(ring_write(r, b, 50), 0, "après lecture, la place est revenue");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_ecriture_plus_grande_que_le_ring(void) {
    Ring *r = make("big", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint8_t big[101];
    fill(big, 101, 8);
    CHECK_EQ(ring_write(r, big, 101), -1, "101 octets dans un ring de 100, même vide → -1");
    RingStats s = ring_stats(r);
    CHECK(s.n_write == 0 && s.n_dropped == 1, "rien écrit, 1 perte comptée");
    ring_close(r);
    ring_destroy(g_name);
}

/* ═══════════════════════════ 5. modèle : des milliers d'opérations, tout est vérifié ═══════════════════════════ */

static size_t msg_len(uint64_t seq) { return 1 + (size_t)((seq * 37) % 70); }
static void msg_fill(uint8_t *b, uint64_t seq) {
    size_t n = msg_len(seq);
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(seq * 131 + i * 7 + 1);
}

static void t_fifo_modele(void) {
    const uint64_t CAP = 128;
    Ring *r = make("model", CAP);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint64_t next_w = 0, next_r = 0, used = 0, dropped = 0, rnd = 12345;
    int bad_write = 0, bad_read = 0, bad_data = 0, bad_stats = 0, bad_empty = 0;
    uint8_t buf[80], exp[80];
    for (int step = 0; step < 20000; step++) {
        rnd = rnd * 1103515245u + 12345u;
        if ((rnd >> 16) & 1) {                                       /* essayer d'écrire le message suivant */
            size_t len = msg_len(next_w);
            msg_fill(buf, next_w);
            int rc = ring_write(r, buf, len);
            int should_fit = len <= CAP - used;
            if ((rc == 0) != should_fit) bad_write++;
            if (rc == 0) { next_w++; used += len; } else { dropped++; }
        } else if (next_r < next_w) {                                /* lire le plus ancien message */
            size_t len = msg_len(next_r);
            if (ring_read(r, buf, len) != 0) { bad_read++; break; }
            msg_fill(exp, next_r);
            if (memcmp(buf, exp, len) != 0) bad_data++;
            next_r++; used -= len;
        } else {                                                     /* ring vide : lire doit échouer */
            if (ring_read(r, buf, 1) != -1) bad_empty++;
        }
        RingStats s = ring_stats(r);
        if (stats_is_error(&s) != 0 || s.used != used || s.free != CAP - used || s.n_dropped != dropped
            || s.writer_pos != s.n_write % CAP || s.reader_pos != s.n_read % CAP) bad_stats++;
    }
    CHECK_EQ(bad_write, 0, "ring_write réussit exactement quand le message rentre");
    CHECK_EQ(bad_read, 0, "ring_read réussit toujours quand un message complet est là");
    CHECK_EQ(bad_data, 0, "chaque message est relu à l'identique, dans l'ordre (20 000 opérations, enroulements compris)");
    CHECK_EQ(bad_empty, 0, "lire un ring vide échoue toujours");
    CHECK_EQ(bad_stats, 0, "stats cohérentes à chaque étape (used, free, n_dropped, positions)");
    CHECK(next_w > 1000 && dropped > 0, "le test a bien exercé l'écriture ET le ring plein");
    ring_close(r);
    ring_destroy(g_name);
}

/* ═══════════════════════════ 6. stats et erreurs ═══════════════════════════ */

static void t_stats_erreurs(void) {
    RingStats s = ring_stats(NULL);
    CHECK_EQ(s.is_error, 1, "ring_stats(NULL) : is_error == 1");
    CHECK_EQ(stats_is_error(&s), 1, "stats_is_error(stats en erreur) == 1");
    CHECK_EQ(stats_is_error(NULL), 1, "stats_is_error(NULL) == 1 : on ne peut pas dire que c'est bon");
    Ring *r = make("st", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    s = ring_stats(r);
    CHECK_EQ(stats_is_error(&s), 0, "stats_is_error(ring valide) == 0");
    ring_close(r);
    ring_destroy(g_name);
}

static void t_header_incoherent(void) {
    uint8_t b[4] = {1, 2, 3, 4};
    Ring *r = fake_ring(0);                                          /* r_size == 0 : header jamais initialisé */
    RingStats s = ring_stats(r);
    CHECK_EQ(s.is_error, 1, "r_size == 0 → is_error (et pas de division par zéro)");
    CHECK_EQ(ring_write(r, b, 4), -1, "ring_write sur header non initialisé → -1");
    CHECK_EQ(ring_read(r, b, 4), -1, "ring_read sur header non initialisé → -1");
    CHECK(r -> n_write == 0, "n_write inchangé");
    free(r);

    r = fake_ring(100);
    r -> n_write = 5; r -> n_read = 10;                               /* lu plus que écrit */
    s = ring_stats(r);
    CHECK_EQ(s.is_error, 1, "n_read > n_write → is_error");
    CHECK_EQ(ring_write(r, b, 4), -1, "ring_write → -1");
    free(r);

    r = fake_ring(100);
    r -> n_write = 5000; r -> n_read = 0;                             /* plus d'octets « utilisés » que la taille */
    s = ring_stats(r);
    CHECK_EQ(s.is_error, 1, "used > size → is_error (et pas de free négatif)");
    CHECK_EQ(ring_read(r, b, 4), -1, "ring_read → -1");
    free(r);
}

/* ═══════════════════════════ 7. les accès atomiques (loads / setters) ═══════════════════════════ */

static void t_loads_et_setters(void) {
    Ring *r = make("ld", 100);
    if (r == NULL) { CHECK(0, "création"); return; }
    uint64_t v = 123;
    CHECK_EQ(rgm_load_atomic_n_read(NULL, &v), -1, "load n_read(ring NULL) → -1");
    CHECK_EQ(rgm_load_atomic_n_write(NULL, &v), -1, "load n_write(ring NULL) → -1");
    CHECK_EQ(rgm_load_atomic_size(NULL, &v), -1, "load r_size(ring NULL) → -1");
    CHECK_EQ(rgm_load_atomic_n_dropped(NULL, &v), -1, "load n_dropped(ring NULL) → -1");
    CHECK(v == 123, "*out n'est pas touché quand il y a erreur");
    CHECK_EQ(rgm_load_atomic_n_read(r, NULL), -1, "load n_read(out NULL) → -1");
    CHECK_EQ(rgm_load_atomic_n_write(r, NULL), -1, "load n_write(out NULL) → -1");
    CHECK_EQ(rgm_load_atomic_size(r, NULL), -1, "load r_size(out NULL) → -1");
    CHECK_EQ(rgm_load_atomic_n_dropped(r, NULL), -1, "load n_dropped(out NULL) → -1");

    CHECK_EQ(rgm_write_atomic_n_write(NULL, 1), -1, "setter n_write(NULL) → -1");
    CHECK_EQ(rgm_write_atomic_n_read(NULL, 1), -1, "setter n_read(NULL) → -1");
    CHECK_EQ(rgm_write_atomic_n_dropped(NULL, 1), -1, "setter n_dropped(NULL) → -1");

    /* la valeur 0xFFFF... est une valeur LÉGITIME : elle ne doit pas être confondue avec une erreur */
    CHECK_EQ(rgm_write_atomic_n_dropped(r, UINT64_MAX), 0, "setter n_dropped = UINT64_MAX → 0");
    v = 0;
    CHECK_EQ(rgm_load_atomic_n_dropped(r, &v), 0, "load de UINT64_MAX → 0 (succès)");
    CHECK(v == UINT64_MAX, "la valeur UINT64_MAX est bien rendue, sans ambiguïté avec l'erreur");
    CHECK_EQ(rgm_write_atomic_n_write(r, 7), 0, "setter n_write");
    CHECK_EQ(rgm_write_atomic_n_read(r, 3), 0, "setter n_read");
    RingStats s = ring_stats(r);
    CHECK(s.n_write == 7 && s.n_read == 3 && s.used == 4, "les setters et ring_stats voient les mêmes compteurs");
    ring_close(r);
    ring_destroy(g_name);
}

/* ═══════════════════════════ 8. ouvrir un ring qui existe (le lecteur) ═══════════════════════════ */

static void t_lecteur_partage_la_memoire(void) {
    Ring *w = make("share", 3840);
    if (w == NULL) { CHECK(0, "création"); return; }
    uint8_t in[30], out[30];
    fill(in, 30, 9);
    CHECK_EQ(ring_write(w, in, 30), 0, "l'écrivain écrit 30 octets");
    Ring *r = rgm_open(g_name, 0, 0);                                /* size 0 : « prends la taille du segment » */
    CHECK(r != NULL, "le lecteur ouvre le segment existant");
    if (r == NULL) { ring_close(w); ring_destroy(g_name); return; }
    CHECK(r != w, "deux mappings distincts du même segment");
    uint64_t v = 0;
    rgm_load_atomic_size(r, &v);
    CHECK(v == 3840, "le lecteur voit r_size == 3840");
    rgm_load_atomic_n_write(r, &v);
    CHECK(v == 30, "ouvrir en lecteur n'a PAS remis les compteurs à zéro : n_write == 30");
    CHECK_EQ(ring_read(r, out, 30), 0, "le lecteur lit ce que l'écrivain a écrit");
    CHECK_MEM(out, in, 30, "mêmes octets");
    RingStats s = ring_stats(w);
    CHECK(s.n_read == 30 && s.used == 0, "l'écrivain voit la lecture : n_read == 30");
    ring_close(r);

    Ring *r2 = rgm_open(g_name, 4096, 0);                            /* taille exacte donnée explicitement */
    CHECK(r2 != NULL, "ouverture avec la taille exacte du segment");
    ring_close(r2);
    ring_close(w);
    ring_destroy(g_name);
}

static void t_lecteur_refus(void) {
    const char *name = uniq("refus");
    ring_destroy(name);
    CHECK(rgm_open(name, 0, 0) == NULL, "segment inexistant → NULL");
    CHECK(!shm_exists(name), "le lecteur n'a CRÉÉ aucun segment");

    Ring *w = rgm_open(name, 4096, 1);
    CHECK(w != NULL, "création 4096");
    if (w == NULL) return;
    CHECK(rgm_open(name, 8192, 0) == NULL, "taille demandée (8192) != taille du segment (4096) → NULL");
    CHECK(rgm_open(name, 2048, 0) == NULL, "taille demandée (2048) != taille du segment → NULL");
    CHECK_EQ(shm_size(name), 4096, "le segment n'a pas changé de taille (le lecteur ne fait jamais ftruncate)");
    ring_close(w);
    ring_destroy(name);
}

static void t_lecteur_header_non_initialise(void) {
    const char *name = uniq("noinit");
    ring_destroy(name);
    int fd = shm_open(name, O_CREAT | O_RDWR, 0600);                 /* un segment de la bonne taille, rempli de 0 */
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0, "segment vide préparé à la main");
    if (fd >= 0) close(fd);
    Ring *r = rgm_open(name, 0, 0);
    CHECK(r == NULL, "header non initialisé (r_size == 0) → NULL, pas un ring inutilisable");
    ring_close(r);
    shm_unlink(name);
}

/* ═══════════════════════════ 9. l'écrivain qui redémarre, les échecs ═══════════════════════════ */

static void t_ecrivain_redemarre(void) {
    Ring *w = make("again", 3840);
    if (w == NULL) { CHECK(0, "création"); return; }
    uint8_t in[10];
    fill(in, 10, 10);
    ring_write(w, in, 10);
    ring_close(w);
    CHECK(shm_exists(g_name), "ring_close ne supprime pas le segment");
    Ring *w2 = rgm_open(g_name, 4096, 1);                            /* l'écrivain redémarre */
    CHECK(w2 != NULL, "réouverture en écrivain d'un segment existant");
    if (w2 == NULL) { ring_destroy(g_name); return; }
    RingStats s = ring_stats(w2);
    CHECK(s.n_write == 0 && s.n_read == 0 && s.n_dropped == 0 && s.size == 3840, "header remis à zéro");
    ring_close(w2);
    ring_destroy(g_name);
}

static void t_echec_ne_detruit_pas_un_segment_existant(void) {
    Ring *w = make("surv", 3840);
    if (w == NULL) { CHECK(0, "création"); return; }
    uint8_t in[10], out[10];
    fill(in, 10, 11);
    ring_write(w, in, 10);
    Ring *bad = rgm_open(g_name, 1ULL << 62, 1);                     /* 4 Eio : impossible à mapper */
    CHECK(bad == NULL, "création démesurée → NULL");
    ring_close(bad);
    CHECK(shm_exists(g_name), "le segment existant n'a PAS été supprimé par l'échec");
    CHECK_EQ(shm_size(g_name), 4096, "ni redimensionné");
    Ring *r = rgm_open(g_name, 0, 0);
    CHECK(r != NULL, "un lecteur peut toujours l'ouvrir");
    if (r) {
        CHECK_EQ(ring_read(r, out, 10), 0, "et il retrouve les données de l'écrivain");
        CHECK_MEM(out, in, 10, "intactes");
        ring_close(r);
    }
    ring_close(w);
    ring_destroy(g_name);
}

static void t_close_et_destroy(void) {
    Ring *w = make("life", 100);
    if (w == NULL) { CHECK(0, "création"); return; }
    const char *name = g_name;
    ring_close(w);
    CHECK(shm_exists(name), "après ring_close, le segment existe encore");
    ring_destroy(name);
    CHECK(!shm_exists(name), "après ring_destroy, il n'existe plus");
    CHECK(rgm_open(name, 0, 0) == NULL, "on ne peut plus l'ouvrir");
    ring_destroy(name);                                              /* 2e fois : sans effet */
    ring_destroy(NULL);
    ring_destroy("");
    ring_destroy("sans_slash");
    ring_close(NULL);
    CHECK(1, "destroy / close sur des arguments invalides ou absents ne plantent pas");
}

static void t_pas_de_fuite_de_descripteurs(void) {
    int avant = count_fds();
    for (int i = 0; i < 100; i++) {
        Ring *r = make("fd", 100);
        Ring *l = rgm_open(g_name, 0, 0);
        ring_close(l);
        ring_close(r);
        ring_destroy(g_name);
    }
    for (int i = 0; i < 50; i++) {
        rgm_open("/rt_inexistant_xyz", 0, 0);
        rgm_open("/rt_trop_petit", 10, 1);
    }
    CHECK_EQ(count_fds(), avant, "aucun descripteur de fichier perdu (cycles et échecs)");
}

/* ═══════════════════════════ 10. deux vrais processus ═══════════════════════════ */

#define XN 200000
#define XLEN 28            /* 28 ne divise pas 3840 : des messages enjambent la fin du ring */

static void xfill(uint8_t *b, uint64_t seq) {
    for (int i = 0; i < XLEN; i++) b[i] = (uint8_t)(seq * 31 + (uint64_t)i);
}

static void t_deux_processus(void) {
    alarm(60);
    const char *name = uniq("xproc");
    ring_destroy(name);
    Ring *w = rgm_open(name, 4096, 1);
    CHECK(w != NULL, "création du ring");
    if (w == NULL) return;
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {                                                  /* ENFANT = lecteur */
        Ring *r = rgm_open(name, 0, 0);
        if (r == NULL) _exit(10);
        uint8_t buf[XLEN], exp[XLEN];
        uint64_t seq = 0;
        int idle = 0;
        while (seq < XN) {
            if (ring_read(r, buf, XLEN) == 0) {
                xfill(exp, seq);
                if (memcmp(buf, exp, XLEN) != 0) _exit(11);          /* octets abîmés ou dans le mauvais ordre */
                seq++; idle = 0;
            } else {
                sched_yield();
                if (++idle > 20000000) _exit(12);                    /* plus rien n'arrive */
            }
        }
        ring_close(r);
        _exit(0);
    }
    uint8_t buf[XLEN];                                               /* PARENT = écrivain */
    for (uint64_t seq = 0; seq < XN; seq++) {
        xfill(buf, seq);
        int tries = 0;
        while (ring_write(w, buf, XLEN) != 0) {
            sched_yield();
            if (++tries > 20000000) { kill(pid, SIGKILL); CHECK(0, "l'écrivain est bloqué : le lecteur ne lit plus"); return; }
        }
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status), "le lecteur s'est terminé normalement");
    CHECK_EQ(WEXITSTATUS(status), 0, "le lecteur a relu 200 000 messages, tous intacts et dans l'ordre (10 = ouverture, 11 = octets abîmés, 12 = bloqué)");
    RingStats s = ring_stats(w);
    CHECK(s.n_write == (uint64_t)XN * XLEN && s.n_read == (uint64_t)XN * XLEN, "n_write == n_read == 200 000 × 28 octets");
    CHECK(s.used == 0, "ring vide à la fin");
    ring_close(w);
    ring_destroy(name);
}


/* ═══════════════════════════ 11. durcissement ═══════════════════════════ */

static void t_lecteur_segment_minuscule(void) {
    const char *name = uniq("tiny");
    long tailles[] = {0, 1, 100, 255, 256};                          /* 256 = le header seul : aucune place pour les données */
    for (int i = 0; i < 5; i++) {
        ring_destroy(name);
        int fd = shm_open(name, O_CREAT | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, tailles[i]) != 0) { CHECK(0, "segment minuscule préparé à la main"); return; }
        close(fd);
        Ring *r = rgm_open(name, 0, 0);
        CHECK(r == NULL, "segment trop petit pour contenir le header → NULL");
        ring_close(r);
        shm_unlink(name);
    }
}

static void t_ecrivain_autre_taille(void) {
    Ring *w = make("size", 3840);                                    /* segment de 4096 */
    if (w == NULL) { CHECK(0, "création"); return; }
    uint8_t in[10], out[10];
    fill(in, 10, 12);
    ring_write(w, in, 10);
    CHECK(rgm_open(g_name, 8192, 1) == NULL, "écrivain avec une autre taille que le segment existant → NULL");
    CHECK(rgm_open(g_name, 2048, 1) == NULL, "idem avec une taille plus petite → NULL");
    CHECK_EQ(shm_size(g_name), 4096, "le segment n'a pas changé de taille");
    Ring *r = rgm_open(g_name, 0, 0);
    CHECK(r != NULL, "il est toujours ouvrable");
    if (r) {
        CHECK_EQ(ring_read(r, out, 10), 0, "et ses données sont intactes");
        CHECK_MEM(out, in, 10, "mêmes octets");
        ring_close(r);
    }
    ring_close(w);
    ring_destroy(g_name);
}

static void t_memoire_reservee(void) {
    Ring *w = make("alloc", (1u << 20) - sizeof(Ring));              /* segment de 1 Mio */
    if (w == NULL) { CHECK(0, "création"); return; }
    CHECK(shm_reserved_bytes(g_name) >= (1 << 20),
          "la mémoire est RÉSERVÉE dès l'ouverture (posix_fallocate) : /dev/shm trop petit = erreur ici, pas un SIGBUS plus tard");
    ring_close(w);
    ring_destroy(g_name);
}

static void t_taille_demesuree_dans_le_header(void) {
    uint8_t b[4] = {1, 2, 3, 4};
    Ring *r = fake_ring(1ULL << 40);                                 /* quelqu'un a écrit 2^40 dans r_size */
    RingStats s = ring_stats(r);
    CHECK_EQ(s.is_error, 1, "r_size = 2^40 → is_error");
    CHECK_EQ(ring_write(r, b, 4), -1, "ring_write refuse (au lieu d'écrire hors du segment)");
    CHECK_EQ(ring_read(r, b, 4), -1, "ring_read refuse");
    ring_close(r);                                                   /* ne doit rien démapper : ce n'est même pas un mapping */
    CHECK(1, "ring_close avec un r_size démesuré ne démappe rien");
    free(r);
}

/* ═══════════════════════════ main ═══════════════════════════ */

int main(int argc, char **argv) {
    tc_begin("test_mmap_ring.c", argc, argv);

    printf("\n── 1. disposition mémoire (lue aussi par Python) ──\n");
    RUN("layout : tailles, positions, atomiques sans verrou",    t_layout);

    printf("\n── 2. ouverture : arguments ──\n");
    RUN_LEAKS("open : arguments invalides",                      t_open_arguments);
    RUN_LEAKS("open : capacité minimale (1 octet)",              t_open_taille_minimale);
    RUN_LEAKS("open : header initial",                           t_header_initial);
    RUN_LEAKS("open : droits du segment (0600)",                 t_droits_du_segment);

    printf("\n── 3. écriture / lecture ──\n");
    RUN_LEAKS("écrire puis lire",                                t_ecriture_lecture);
    RUN_LEAKS("arguments NULL",                                  t_arguments_nuls);
    RUN_LEAKS("lecture : vide, ou plus que disponible",          t_lecture_vide_ou_trop_grande);
    RUN_LEAKS("octets bruts dans data",                          t_octets_bruts_dans_data);
    RUN_LEAKS("enroulement (écriture et lecture à cheval)",      t_enroulement);

    printf("\n── 4. ring plein ──\n");
    RUN_LEAKS("plein : n_dropped, rien d'écrit",                 t_plein);
    RUN_LEAKS("écriture plus grande que le ring",                t_ecriture_plus_grande_que_le_ring);

    printf("\n── 5. modèle : 20 000 opérations ──\n");
    RUN_LEAKS("FIFO contre un modèle",                           t_fifo_modele);

    printf("\n── 6. stats et erreurs ──\n");
    RUN_LEAKS("stats : erreurs et stats_is_error",               t_stats_erreurs);
    RUN_LEAKS("header incohérent : pas de plantage",             t_header_incoherent);

    printf("\n── 7. loads et setters ──\n");
    RUN_LEAKS("loads : erreur signalée à part de la valeur",     t_loads_et_setters);

    printf("\n── 8. le lecteur ──\n");
    RUN_LEAKS("lecteur : même mémoire, compteurs conservés",     t_lecteur_partage_la_memoire);
    RUN_LEAKS("lecteur : refus (absent, mauvaise taille)",       t_lecteur_refus);
    RUN_LEAKS("lecteur : header non initialisé",                 t_lecteur_header_non_initialise);

    printf("\n── 9. cycle de vie ──\n");
    RUN_LEAKS("l'écrivain redémarre",                            t_ecrivain_redemarre);
    RUN_LEAKS("un échec ne détruit pas un segment existant",     t_echec_ne_detruit_pas_un_segment_existant);
    RUN_LEAKS("close et destroy",                                t_close_et_destroy);
    RUN_LEAKS("aucun descripteur perdu",                         t_pas_de_fuite_de_descripteurs);

    printf("\n── 11. durcissement ──\n");
    RUN_LEAKS("lecteur : segment trop petit pour le header",     t_lecteur_segment_minuscule);
    RUN_LEAKS("écrivain : taille différente du segment",         t_ecrivain_autre_taille);
    RUN_LEAKS("mémoire réservée à l'ouverture",                  t_memoire_reservee);
    RUN_LEAKS("r_size démesuré dans le header",                  t_taille_demesuree_dans_le_header);

    printf("\n── 10. deux vrais processus ──\n");
    RUN("fork : 200 000 messages, un écrivain, un lecteur",      t_deux_processus);

    return tc_end();
}
