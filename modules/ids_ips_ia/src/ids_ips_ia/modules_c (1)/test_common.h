/* test_common.h : mini-framework de tests partagé par tous les test_*.c
 *
 * Principes :
 *  - chaque test tourne dans un PROCESS ENFANT : un plantage (segfault, ASan, boucle infinie)
 *    donne UN test rouge, pas la fin de toute la série ;
 *  - un test = une fonction void f(void) qui appelle CHECK / CHECK_EQ / ... ;
 *  - alarm(5) : une boucle infinie est signalée au bout de 5 secondes ;
 *  - les fuites mémoire ne sont vérifiées QUE par les tests déclarés avec RUN_LEAKS
 *    (sinon un seul bug de free ferait rougir tous les tests) ;
 *  - ./test_xxx            → lance tout
 *    ./test_xxx motif      → lance seulement les tests dont le titre contient « motif »
 *    TC_NOFORK=1 ./test_xxx motif → pas de fork (pour gdb ou valgrind)
 *
 * Compiler avec les sanitizers (voir run_tests.sh) :
 *   -fsanitize=address,undefined -g -O0
 */
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/lsan_interface.h>
#define TC_LSAN_OFF() __lsan_disable()
#else
#define TC_LSAN_OFF() ((void)0)
#endif

/* code de sortie 99 = « un sanitizer a trouvé quelque chose » */
const char *__asan_default_options(void)  { return "detect_leaks=1:exitcode=99"; }
const char *__ubsan_default_options(void) { return "halt_on_error=1:exitcode=99:print_stacktrace=1"; }

static int tc_checks = 0, tc_fails = 0;           /* compteurs du test en cours */
static int tc_n_ok = 0, tc_n_fail = 0, tc_n_crash = 0;
static const char *tc_only = NULL;

/* ───────────── vérifications ───────────── */
#define CHECK(cond, msg) do {                                                        \
        tc_checks++;                                                                 \
        if (!(cond)) { tc_fails++; printf("      ✗ %s  (ligne %d)\n", (msg), __LINE__); } \
    } while (0)

#define CHECK_EQ(got, want, msg) do {                                                \
        long long g_ = (long long)(got), w_ = (long long)(want);                     \
        tc_checks++;                                                                 \
        if (g_ != w_) { tc_fails++;                                                  \
            printf("      ✗ %s : obtenu %lld, attendu %lld  (ligne %d)\n", (msg), g_, w_, __LINE__); } \
    } while (0)

#define CHECK_EQ_HEX(got, want, msg) do {                                            \
        unsigned long long g_ = (unsigned long long)(got), w_ = (unsigned long long)(want); \
        tc_checks++;                                                                 \
        if (g_ != w_) { tc_fails++;                                                  \
            printf("      ✗ %s : obtenu 0x%llX, attendu 0x%llX  (ligne %d)\n", (msg), g_, w_, __LINE__); } \
    } while (0)

#define CHECK_PTR(got, want, msg) do {                                               \
        const void *g_ = (const void *)(got), *w_ = (const void *)(want);            \
        tc_checks++;                                                                 \
        if (g_ != w_) { tc_fails++;                                                  \
            printf("      ✗ %s : obtenu %p, attendu %p  (ligne %d)\n", (msg), g_, w_, __LINE__); } \
    } while (0)

#define CHECK_MEM(got, want, n, msg) do {                                            \
        tc_checks++;                                                                 \
        if (memcmp((got), (want), (n)) != 0) { tc_fails++;                           \
            printf("      ✗ %s : octets différents  (ligne %d)\n", (msg), __LINE__); } \
    } while (0)

/* ───────────── lanceur ───────────── */
static void tc_run(const char *title, void (*fn)(void), int check_leaks) {
    if (tc_only && !strstr(title, tc_only)) return;
    printf("▶ %s\n", title);
    fflush(stdout);

    if (getenv("TC_NOFORK")) {                    /* mode debug : tout dans ce process */
        tc_checks = tc_fails = 0;
        fn();
        if (tc_fails) { printf("   ✗ ÉCHEC : %d vérification(s) ratée(s) sur %d\n", tc_fails, tc_checks); tc_n_fail++; }
        else          { printf("   ✓ OK (%d vérifications)\n", tc_checks); tc_n_ok++; }
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {                               /* ── enfant ── */
        setvbuf(stdout, NULL, _IONBF, 0);         /* rien de perdu si ça plante */
        if (!check_leaks) TC_LSAN_OFF();
        alarm(5);
        tc_checks = tc_fails = 0;
        fn();
        if (tc_fails) printf("   ✗ ÉCHEC : %d vérification(s) ratée(s) sur %d\n", tc_fails, tc_checks);
        exit(tc_fails ? 1 : 0);
    }
    int st = 0;                                   /* ── parent ── */
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) {
        int sig = WTERMSIG(st);
        if (sig == SIGALRM) printf("   ⏱  BOUCLE INFINIE ? (plus de 5 s)\n");
        else                printf("   💥 PLANTAGE : signal %d (%s)\n", sig, strsignal(sig));
        tc_n_crash++;
    } else if (WEXITSTATUS(st) == 0) { printf("   ✓ OK\n"); tc_n_ok++; }
    else if (WEXITSTATUS(st) == 1)   { tc_n_fail++; }
    else { printf("   💥 SANITIZER (ASan / UBSan / LSan) : voir le rapport juste au-dessus\n"); tc_n_crash++; }
}

#define RUN(title, fn)       tc_run((title), (fn), 0)
#define RUN_LEAKS(title, fn) tc_run((title), (fn), 1)   /* vérifie aussi les fuites mémoire */

static void tc_begin(const char *file, int argc, char **argv) {
    if (argc > 1) tc_only = argv[1];
    printf("\n════════════════════════════════════════════════════════\n");
    printf(" %s\n", file);
    printf("════════════════════════════════════════════════════════\n");
}

static int tc_end(void) {
    printf("\n────────────────────────────────────────────────────────\n");
    printf(" ✓ %d OK   ✗ %d échecs   💥 %d plantages\n", tc_n_ok, tc_n_fail, tc_n_crash);
    printf("────────────────────────────────────────────────────────\n");
    return (tc_n_fail || tc_n_crash) ? 1 : 0;
}

#endif
