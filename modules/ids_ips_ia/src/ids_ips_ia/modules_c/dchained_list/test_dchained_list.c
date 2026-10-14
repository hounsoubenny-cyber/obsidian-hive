/* test_dchained_list.c : tests de la liste doublement chaînée (file LRU des flux)
 *
 * Compiler (depuis modules_c/) :
 *   gcc -std=gnu11 -g -O0 -Wall -Wextra -fsanitize=address,undefined \
 *       dchained_list/test_dchained_list.c dchained_list/dchained_list.c -o build/test_dcl
 * Ou simplement : ./run_tests.sh dchained_list
 *
 * Convention de la liste (celle de flow_table) :
 *   head = le plus ANCIEN, tail = le plus RÉCENT.
 *   add_to_end ajoute côté tail, add_to_top côté head.
 *
 * Contrat testé :
 *   - liste vide : head == tail == NULL et n_elements == 0
 *   - après CHAQUE opération : n_elements juste, head/tail justes, head->lru_prev == NULL,
 *     tail->lru_next == NULL, et le parcours dans les DEUX sens donne le même ordre
 *   - delete_from_top / delete_from_end libèrent (free) le FlowEntry retiré :
 *     on ne le touche plus après
 *   - max_element == 0 veut dire « illimité »
 *   - sur une liste vide, delete_* ne plante pas et ne change rien
 *
 * Tous les FlowEntry sont alloués sur le tas (calloc), car delete_* les free.
 */
#include "../test_common.h"
#include "dchained_list.h"

/* ───────────── outils ───────────── */
static FlowEntry *E(void) { return (FlowEntry *)calloc(1, sizeof(FlowEntry)); }

/* libère la liste en la parcourant (sauf si le test est déjà rouge : la liste serait peut-être corrompue) */
static void free_all(DChainedList *d) {
    if (tc_fails) return;                  /* un CHECK a déjà échoué : la liste est sans doute abîmée, on ne la parcourt pas */
    FlowEntry *e = d->head;
    int garde = 0;
    while (e && garde++ < 100000) { FlowEntry *n = e->lru_next; free(e); e = n; }
    free(d);
}

static char g_msg[160];

/* NULL si la liste est exactement [exp[0] .. exp[n-1]], sinon une phrase qui dit ce qui cloche */
static const char *list_problem(DChainedList *d, FlowEntry **exp, int n) {
    if ((int)d->n_elements != n) {
        snprintf(g_msg, sizeof g_msg, "n_elements = %u au lieu de %d", d->n_elements, n);
        return g_msg;
    }
    if (n == 0) {
        if (d->head != NULL || d->tail != NULL) {
            snprintf(g_msg, sizeof g_msg, "liste vide mais head=%p tail=%p (attendu NULL, NULL)", (void *)d->head, (void *)d->tail);
            return g_msg;
        }
        return NULL;
    }
    if (d->head != exp[0])     { snprintf(g_msg, sizeof g_msg, "head n'est pas le bon maillon");  return g_msg; }
    if (d->tail != exp[n - 1]) { snprintf(g_msg, sizeof g_msg, "tail n'est pas le bon maillon");  return g_msg; }
    if (d->head->lru_prev != NULL) { snprintf(g_msg, sizeof g_msg, "head->lru_prev devrait être NULL"); return g_msg; }
    if (d->tail->lru_next != NULL) { snprintf(g_msg, sizeof g_msg, "tail->lru_next devrait être NULL"); return g_msg; }
    FlowEntry *e = d->head;
    for (int i = 0; i < n; i++) {
        if (e != exp[i]) { snprintf(g_msg, sizeof g_msg, "sens head→tail : le maillon %d est faux (lru_next mal chaîné)", i); return g_msg; }
        e = e->lru_next;
    }
    e = d->tail;
    for (int i = n - 1; i >= 0; i--) {
        if (e != exp[i]) { snprintf(g_msg, sizeof g_msg, "sens tail→head : le maillon %d est faux (lru_prev mal chaîné)", i); return g_msg; }
        e = e->lru_prev;
    }
    return NULL;
}

#define CHECK_LIST_N(d, exp, n, msg) do {                                            \
        const char *p_ = list_problem((d), (exp), (n));                              \
        tc_checks++;                                                                 \
        if (p_) { tc_fails++; printf("      ✗ %s : %s  (ligne %d)\n", (msg), p_, __LINE__); } \
    } while (0)

/* LIST(d, "message", a, b, c) : la liste doit être exactement a, b, c (de head à tail) */
#define LIST(d, msg, ...) do {                                                       \
        FlowEntry *ex_[] = {__VA_ARGS__};                                            \
        CHECK_LIST_N((d), ex_, (int)(sizeof ex_ / sizeof ex_[0]), (msg));            \
    } while (0)

#define LIST_EMPTY(d, msg) CHECK_LIST_N((d), NULL, 0, (msg))

/* ───────────── création ───────────── */

static void t_create(void) {
    DChainedList *d = create_dcl(5);
    CHECK(d != NULL, "create_dcl(5) != NULL");
    if (!d) return;
    CHECK_EQ(d->max_element, 5, "max_element == 5");
    LIST_EMPTY(d, "liste neuve vide");
    free(d);

    DChainedList *inf = create_dcl(0);
    CHECK(inf != NULL, "create_dcl(0) != NULL (0 = illimité)");
    if (inf) { CHECK_EQ(inf->max_element, 0, "max_element == 0"); free(inf); }
}

/* ───────────── ajouts ───────────── */

static void t_add_end_liste_vide(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    CHECK_EQ(add_to_end(d, a, 0), 0, "add_to_end sur liste vide → 0");
    LIST(d, "[a]", a);
    CHECK(a->lru_prev == NULL && a->lru_next == NULL, "a->lru_prev et lru_next == NULL");
    free_all(d);
}

static void t_add_top_liste_vide(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    CHECK_EQ(add_to_top(d, a, 0), 0, "add_to_top sur liste vide → 0");
    LIST(d, "[a]", a);
    free_all(d);
}

static void t_add_end_trois(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E(), *b = E(), *c = E();
    CHECK_EQ(add_to_end(d, a, 0), 0, "add a");
    CHECK_EQ(add_to_end(d, b, 0), 0, "add b");
    LIST(d, "[a, b]", a, b);
    CHECK_EQ(add_to_end(d, c, 0), 0, "add c");
    LIST(d, "[a, b, c]", a, b, c);
    free_all(d);
}

static void t_add_top_trois(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E(), *b = E(), *c = E();
    add_to_top(d, a, 0);
    add_to_top(d, b, 0);
    LIST(d, "[b, a]", b, a);
    add_to_top(d, c, 0);
    LIST(d, "[c, b, a]", c, b, a);
    free_all(d);
}

static void t_add_melanges(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E(), *b = E(), *c = E(), *x = E();
    add_to_end(d, a, 0);
    add_to_top(d, b, 0);
    add_to_end(d, c, 0);
    add_to_top(d, x, 0);
    LIST(d, "[x, b, a, c]", x, b, a, c);
    free_all(d);
}

static void t_illimite_1000(void) {
    DChainedList *d = create_dcl(0);
    for (int i = 0; i < 1000; i++) CHECK_EQ(add_to_end(d, E(), 0), 0, "add_to_end sans limite → 0");
    CHECK_EQ(d->n_elements, 1000, "n_elements == 1000");
    int n = 0;
    for (FlowEntry *e = d->head; e && n < 5000; e = e->lru_next) n++;
    CHECK_EQ(n, 1000, "le parcours head→tail voit 1000 maillons");
    n = 0;
    for (FlowEntry *e = d->tail; e && n < 5000; e = e->lru_prev) n++;
    CHECK_EQ(n, 1000, "le parcours tail→head voit 1000 maillons");
    free_all(d);
}

/* ───────────── arguments invalides ───────────── */

static void t_args_nuls_ajout_fin(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    CHECK_EQ(add_to_end(NULL, a, 0), -1, "add_to_end(dcl NULL) → -1");
    CHECK_EQ(add_to_end(d, NULL, 0), -1, "add_to_end(entry NULL) → -1");
    LIST_EMPTY(d, "la liste n'a pas bougé");
    free(a);
    free_all(d);
}

static void t_args_nuls_ajout_debut(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    CHECK_EQ(add_to_top(NULL, a, 0), -1, "add_to_top(dcl NULL) → -1");
    CHECK_EQ(add_to_top(d, NULL, 0), -1, "add_to_top(entry NULL) → -1");
    LIST_EMPTY(d, "la liste n'a pas bougé");
    free(a);
    free_all(d);
}

static void t_args_nuls_autres(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    add_to_end(d, a, 0);
    CHECK_EQ(move_to_top(NULL, a), -1, "move_to_top(dcl NULL) → -1");
    CHECK_EQ(move_to_top(d, NULL), -1, "move_to_top(entry NULL) → -1");
    CHECK_EQ(move_to_end(NULL, a), -1, "move_to_end(dcl NULL) → -1");
    CHECK_EQ(move_to_end(d, NULL), -1, "move_to_end(entry NULL) → -1");
    CHECK_EQ(delete_from_top(NULL), -1, "delete_from_top(NULL) → -1");
    CHECK_EQ(delete_from_end(NULL), -1, "delete_from_end(NULL) → -1");
    LIST(d, "la liste n'a pas bougé", a);
    free_all(d);
}

/* ───────────── capacité maximale ───────────── */

static void t_plein_sans_suppression(void) {
    DChainedList *d = create_dcl(3);
    FlowEntry *a = E(), *b = E(), *c = E(), *x = E(), *y = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0);
    CHECK_EQ(add_to_end(d, x, 0), -1, "liste pleine, del=0 : add_to_end → -1");
    CHECK_EQ(add_to_top(d, y, 0), -1, "liste pleine, del=0 : add_to_top → -1");
    LIST(d, "la liste n'a pas bougé", a, b, c);
    free(x); free(y);
    free_all(d);
}

static void t_plein_add_end_supprime_le_premier(void) {
    DChainedList *d = create_dcl(3);
    FlowEntry *a = E(), *b = E(), *c = E(), *x = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0);
    CHECK_EQ(add_to_end(d, x, 1), 0, "liste pleine, del=1 : add_to_end → 0");
    LIST(d, "[b, c, x] : le plus ancien (a) est parti", b, c, x);   /* a est free par la liste */
    free_all(d);
}

static void t_plein_add_top_supprime_le_dernier(void) {
    DChainedList *d = create_dcl(3);
    FlowEntry *a = E(), *b = E(), *c = E(), *x = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0);
    CHECK_EQ(add_to_top(d, x, 1), 0, "liste pleine, del=1 : add_to_top → 0");
    LIST(d, "[x, a, b] : le dernier (c) est parti", x, a, b);       /* c est free par la liste */
    free_all(d);
}

static void t_capacite_un(void) {
    DChainedList *d = create_dcl(1);
    FlowEntry *a = E(), *b = E();
    CHECK_EQ(add_to_end(d, a, 0), 0, "1er élément accepté");
    CHECK_EQ(add_to_end(d, b, 0), -1, "2e refusé (del=0)");
    LIST(d, "[a]", a);
    CHECK_EQ(add_to_end(d, b, 1), 0, "2e accepté avec del=1");
    LIST(d, "[b] : a est parti", b);
    free_all(d);
}

/* ───────────── suppressions ───────────── */

static void t_delete_from_top(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E(), *b = E(), *c = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0);
    CHECK_EQ(delete_from_top(d), 0, "1re suppression → 0");
    LIST(d, "[b, c]", b, c);
    CHECK_EQ(delete_from_top(d), 0, "2e suppression → 0");
    LIST(d, "[c]", c);
    CHECK_EQ(delete_from_top(d), 0, "3e suppression → 0");
    LIST_EMPTY(d, "liste vide : head, tail NULL et n_elements 0");
    free(d);
}

static void t_delete_from_end(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E(), *b = E(), *c = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0);
    CHECK_EQ(delete_from_end(d), 0, "1re suppression → 0");
    LIST(d, "[a, b]", a, b);
    CHECK_EQ(delete_from_end(d), 0, "2e suppression → 0");
    LIST(d, "[a]", a);
    CHECK_EQ(delete_from_end(d), 0, "3e suppression → 0");
    LIST_EMPTY(d, "liste vide : head, tail NULL et n_elements 0");
    free(d);
}

static void t_delete_sur_liste_vide(void) {
    DChainedList *d = create_dcl(0);
    (void)delete_from_top(d);
    LIST_EMPTY(d, "après delete_from_top sur liste vide");
    (void)delete_from_end(d);
    LIST_EMPTY(d, "après delete_from_end sur liste vide");
    free(d);
}

static void t_reutilisable_apres_vidage(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    add_to_end(d, a, 0);
    delete_from_top(d);                    /* a est free, la liste est vide */
    FlowEntry *x = E(), *y = E();
    CHECK_EQ(add_to_end(d, x, 0), 0, "ajout après vidage → 0");
    CHECK_EQ(add_to_top(d, y, 0), 0, "ajout en tête après vidage → 0");
    LIST(d, "[y, x]", y, x);
    free_all(d);
}

/* ───────────── déplacements ───────────── */

#define LISTE_ABCD()                                                                 \
    DChainedList *d = create_dcl(0);                                                 \
    FlowEntry *a = E(), *b = E(), *c = E(), *x = E();                                \
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0); add_to_end(d, x, 0)

static void t_move_to_top_milieu(void) {
    LISTE_ABCD();                          /* [a, b, c, x], x joue le rôle de « d » */
    CHECK_EQ(move_to_top(d, b), 0, "move_to_top(b) → 0");
    LIST(d, "[b, a, c, x]", b, a, c, x);
    CHECK_EQ(move_to_top(d, c), 0, "move_to_top(c) → 0");
    LIST(d, "[c, b, a, x]", c, b, a, x);
    free_all(d);
}

static void t_move_to_top_dernier(void) {
    LISTE_ABCD();
    CHECK_EQ(move_to_top(d, x), 0, "move_to_top(dernier) → 0");
    LIST(d, "[x, a, b, c]", x, a, b, c);
    free_all(d);
}

static void t_move_to_top_deja_premier(void) {
    LISTE_ABCD();
    CHECK_EQ(move_to_top(d, a), 0, "move_to_top(premier) → 0");
    LIST(d, "rien ne change", a, b, c, x);
    free_all(d);
}

static void t_move_to_end_milieu(void) {
    LISTE_ABCD();
    CHECK_EQ(move_to_end(d, b), 0, "move_to_end(b) → 0");
    LIST(d, "[a, c, x, b]", a, c, x, b);
    CHECK_EQ(move_to_end(d, c), 0, "move_to_end(c) → 0");
    LIST(d, "[a, x, b, c]", a, x, b, c);
    free_all(d);
}

static void t_move_to_end_premier(void) {
    LISTE_ABCD();
    CHECK_EQ(move_to_end(d, a), 0, "move_to_end(premier) → 0");
    LIST(d, "[b, c, x, a]", b, c, x, a);
    free_all(d);
}

static void t_move_to_end_deja_dernier(void) {
    LISTE_ABCD();
    CHECK_EQ(move_to_end(d, x), 0, "move_to_end(dernier) → 0");
    LIST(d, "rien ne change", a, b, c, x);
    free_all(d);
}

static void t_move_un_seul_element(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E();
    add_to_end(d, a, 0);
    CHECK_EQ(move_to_top(d, a), 0, "move_to_top sur liste de 1 → 0");
    LIST(d, "[a]", a);
    CHECK_EQ(move_to_end(d, a), 0, "move_to_end sur liste de 1 → 0");
    LIST(d, "[a]", a);
    free_all(d);
}

static void t_move_deux_elements(void) {
    DChainedList *d = create_dcl(0);
    FlowEntry *a = E(), *b = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0);
    move_to_end(d, a);
    LIST(d, "[b, a]", b, a);
    move_to_end(d, b);
    LIST(d, "[a, b]", a, b);
    move_to_top(d, b);
    LIST(d, "[b, a]", b, a);
    move_to_top(d, a);
    LIST(d, "[a, b]", a, b);
    free_all(d);
}

/* ───────────── scénario LRU réel ───────────── */

static void t_scenario_lru(void) {
    /* capacité 3 ; on « touche » un flux = move_to_end ; la tête est toujours le plus ancien */
    DChainedList *d = create_dcl(3);
    FlowEntry *a = E(), *b = E(), *c = E(), *x = E();
    add_to_end(d, a, 0); add_to_end(d, b, 0); add_to_end(d, c, 0);
    move_to_end(d, a);
    LIST(d, "a touché → [b, c, a]", b, c, a);
    CHECK_EQ(add_to_end(d, x, 1), 0, "nouveau flux, liste pleine → évince b");
    LIST(d, "[c, a, x]", c, a, x);
    move_to_end(d, c);
    LIST(d, "c touché → [a, x, c]", a, x, c);
    delete_from_top(d);
    LIST(d, "éviction du plus ancien → [x, c]", x, c);
    free_all(d);
}

/* ───────────── test aléatoire contre un modèle ───────────── */

static void t_operations_aleatoires(void) {
    /* 3000 opérations tirées au hasard (suite fixe), comparées à un tableau « modèle ».
       On s'arrête à la première divergence. */
    DChainedList *d = create_dcl(0);
    FlowEntry *model[64];
    int m = 0;
    uint32_t seed = 12345;
    for (int step = 0; step < 3000; step++) {
        seed = seed * 1103515245u + 12345u;
        int op = (int)((seed >> 16) % 5);
        int idx = m ? (int)((seed >> 8) % (uint32_t)m) : 0;
        const char *nom = NULL;
        if (op == 0 && m < 40) {
            FlowEntry *e = E(); add_to_end(d, e, 0); model[m++] = e; nom = "add_to_end";
        } else if (op == 1 && m < 40) {
            FlowEntry *e = E(); add_to_top(d, e, 0);
            memmove(model + 1, model, (size_t)m * sizeof *model); model[0] = e; m++; nom = "add_to_top";
        } else if (op == 2 && m > 0) {
            FlowEntry *e = model[idx]; move_to_end(d, e);
            memmove(model + idx, model + idx + 1, (size_t)(m - idx - 1) * sizeof *model); model[m - 1] = e; nom = "move_to_end";
        } else if (op == 3 && m > 0) {
            FlowEntry *e = model[idx]; move_to_top(d, e);
            memmove(model + 1, model, (size_t)idx * sizeof *model); model[0] = e; nom = "move_to_top";
        } else if (op == 4 && m > 0) {
            if (seed & 0x100) { delete_from_top(d); memmove(model, model + 1, (size_t)(m - 1) * sizeof *model); m--; nom = "delete_from_top"; }
            else              { delete_from_end(d); m--; nom = "delete_from_end"; }
        } else continue;

        const char *p = list_problem(d, model, m);
        tc_checks++;
        if (p) {
            tc_fails++;
            printf("      ✗ divergence à l'opération n°%d (%s, indice %d, taille %d) : %s\n", step, nom, idx, m, p);
            return;                        /* liste abîmée : on ne la libère pas */
        }
    }
    CHECK(1, "3000 opérations sans divergence");
    for (int i = 0; i < m; i++) free(model[i]);
    free(d);
}

int main(int argc, char **argv) {
    tc_begin("test_dchained_list.c — dchained_list", argc, argv);

    RUN("create_dcl",                                       t_create);

    RUN("add_to_end : liste vide",                          t_add_end_liste_vide);
    RUN("add_to_top : liste vide",                          t_add_top_liste_vide);
    RUN("add_to_end : trois éléments",                      t_add_end_trois);
    RUN("add_to_top : trois éléments",                      t_add_top_trois);
    RUN("add_to_end et add_to_top mélangés",                t_add_melanges);
    RUN("max_element == 0 : 1000 éléments sans limite",     t_illimite_1000);

    RUN("add_to_end : arguments NULL",                      t_args_nuls_ajout_fin);
    RUN("add_to_top : arguments NULL",                      t_args_nuls_ajout_debut);
    RUN("move_* et delete_* : arguments NULL",              t_args_nuls_autres);

    RUN("liste pleine, del=0 : refus",                      t_plein_sans_suppression);
    RUN("liste pleine, add_to_end del=1 : le premier part", t_plein_add_end_supprime_le_premier);
    RUN("liste pleine, add_to_top del=1 : le dernier part", t_plein_add_top_supprime_le_dernier);
    RUN("capacité 1",                                       t_capacite_un);

    RUN("delete_from_top : 3 éléments jusqu'au vide",       t_delete_from_top);
    RUN("delete_from_end : 3 éléments jusqu'au vide",       t_delete_from_end);
    RUN("delete_* sur liste vide : ne plante pas",          t_delete_sur_liste_vide);
    RUN("liste réutilisable après vidage complet",          t_reutilisable_apres_vidage);

    RUN("move_to_top : élément du milieu",                  t_move_to_top_milieu);
    RUN("move_to_top : le dernier",                         t_move_to_top_dernier);
    RUN("move_to_top : déjà premier",                       t_move_to_top_deja_premier);
    RUN("move_to_end : élément du milieu",                  t_move_to_end_milieu);
    RUN("move_to_end : le premier",                         t_move_to_end_premier);
    RUN("move_to_end : déjà dernier",                       t_move_to_end_deja_dernier);
    RUN("move_* sur une liste d'un seul élément",           t_move_un_seul_element);
    RUN("move_* sur une liste de deux éléments",            t_move_deux_elements);

    RUN("scénario LRU (capacité 3)",                        t_scenario_lru);
    RUN("3000 opérations aléatoires contre un modèle",      t_operations_aleatoires);

    return tc_end();
}
