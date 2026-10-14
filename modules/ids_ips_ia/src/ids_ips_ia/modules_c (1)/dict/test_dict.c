#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dict.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(int cond, const char *msg) {
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; }
    else      { printf("  [FAIL] %s\n", msg); g_fail++; }
}

static void section(const char *name) {
    printf("\n=====================================================\n");
    printf("TEST : %s\n", name);
    printf("=====================================================\n");
}

/* Helpers pour create_dict_raw */
static int int_hash_raw(const void *key) {
    int v = *(const int *)key;
    return (int)((v * 2654435761u) & 0x7FFFFFFF);
}
static int int_compare_raw(const void *a, const void *b) {
    int va = *(const int *)a;
    int vb = *(const int *)b;
    return (va > vb) - (va < vb);
}

int main(void) {

    /* ------------------------------------------------------------
     * TEST 1 : create_dict_str — cas nominal
     * ------------------------------------------------------------ */
    section("1. create_dict_str — cas nominal");
    {
        Dict *d = create_dict_str(16);
        check(d != NULL,                    "dict != NULL");
        check(d->size == 16,                "size == 16");
        check(d->nbr_elements == 0,         "nbr_elements == 0");
        check(d->nbr_fields == 0,           "nbr_fields == 0");
        check(d->key_dup != NULL,           "key_dup défini");
        check(d->key_free != NULL,          "key_free défini");
        check(d->value_dup == NULL,         "value_dup == NULL");
        check(d->value_free == NULL,        "value_free == NULL");
        check(d->ptr != NULL,               "ptr != NULL");
        int all_null = 1;
        for (uint32_t i = 0; i < d->size; i++) {
            if (d->ptr[i] != NULL) { all_null = 0; break; }
        }
        check(all_null,                     "tous les buckets == NULL");
        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 2 : create_dict — erreurs
     * ------------------------------------------------------------ */
    section("2. create_dict — erreurs");
    {
        Dict *d1 = create_dict(16, NULL, NULL, NULL, NULL, NULL, NULL);
        check(d1 == NULL,                   "hash == NULL → NULL");

        Dict *d2 = create_dict(0, int_hash_raw, int_compare_raw, NULL, NULL, NULL, NULL);
        check(d2 == NULL,                   "size == 0 → NULL");
    }

    /* ------------------------------------------------------------
     * TEST 3 : setitem/getitem — 1 clé
     * ------------------------------------------------------------ */
    section("3. setitem/getitem — 1 clé");
    {
        Dict *d = create_dict_str(16);

        int v1 = 42;
        int r = dict_setitem(d, "tcp", &v1);
        check(r == 0,                       "setitem retourne 0");
        check(d->nbr_elements == 1,         "nbr_elements == 1");

        int *got = (int *)dict_getitem(d, "tcp");
        check(got == &v1,                   "getitem retourne le même pointeur");
        check(got != NULL && *got == 42,    "*got == 42");

        check(dict_getitem(d, "udp") == NULL, "clé absente → NULL");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 4 : la clé est bien COPIÉE
     * ------------------------------------------------------------ */
    section("4. la clé est copiée (indépendance)");
    {
        Dict *d = create_dict_str(16);

        int v = 42;
        char buf[16];
        snprintf(buf, 16, "tcp");
        dict_setitem(d, buf, &v);
        buf[0] = 'X';

        check(dict_getitem(d, "tcp") == &v,   "clé copiée : 'tcp' trouvée");
        check(dict_getitem(d, "Xcp") == NULL, "modification de buf n'affecte pas le dict");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 5 : plusieurs clés
     * ------------------------------------------------------------ */
    section("5. setitem/getitem — plusieurs clés");
    {
        Dict *d = create_dict_str(16);

        int v_tcp = 6, v_udp = 17, v_icmp = 1;
        dict_setitem(d, "tcp",  &v_tcp);
        dict_setitem(d, "udp",  &v_udp);
        dict_setitem(d, "icmp", &v_icmp);

        check(d->nbr_elements == 3,         "nbr_elements == 3");
        check(*(int *)dict_getitem(d, "tcp")  == 6,  "tcp  == 6");
        check(*(int *)dict_getitem(d, "udp")  == 17, "udp  == 17");
        check(*(int *)dict_getitem(d, "icmp") == 1,  "icmp == 1");
        check(dict_getitem(d, "xyz") == NULL,        "xyz  → NULL");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 6 : remplacement
     * ------------------------------------------------------------ */
    section("6. setitem — remplacement");
    {
        Dict *d = create_dict_str(16);

        int v1 = 1, v2 = 2;
        dict_setitem(d, "x", &v1);
        check(*(int *)dict_getitem(d, "x") == 1,  "x == 1 (avant)");
        check(d->nbr_elements == 1,               "nbr_elements == 1");

        dict_setitem(d, "x", &v2);
        check(*(int *)dict_getitem(d, "x") == 2,  "x == 2 (après remplacement)");
        check(d->nbr_elements == 1,               "nbr_elements reste 1");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 7 : collisions (bucket size = 1)
     * ------------------------------------------------------------ */
    section("7. collisions (bucket size = 1)");
    {
        Dict *d = create_dict_str(1);

        int v_a = 10, v_b = 20, v_c = 30;
        dict_setitem(d, "a", &v_a);
        dict_setitem(d, "b", &v_b);
        dict_setitem(d, "c", &v_c);

        check(d->nbr_elements == 3,                 "nbr_elements == 3");
        check(*(int *)dict_getitem(d, "a") == 10,   "a == 10");
        check(*(int *)dict_getitem(d, "b") == 20,   "b == 20");
        check(*(int *)dict_getitem(d, "c") == 30,   "c == 30");
        check(dict_getitem(d, "z") == NULL,         "z → NULL");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 8 : setitem — arguments invalides
     * ------------------------------------------------------------ */
    section("8. setitem — erreurs");
    {
        Dict *d = create_dict_str(16);
        int v = 1;

        check(dict_setitem(NULL, "k", &v) == -1,    "dict NULL → -1");
        check(dict_setitem(d, NULL, &v)  == -1,     "key NULL → -1");
        check(dict_setitem(d, "k", NULL) == -1,     "value NULL → -1");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 9 : getitem — arguments invalides
     * ------------------------------------------------------------ */
    section("9. getitem — erreurs");
    {
        Dict *d = create_dict_str(16);

        check(dict_getitem(NULL, "k") == NULL,      "dict NULL → NULL");
        check(dict_getitem(d, NULL)   == NULL,      "key NULL → NULL");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 10 : stress — 100 clés
     * ------------------------------------------------------------ */
    section("10. stress — 100 clés");
    {
        Dict *d = create_dict_str(16);

        int *vals = (int *)malloc(100 * sizeof(int));
        char buf[16];

        for (int i = 0; i < 100; i++) {
            vals[i] = i * 10;
            snprintf(buf, 16, "key_%d", i);
            dict_setitem(d, buf, &vals[i]);
        }

        check(d->nbr_elements == 100,               "nbr_elements == 100");

        int ok = 1;
        for (int i = 0; i < 100; i++) {
            snprintf(buf, 16, "key_%d", i);
            int *got = (int *)dict_getitem(d, buf);
            if (got == NULL || *got != i * 10) { ok = 0; break; }
        }
        check(ok,                                    "toutes les valeurs retrouvées");

        free(vals);
        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 11 : value_free — le dict libère les values
     * ------------------------------------------------------------ */
    section("11. dict_clear — value_free");
    {
        /* On doit utiliser create_dict complet car on veut value_free = free.
         * MAIS on a besoin des helpers str_* qui sont statiques dans dict.c.
         * Solution : exposer dict_str_hash, dict_str_compare, dict_str_dup,
         * dict_str_free dans dict.h. Voir plus bas.
         *
         * En attendant, on utilise create_dict_str et on free manuellement
         * les values AVANT dict_clear. */
        Dict *d = create_dict_str(16);

        for (int i = 0; i < 5; i++) {
            int *v = (int *)malloc(sizeof(int));
            *v = i;
            char buf[8];
            snprintf(buf, 8, "k%d", i);
            dict_setitem(d, buf, v);
        }

        /* libérer les values à la main */
        for (int i = 0; i < 5; i++) {
            char buf[8];
            snprintf(buf, 8, "k%d", i);
            int *v = (int *)dict_getitem(d, buf);
            free(v);
        }

        dict_clear(d);
        check(1, "pas de crash");
    }

    /* ------------------------------------------------------------
     * TEST 12 : value_dup — value copiée
     * ------------------------------------------------------------ */
    section("12. value_dup — via create_dict complet");
    {
        /* Idem : on ne peut pas passer int_dup (statique).
         * On teste que create_dict accepte bien value_dup != NULL. */
        Dict *d = create_dict(16,
                              int_hash_raw, int_compare_raw,
                              NULL, NULL,       /* pas de key_dup/free */
                              NULL, NULL);      /* pas de value_dup/free */
        check(d != NULL,                       "create_dict avec value_dup=NULL");
        check(d->value_dup == NULL,            "value_dup == NULL");
        check(d->value_free == NULL,           "value_free == NULL");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 13 : dict_clear(NULL)
     * ------------------------------------------------------------ */
    section("13. dict_clear — cas NULL");
    {
        dict_clear(NULL);
        check(1, "dict_clear(NULL) ne crash pas");
    }

    /* ------------------------------------------------------------
     * TEST 14 : clés de type int
     * ------------------------------------------------------------ */
    section("14. clés de type int");
    {
        Dict *d = create_dict_int(16);

        int k1 = 42, k2 = 100, k3 = -7;
        int v1 = 111, v2 = 222, v3 = 333;

        dict_setitem(d, &k1, &v1);
        dict_setitem(d, &k2, &v2);
        dict_setitem(d, &k3, &v3);

        check(d->nbr_elements == 3,                 "nbr_elements == 3");
        check(*(int *)dict_getitem(d, &k1) == 111,  "k1 → 111");
        check(*(int *)dict_getitem(d, &k2) == 222,  "k2 → 222");
        check(*(int *)dict_getitem(d, &k3) == 333,  "k3 → 333");

        int k_miss = 999;
        check(dict_getitem(d, &k_miss) == NULL,     "clé absente → NULL");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 15 : key_dup = NULL (mode raw)
     * ------------------------------------------------------------ */
    section("15. create_dict_raw — pas de copie");
    {
        Dict *d = create_dict_raw(16, int_hash_raw, int_compare_raw);

        int k = 42;
        int v = 6;
        dict_setitem(d, &k, &v);

        check(dict_getitem(d, &k) == &v, "clé trouvée (pas de copie)");

        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 16 : rehash se déclenche
     * ------------------------------------------------------------
     * On crée un dict de taille 4 (load factor = 0.75 → rehash à 3 entrées).
     * Après 10 insertions, size doit avoir grandi.
     */
    section("16. rehash — size augmente");
    {
        Dict *d = create_dict_str(4);
        uint32_t initial_size = d->size;
        check(initial_size == 4,                    "size initial == 4");

        char buf[16];
        for (int i = 0; i < 10; i++) {
            snprintf(buf, 16, "k%d", i);
            int *v = (int *)malloc(sizeof(int));
            *v = i;
            dict_setitem(d, buf, v);
        }

        check(d->size > initial_size,               "size a augmenté après rehash");
        check(d->nbr_elements == 10,                "nbr_elements == 10");

        /* Vérifier que toutes les clés sont retrouvables */
        int ok = 1;
        for (int i = 0; i < 10; i++) {
            snprintf(buf, 16, "k%d", i);
            int *got = (int *)dict_getitem(d, buf);
            if (got == NULL || *got != i) { ok = 0; break; }
        }
        check(ok, "toutes les clés retrouvées après rehash");

        /* libérer les values */
        for (int i = 0; i < 10; i++) {
            snprintf(buf, 16, "k%d", i);
            int *got = (int *)dict_getitem(d, buf);
            free(got);
        }
        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 17 : stress rehash — 500 clés dans un dict de 4
     * ------------------------------------------------------------ */
    section("17. stress rehash — 500 clés, size initial = 4");
    {
        Dict *d = create_dict_str(4);

        int *vals = (int *)malloc(500 * sizeof(int));
        char buf[16];

        for (int i = 0; i < 500; i++) {
            vals[i] = i;
            snprintf(buf, 16, "k%d", i);
            dict_setitem(d, buf, &vals[i]);
        }

        check(d->nbr_elements == 500,               "nbr_elements == 500");
        check(d->size >= 500,                       "size >= 500 (rehash multiples)");

        int ok = 1;
        for (int i = 0; i < 500; i++) {
            snprintf(buf, 16, "k%d", i);
            int *got = (int *)dict_getitem(d, buf);
            if (got == NULL || *got != i) { ok = 0; break; }
        }
        check(ok, "toutes les valeurs retrouvées après plusieurs rehash");

        free(vals);
        dict_clear(d);
    }

    /* ------------------------------------------------------------
     * TEST 18 : les valeurs survivent au rehash
     * ------------------------------------------------------------ */
    section("18. rehash préserve les valeurs");
    {
        Dict *d = create_dict_str(2);

        int v1 = 100, v2 = 200, v3 = 300;
        dict_setitem(d, "a", &v1);
        dict_setitem(d, "b", &v2);
        dict_setitem(d, "c", &v3);   /* rehash probable ici */

        check(dict_getitem(d, "a") == &v1, "a → &v1");
        check(dict_getitem(d, "b") == &v2, "b → &v2");
        check(dict_getitem(d, "c") == &v3, "c → &v3");
        check(*(int *)dict_getitem(d, "a") == 100, "a == 100");
        check(*(int *)dict_getitem(d, "b") == 200, "b == 200");
        check(*(int *)dict_getitem(d, "c") == 300, "c == 300");

        dict_clear(d);
    }

    section("26. dict_delitem");
    {
        Dict *d = create_dict_str(16);
        int a = 1, b = 2, c = 3;
        dict_setitem(d, "a", &a);
        dict_setitem(d, "b", &b);
        dict_setitem(d, "c", &c);
        check(d->nbr_elements == 3, "3 éléments");

        check(dict_delitem(d, "b") == 0,    "delitem b → 0");
        check(d->nbr_elements == 2,         "nbr_elements == 2");
        check(dict_getitem(d, "b") == NULL, "b absent");
        check(dict_getitem(d, "a") == &a,   "a toujours là");
        check(dict_getitem(d, "c") == &c,   "c toujours là");

        check(dict_delitem(d, "zzz") == -1, "clé absente → -1");

        /* suppression en tête de bucket (avec collision) */
        Dict *d2 = create_dict_str(1);
        int x = 10, y = 20, z = 30;
        dict_setitem(d2, "x", &x);
        dict_setitem(d2, "y", &y);
        dict_setitem(d2, "z", &z);
        check(dict_delitem(d2, "z") == 0,   "delitem z (tête) → 0");
        check(dict_getitem(d2, "x") == &x,  "x toujours là");
        check(dict_getitem(d2, "y") == &y,  "y toujours là");
        dict_clear(d2);

        dict_clear(d);
    }


    /* ============================================================
     * RESUME
     * ============================================================ */
    printf("\n=====================================================\n");
    printf("RESUME\n");
    printf("=====================================================\n");
    int total = g_pass + g_fail;
    printf("  Total checks : %d\n", total);
    printf("  PASS         : %d\n", g_pass);
    printf("  FAIL         : %d\n", g_fail);
    printf("  Taux         : %.1f%%\n", total ? (100.0 * g_pass / total) : 0.0);
    printf("=====================================================\n");
    return g_fail == 0 ? 0 : 1;
}