
## Exemples d'usage

### Exemple 1 — Le plus simple : compter des mots

```c
#include "dict.h"
#include <stdio.h>

int main(void) {
    Dict *mots = create_dict_str(16);

    /* Compter les occurrences */
    const char *phrase[] = {"le", "chat", "le", "chien", "le", "chat"};
    int counts[3] = {0, 0, 0};   /* valeurs stockées */

    for (int i = 0; i < 6; i++) {
        int *c = (int *)dict_getitem(mots, phrase[i]);
        if (c != NULL) {
            (*c)++;
        } else {
            counts[i % 3] = 1;
            dict_setitem(mots, phrase[i], &counts[i % 3]);
        }
    }

    /* Afficher les résultats */
    const char *cles[] = {"le", "chat", "chien"};
    for (int i = 0; i < 3; i++) {
        int *c = (int *)dict_getitem(mots, cles[i]);
        if (c != NULL) printf("%s : %d\n", cles[i], *c);
    }

    dict_clear(mots);
    return 0;
}
/* Sortie :
 * le : 3
 * chat : 2
 * chien : 1
 */
```

### Exemple 2 — Config clé/valeur (chaînes → chaînes)

```c
#include "dict.h"
#include <stdio.h>

int main(void) {
    Dict *config = create_dict_str(16);

    char *host = "localhost";
    char *port = "8080";
    char *user = "admin";

    dict_setitem(config, "host", host);
    dict_setitem(config, "port", port);
    dict_setitem(config, "user", user);

    printf("host = %s\n", (char *)dict_getitem(config, "host"));
    printf("port = %s\n", (char *)dict_getitem(config, "port"));
    printf("user = %s\n", (char *)dict_getitem(config, "user"));

    /* clé absente */
    char *val = (char *)dict_getitem(config, "password");
    if (val == NULL) {
        printf("password non défini\n");
    }

    dict_clear(config);
    return 0;
}
```

### Exemple 3 — Parser réseau : mapper nom de protocole → numéro

```c
#include "dict.h"
#include <stdio.h>

int main(void) {
    Dict *protos = create_dict_str(8);

    int tcp = 6, udp = 17, icmp = 1;
    dict_setitem(protos, "tcp",  &tcp);
    dict_setitem(protos, "udp",  &udp);
    dict_setitem(protos, "icmp", &icmp);

    const char *nom = "tcp";
    int *num = (int *)dict_getitem(protos, nom);
    if (num != NULL) {
        printf("protocole %s = %d\n", nom, *num);
    } else {
        printf("protocole inconnu : %s\n", nom);
    }

    dict_clear(protos);
    return 0;
}
/* Sortie : protocole tcp = 6 */
```

### Exemple 4 — Clés int : mapper ID → nom

```c
#include "dict.h"
#include <stdio.h>

int main(void) {
    Dict *users = create_dict_int(16);

    int id_alice = 1001, id_bob = 1002;
    char *nom_alice = "Alice";
    char *nom_bob = "Bob";

    dict_setitem(users, &id_alice, nom_alice);
    dict_setitem(users, &id_bob, nom_bob);

    int recherche = 1001;
    char *nom = (char *)dict_getitem(users, &recherche);
    if (nom != NULL) {
        printf("id %d = %s\n", recherche, nom);
    }

    dict_clear(users);
    return 0;
}
```

### Exemple 5 — Compteur avec value allouée (malloc) + value_free

Pour ça il faut **exposer les helpers** dans `dict.h`. Voici ce qu'il faut ajouter :

```c
/* dict.h — ajouter ces déclarations */
int   dict_str_hash(const void *key);
int   dict_str_compare(const void *a, const void *b);
void *dict_str_dup(const void *key);
void  dict_str_free(void *key);
int   dict_int_hash(const void *key);
int   dict_int_compare(const void *a, const void *b);
void *dict_int_dup(const void *key);
void  dict_int_free(void *key);
```

Et dans `dict.c`, **retirer le `static`** de ces fonctions.

Ensuite :

```c
#include "dict.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* value_dup = dict_int_dup, value_free = dict_int_free */
    Dict *compteurs = create_dict(16,
                                  dict_str_hash, dict_str_compare,
                                  dict_str_dup, dict_str_free,
                                  dict_int_dup, dict_int_free);

    const char *mots[] = {"a", "b", "a", "c", "b", "a"};

    for (int i = 0; i < 6; i++) {
        int *c = (int *)dict_getitem(compteurs, mots[i]);
        if (c != NULL) {
            (*c)++;
        } else {
            int init = 1;
            dict_setitem(compteurs, mots[i], &init);   /* dict_int_dup copie init */
        }
    }

    const char *cles[] = {"a", "b", "c"};
    for (int i = 0; i < 3; i++) {
        int *c = (int *)dict_getitem(compteurs, cles[i]);
        if (c != NULL) printf("%s : %d\n", cles[i], *c);
    }

    dict_clear(compteurs);   /* libère clés ET values automatiquement */
    return 0;
}
/* Sortie :
 * a : 3
 * b : 2
 * c : 1
 */
```

### Exemple 6 — Vérifier si une clé existe (idiome)

```c
if (dict_getitem(d, "ma_cle") != NULL) {
    /* la clé existe */
} else {
    /* la clé n'existe pas */
}
```

### Exemple 7 — Compter les occurrences avec un `int` sur la pile

```c
#include "dict.h"
#include <stdio.h>

int main(void) {
    Dict *counts = create_dict_str(16);
    int stockage[10];   /* stockage des compteurs sur la pile */
    int idx = 0;

    const char *items[] = {"x", "y", "x", "z", "x"};
    for (int i = 0; i < 5; i++) {
        int *c = (int *)dict_getitem(counts, items[i]);
        if (c == NULL) {
            stockage[idx] = 0;
            dict_setitem(counts, items[i], &stockage[idx]);
            c = (int *)dict_getitem(counts, items[i]);
            idx++;
        }
        (*c)++;
    }

    printf("x : %d\n", *(int *)dict_getitem(counts, "x"));
    printf("y : %d\n", *(int *)dict_getitem(counts, "y"));
    printf("z : %d\n", *(int *)dict_getitem(counts, "z"));

    dict_clear(counts);
    return 0;
}
```

---

## Résumé des fonctions disponibles

| Fonction | Ce qu'elle fait |
|---|---|
| `create_dict_str(size)` | Dict avec clés chaînes (copiées + libérées) |
| `create_dict_int(size)` | Dict avec clés int (copiées + libérées) |
| `create_dict_raw(size, h, c)` | Dict avec clés brutes (pas de copie) |
| `create_dict(size, h, c, kd, kf, vd, vf)` | Contrôle total |
| `dict_setitem(d, key, value)` | Insert ou remplace |
| `dict_getitem(d, key)` | Cherche, retourne `NULL` si absent |
| `dict_clear(d)` | Libère tout (selon les fonctions fournies) |

## Idiome à retenir

**Pour vérifier si une clé existe** :

```c
void *val = dict_getitem(d, key);
if (val != NULL) {
    /* existe */
} else {
    /* n'existe pas */
}
```

**Pour un compteur** :

```c
int *c = (int *)dict_getitem(d, key);
if (c == NULL) {
    int init = 0;
    dict_setitem(d, key, &init);
    c = (int *)dict_getitem(d, key);
}
(*c)++;
```

C'est le pattern **"get or create"** — très utile.

---

## Récapitulatif de la mise à jour

| Test | Ce qui change |
|---|---|
| 1-10 | Inchangés |
| 11 | Test `value_free` (manual free) |
| 12 | Vérifie `create_dict` accepte `value_dup = NULL` |
| 13-15 | Inchangés |
| **16** | **Nouveau** : rehash déclenché |
| **17** | **Nouveau** : stress 500 clés |
| **18** | **Nouveau** : valeurs survivent au rehash |

Compile et lance :

```bash
gcc -Wall -Wextra -O0 -g -o test_dict dict.c test_dict.c && ./test_dict
```

Dis-moi ce qui passe / ce qui casse. Si les tests 16-18 passent, ton rehash est bon. 🎯