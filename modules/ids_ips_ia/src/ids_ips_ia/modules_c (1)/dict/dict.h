#ifndef DICT_H
#define DICT_H
#include <stdint.h>
#include "../utils/utils.h"
#define DICT_LOAD_FACTOR_NUM 3    /* 3/4 = 0.75 */
#define DICT_LOAD_FACTOR_DEN 4

struct Entry{
    const void *key;
    void *value;
    int hash;
    struct Entry *next;
};
typedef struct Entry Entry;

struct Dict{
    uint32_t size;
    Entry **ptr;
    int (*hash)(const void*);
    int (*compare)(const void*, const void*);
    void *(*key_dup)(const void*);       // copie une clé (NULL = pas de copie)
    void  (*key_free)(void*);             // libère une clé (NULL = pas de free)
    void *(*value_dup)(const void*);      // copie une value (NULL = pas de copie)
    void  (*value_free)(void*);           // libère une value (NULL = pas de free)
    uint32_t nbr_elements;
    uint32_t nbr_fields;
};

typedef struct Dict Dict;

/* Création générique (contrôle total) */
Dict *create_dict(
    uint32_t size,
    int (*hash)(const void*),
    int (*compare)(const void*, const void*),
    void *(*key_dup)(const void*),
    void  (*key_free)(void*),
    void *(*value_dup)(const void*),
    void  (*value_free)(void*)
);

/* Wrappers pratiques */
Dict *create_dict_str(uint32_t size);    // clés = chaînes (copiées + libérées)
Dict *create_dict_int(uint32_t size);    // clés = int (copiés + libérés)
Dict *create_dict_raw(uint32_t size, int (*hash)(const void*), int (*compare)(const void*, const void*));   // clés = pointeurs bruts (pas de copie)

int   dict_setitem(Dict *dict, const void *key, void *value);
int   dict_setitem_hash(Dict *dict, const void *key, void *value, int hash);
void * dict_getitem(Dict *dict, const void *key);
void * dict_getitem_hash(Dict *dict, const void *key, int hash);
int  dict_delitem(Dict *dict, const void *key);
int  dict_delitem_hash(Dict *dict, const void *key, int hash);
void  dict_clear(Dict *dict);

#endif