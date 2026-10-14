#include "dict.h"
#include <stdlib.h>
#include <string.h>

static int dict_rehash_internal(Dict *dict, uint32_t new_size){
    if (dict == NULL || new_size == 0){
        return -1;
    }
    
    // 1. Nouveau tableau de pointeurs
    Entry **new_ptr = (Entry **)calloc(new_size, sizeof(Entry*));
    if (new_ptr == NULL){
        return -1;
    }
    
    // 2. Reparcourir l'ancien tableau et replacer chaque entrée
    for (uint32_t i = 0; i < dict -> size; i++){
        Entry *e = (dict -> ptr)[i];
        while (e != NULL){
            Entry *next = e -> next;   // sauvegarder AVANT de modifier e->next
            uint32_t new_pos = (uint32_t)e -> hash % new_size;
            e -> next = new_ptr[new_pos];   // insérer en tête
            new_ptr[new_pos] = e;
            e = next;
        }
    }
    
    // 3. Libérer l'ANCIEN tableau (pas les Entry !)
    free(dict -> ptr);
    
    // 4. Mettre à jour
    dict -> ptr = new_ptr;
    dict -> size = new_size;
    
    // NOTE : nbr_elements et nbr_fields restent identiques
    // (nbr_fields devrait être recalculé mais pour simplifier, on peut le recalculer)
    dict -> nbr_fields = 0;
    for (uint32_t i = 0; i < new_size; i++){
        if (new_ptr[i] != NULL) dict -> nbr_fields += 1;
    }
    
    return 0;
}

Dict *create_dict(
    uint32_t size, int (*hash)(const void*), 
    int (*compare)(const void*,  const void*),
    void *(*key_dup)(const void*),
    void  (*key_free)(void*),
    void *(*value_dup)(const void*),
    void  (*value_free)(void*)
){
    if (hash == NULL || compare == NULL){
        return NULL;
    }
    if (size <= 0){
        return NULL;
    }
    Dict *dict = (Dict *)calloc(1, sizeof(Dict));
    if (dict == NULL){
        return NULL;
    }
    dict -> size = size;
    dict -> hash = hash;
    dict -> compare = compare;
    dict -> key_dup = key_dup;
    dict -> key_free = key_free;
    dict -> value_dup = value_dup;
    dict -> value_free = value_free;
    Entry **content = (Entry **)calloc(size, sizeof(Entry*));
    if (content == NULL){
        free(dict);
        return NULL;
    }
    dict -> ptr = content;
    dict -> nbr_elements = 0;
    dict -> nbr_fields = 0;
    return dict;
}

static int _dict_setitem(Dict *dict, int pos, const void *key, void *value, int hash_result){
    // copie de la clé si une fonction key_dup est fournie
    const void *key_copy = key;
    if (dict -> key_dup != NULL){
        key_copy = (*(dict -> key_dup))(key);
        if (key_copy == NULL){
            return -1;
        }
    }
    
    // copie de la value si une fonction value_dup est fournie
    void *value_copy = value;
    if (dict -> value_dup != NULL){
        value_copy = (*(dict -> value_dup))(value);
        if (value_copy == NULL){
            if (dict -> key_free != NULL){
                (*(dict -> key_free))((void*)key_copy);
            }
            return -1;
        }
    }
    if ((dict -> ptr)[pos] != NULL){
        Entry *tmp = (dict -> ptr)[pos];
        while (tmp != NULL) {
            if ((*(dict -> compare))(key, tmp -> key) == 0){
                // clé déjà présente : on remplace la value
                if (dict -> value_free != NULL && tmp -> value != NULL){
                    (*(dict -> value_free))(tmp -> value);
                }
                tmp -> value = value_copy;
                // la clé copiée n'est pas utilisée → on la libère
                if (dict -> key_dup != NULL && dict -> key_free != NULL){
                    (*(dict -> key_free))((void*)key_copy);
                }
                return 0;
            }
            if (tmp -> next == NULL){  // dernier de la chaîne et on pas trouvé
                Entry *entry = (Entry *)calloc(1, sizeof(Entry));
                if (entry == NULL){
                    if (dict -> key_free != NULL && dict -> key_dup != NULL){
                        (*(dict -> key_free))((void*)key_copy);
                    }
                    if (dict -> value_free != NULL && dict -> value_dup != NULL){
                        (*(dict -> value_free))(value_copy);
                    }
                    return -1;
                }
                entry -> hash = hash_result;
                entry -> key = key_copy;
                entry -> value = value_copy;
                tmp -> next = entry;
                dict -> nbr_elements += 1;
                return 0;
            }
            tmp = tmp -> next;
        }
    }
    else {
        Entry *entry = (Entry *)calloc(1, sizeof(Entry));
        if (entry == NULL){
            if (dict -> key_free != NULL && dict -> key_dup != NULL){
                (*(dict -> key_free))((void*)key_copy);
            }
            if (dict -> value_free != NULL && dict -> value_dup != NULL){
                (*(dict -> value_free))(value_copy);
            }
            return -1;
        }
        entry -> hash = hash_result;
        entry -> key = key_copy;
        entry -> value = value_copy;
        (dict -> ptr)[pos] = entry;
        dict -> nbr_fields += 1;
        dict -> nbr_elements += 1;
    }
    return 0;
}

int dict_setitem(Dict *dict, const void *key, void *value){
    if (dict == NULL || key == NULL || value == NULL){
        return -1;
    }
    if (dict -> hash == NULL || dict -> compare == NULL || dict -> ptr == NULL || dict -> size == 0){
        return -1;
    }
    // +1 car on veut add un element
    if ((dict -> nbr_elements + 1) * DICT_LOAD_FACTOR_DEN >= dict -> size * DICT_LOAD_FACTOR_NUM){
        if (dict_rehash_internal(dict, dict -> size * 2) != 0){
            return -1;
        }
    }
    int hash_result = (*(dict -> hash))(key);
    uint32_t pos = (uint32_t)hash_result % dict -> size;
    return _dict_setitem(dict, pos, key, value, hash_result);
}

int dict_setitem_hash(Dict *dict, const void *key, void *value, int hash){
    if (dict == NULL || key == NULL || value == NULL){
        return -1;
    }
    if (dict -> hash == NULL || dict -> compare == NULL || dict -> ptr == NULL || dict -> size == 0){
        return -1;
    }
    // +1 car on veut add un element
    if ((dict -> nbr_elements + 1) * DICT_LOAD_FACTOR_DEN >= dict -> size * DICT_LOAD_FACTOR_NUM){
        if (dict_rehash_internal(dict, dict -> size * 2) != 0){
            return -1;
        }
    }
    uint32_t pos = (uint32_t)hash % dict -> size;
    return _dict_setitem(dict, pos, key, value, hash);
}

static void* _dict_getitem(Dict *dict, const void *key, int hash_result){
    uint32_t pos = (uint32_t)hash_result % dict -> size;
    Entry *tmp = (dict -> ptr)[pos];
    while (tmp != NULL) {
        if (tmp -> hash != hash_result){
            tmp = tmp -> next;
            continue;
        }
        if ((*(dict -> compare))(key, tmp -> key) == 0){
            return tmp -> value;
        }
        tmp = tmp -> next;
    }
    return NULL;
}

void *dict_getitem(Dict *dict, const void *key){
    if (dict == NULL || key == NULL){
        return NULL;
    }
    if (dict -> hash == NULL || dict -> compare == NULL || dict -> ptr == NULL || dict -> size == 0){
        return NULL;
    }
    int hash_result = (*(dict -> hash))(key);
    return _dict_getitem(dict, key, hash_result);
}

void * dict_getitem_hash(Dict *dict, const void *key, int hash){
    if (dict == NULL || key == NULL){
        return NULL;
    }
    if (dict -> hash == NULL || dict -> compare == NULL || dict -> ptr == NULL || dict -> size == 0){
        return NULL;
    }
    return _dict_getitem(dict, key, hash);
}

static int _dict_delitem(Dict *dict, const void *key, int hash_result){
    uint32_t pos = (uint32_t)hash_result % dict -> size;
    Entry *cur = (dict -> ptr)[pos];
    Entry *prev = NULL;
    while (cur != NULL) {
        if ((*(dict -> compare))(key, cur -> key) == 0){
            // retirer de la liste chaînée
            if (prev == NULL){
                (dict -> ptr)[pos] = cur -> next;   // tête de liste
            } else {
                prev -> next = cur -> next;          // milieu ou queue
            }
            // libérer la clé et la value si demandé
            if (dict -> key_free != NULL && cur -> key != NULL){
                (*(dict -> key_free))((void*)cur -> key);
            }
            if (dict -> value_free != NULL && cur -> value != NULL){
                (*(dict -> value_free))(cur -> value);
            }
            free(cur);
            // mettre à jour les compteurs
            dict -> nbr_elements -= 1;
            if ((dict -> ptr)[pos] == NULL){
                dict -> nbr_fields -= 1;            // bucket devenu vide
            }
            return 0;
        }
        prev = cur;
        cur = cur -> next;
    }
    return -1;   // clé absente
}

int dict_delitem(Dict *dict, const void *key){
    if (dict == NULL || key == NULL){
        return -1;
    }
    if (dict -> hash == NULL || dict -> compare == NULL || dict -> ptr == NULL || dict -> size == 0){
        return -1;
    }
    int hash_result = (*(dict -> hash))(key);
    return _dict_delitem(dict, key, hash_result);
}

int  dict_delitem_hash(Dict *dict, const void *key, int hash){
    if (dict == NULL || key == NULL){
        return -1;
    }
    if (dict -> hash == NULL || dict -> compare == NULL || dict -> ptr == NULL || dict -> size == 0){
        return -1;
    }
    return _dict_delitem(dict, key, hash);
}

void dict_clear(Dict *dict){
    if (dict == NULL) return;
    if (dict -> ptr == NULL){
        free(dict);
        return;
    }
    for (uint32_t i = 0; i < dict -> size; i++){
        Entry *e = (dict -> ptr)[i];
        while (e != NULL) {
            Entry *tmp = e -> next;
            if (dict -> key_free != NULL && e -> key != NULL){
                (*(dict -> key_free))((void*)e -> key);
            }
            if (dict -> value_free != NULL && e -> value != NULL){
                (*(dict -> value_free))(e -> value);
            }
            free(e);
            e = tmp;
        }
    }
    free(dict -> ptr);
    free(dict);
    return;
}

/* ============================================================
 * Helpers pour clés de type "chaîne C"
 * ============================================================ */
int str_hash(const void *key){
    const char *s = (const char *)key;
    uint32_t h = 2166136261u;
    while (*s){
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    h = fmix32(h);
    return (int)(h & 0x7FFFFFFF);
}

static int str_compare(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static void *str_dup(const void *key) {
    return strdup((const char *)key);
}

static void str_free(void *key) {
    free(key);
}

/* ============================================================
 * Helpers pour clés de type "int"
 * ============================================================ */

static int int_hash(const void *key) {
    int v = *(const int *)key;
    return (int)(fmix32((uint32_t)v) & 0x7FFFFFFF);
}

static int int_compare(const void *a, const void *b) {
    int va = *(const int *)a;
    int vb = *(const int *)b;
    return (va > vb) - (va < vb);
}

static void *int_dup(const void *key) {
    int *copy = (int *)malloc(sizeof(int));
    if (copy == NULL) return NULL;
    *copy = *(const int *)key;
    return copy;
}

static void int_free(void *key) {
    free(key);
}

/* ============================================================
 * Wrappers
 * ============================================================ */

Dict *create_dict_str(uint32_t size) {
    return create_dict(
        size, str_hash, str_compare, str_dup, str_free, NULL, NULL
    );
}

Dict *create_dict_int(uint32_t size) {
    return create_dict(
        size, int_hash, int_compare, int_dup, int_free, NULL, NULL
    );
}

Dict *create_dict_raw(uint32_t size, int (*hash)(const void*), int (*compare)(const void*, const void*)) {
    return create_dict(size, hash, compare, NULL, NULL, NULL, NULL);
}