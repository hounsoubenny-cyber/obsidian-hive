#include "utils.h"

uint32_t ipv4_to_u32(const uint8_t ip[4]){
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8)  |  (uint32_t)ip[3];
}

uint16_t port_to_u16(const uint8_t p[2]){
    return ((uint16_t)p[0] << 8) | p[1];
}

uint64_t monotonic_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

uint64_t realtime_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

/*
fmix32 — finalizer de MurmurHash3

Le principe : prendre un seul nombre (32 bits) et mélanger profondément ses bits.
Ce n'est PAS un hash de données. C'est un "avalanche" : un petit changement en entrée → gros changement en sortie.

Utilisé : à la fin d'un hash, pour casser les patterns. C'est le "finalizer" de MurmurHash3.

Pourquoi ça aide : si ton hash a un biais (ex: les bits de poids faible varient peu), fmix32 le corrige.
 Chaque bit d'entrée influence tous les bits de sortie.
 */

uint32_t fmix32(uint32_t h){
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

/*
FNV-1a — Fowler-Noll-Vo

Le principe : parcourir les octets un par un, XOR puis multiplier.
Caractéristiques :

    Simple (2 opérations par octet)

    Rapide

    Bon pour des clés courtes (< 100 octets)

    Utilisé : Python anciennes versions, Redis, etc.

Les constantes magiques :

    2166136261 = offset basis (graine initiale)

    16777619 = FNV prime (nombre premier)

Pourquoi ces valeurs ? Ce sont des constantes standardisées par les auteurs. 
Elles donnent une bonne distribution. Tu peux les changer, mais on perds la compatibilité avec les autres implémentations.
*/

uint32_t fnv1a(const void *data, size_t len){
    const uint8_t *p = data;
    uint32_t h = 2166136261u;    /* offset basis */
    for (size_t i = 0; i < len; i++){
        h ^= p[i];
        h *= 16777619u;          /* FNV prime */
    }
    return h;
}

uint32_t fnv1a_update(uint32_t h, const uint8_t *p, size_t n){
    for (size_t i = 0; i < n; i++){
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}
