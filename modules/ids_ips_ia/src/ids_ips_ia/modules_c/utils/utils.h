#ifndef UTILS_H
#define UTILS_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>


uint32_t ipv4_to_u32(const uint8_t ip[4]);
uint16_t port_to_u16(const uint8_t p[2]);
uint64_t monotonic_ms(void);   // ms depuis le démarrage de la machine (jamais en arrière, mais PAS une date)
uint64_t realtime_ms(void);    // ms depuis le 1er janvier 1970 : en Python, int(time.time() * 1000)
uint32_t fnv1a(const void *data, size_t len);
uint32_t fnv1a_update(uint32_t h, const uint8_t *p, size_t n);
uint32_t fmix32(uint32_t h);

#endif