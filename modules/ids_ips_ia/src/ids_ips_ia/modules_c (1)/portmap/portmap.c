#include "portmap.h"
#include <string.h>

void portmap_reset(struct PortMap *pm) {
    memset(pm->bits, 0, sizeof(pm->bits));
    pm->count = 0;
}

void portmap_init(struct PortMap *pm) {
    portmap_reset(pm);
    pm->refcount = 0;
}

int portmap_add(struct PortMap *pm, uint16_t port) {
    uint32_t word = port / 64;
    uint32_t bit  = port % 64;
    uint64_t mask = 1ULL << bit;
    if (pm->bits[word] & mask) return 0;
    pm->bits[word] |= mask;
    pm->count++;
    return 1;
}

int portmap_test(const struct PortMap *pm, uint16_t port) {
    return (pm->bits[port / 64] >> (port % 64)) & 1;
}
