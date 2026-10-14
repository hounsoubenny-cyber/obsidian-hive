#ifndef PORTMAP_H
#define PORTMAP_H

#include <stdint.h>

#define PORTMAP_WORDS 1024   /* 1024 × 64 = 65536 ports */

struct PortMap {
    uint64_t bits[PORTMAP_WORDS];
    uint32_t count;
    uint32_t refcount;
};

void portmap_init(struct PortMap *pm);
int  portmap_add(struct PortMap *pm, uint16_t port);   /* question : 1 = port nouveau (ajouté), 0 = déjà vu */
/* question : 1 = port vu, 0 = pas vu */
int  portmap_test(const struct PortMap *pm, uint16_t port);
void portmap_reset(struct PortMap *pm);

#endif