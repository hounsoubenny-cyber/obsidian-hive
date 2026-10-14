#ifndef IPSET_H
#define IPSET_H
#include <stdint.h>

/* Un ensemble d'adresses IP (v4 ou v6), partagé entre plusieurs threads :
 *   · LIRE (ipset_contains) : sans verrou, sans attente. C'est le chemin chaud (chaque paquet).
 *   · ÉCRIRE (ipset_add / ipset_remove) : un seul écrivain à la fois, grâce à un verrou interne (mutex).
 *
 * Comment c'est possible sans verrou en lecture : c'est une table de hachage à adressage ouvert dont chaque case
 * est UN pointeur atomique vers une « fiche » (IpEntry) qu'on ne modifie JAMAIS une fois publiée.
 * Un lecteur voit donc soit la case vide, soit une fiche complète : jamais une IP à moitié écrite.
 *
 * Conventions : action 0 = succès / -1 = échec · question 1 = oui / 0 = non */
typedef struct IpSet IpSet;

IpSet *ipset_create(uint32_t max_items);                       /* NULL si échec. Capacité : max_items IP (arrondi) */
void ipset_destroy(IpSet *s);                                  /* ne pas l'appeler pendant que d'autres threads lisent */
int ipset_add(IpSet *s, const uint8_t *ip, int v4);            /* v4 = 1 : 4 octets · v4 = 0 : 16 octets. Déjà présente : 0 */
int ipset_remove(IpSet *s, const uint8_t *ip, int v4);         /* 0 = retirée, -1 = n'était pas là */
int ipset_contains(const IpSet *s, const uint8_t *ip, int v4); /* 1 = présente, 0 = absente (sans verrou) */
uint32_t ipset_count(const IpSet *s);                          /* nombre d'IP présentes */
#endif
