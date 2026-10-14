#ifndef RULES_H
#define RULES_H
#include "../flows/flow.h"
#include "../portmap/portmap.h"

// Une règle = une fonction rapide qui LIT un flux et donne un verdict. Elle ne supprime rien, ne bloque rien elle-même.
//   UNKNOW = « pas d'avis » (le verdict actuel du flux ne change pas), BLOCK, LIMIT_REACHED
// ports = la PortMap de l'IP qui a lancé le flux (peut être NULL)
typedef FlowVerdict (*FlowRuleFn)(const FlowData *data, const struct PortMap *ports);

#define SCAN_PORT_THRESHOLD 20   // ports distincts visités par une même IP source avant de dire « scan »

FlowVerdict rule_port_scan(const FlowData *data, const struct PortMap *ports);
#endif
