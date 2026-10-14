#include "rules.h"

// Scan de ports : une IP qui a touché SCAN_PORT_THRESHOLD ports distincts ou plus
FlowVerdict rule_port_scan(const FlowData *data, const struct PortMap *ports){
    (void)data;
    if (ports == NULL) return UNKNOW;
    return ports -> count >= SCAN_PORT_THRESHOLD ? BLOCK : UNKNOW;
}
