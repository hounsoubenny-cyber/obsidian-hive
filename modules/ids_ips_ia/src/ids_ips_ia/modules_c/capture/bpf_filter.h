#ifndef BPF_FILTER_H
#define BPF_FILTER_H
#include <linux/filter.h>      /* struct sock_filter, struct sock_fprog */

enum BpfFilerType{
    BPF_001 = 0,         // tcpdump -dd "tcp or udp or icmp or icmp6 or vlan or ether proto 0x88a8"    
    BPF_002 = 1,         // tcpdump -dd "ip or ip6 or arp or vlan or ether proto 0x88a8"
    BPF_003 = 2,         // tcpdump -dd "tcp or udp or icmp or icmp6"
};
typedef enum BpfFilerType BpfFilerType;
struct sock_filter *get_bpf_filter(BpfFilerType type);
#endif