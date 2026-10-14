/* test_packets.h : fabrique des ParserResult « à la main » (sans passer par parse()),
 * pour tester flow.c et flow_table.c indépendamment du parser.
 *
 *   IP4(10,0,0,1)            → tableau de 4 octets
 *   pk_ip6(out, 1)           → 2001:db8::1 (le dernier octet est configurable)
 *   pk_tcp4(src, sp, dst, dp, flags)
 *   pk_udp4(src, sp, dst, dp)
 *   pk_icmp4(src, dst, type, code)
 *   pk_tcp6 / pk_udp6        → pareil en IPv6
 */
#ifndef TEST_PACKETS_H
#define TEST_PACKETS_H

#include <stdint.h>
#include <string.h>
#include "parser/parser.h"

#define IP4(a, b, c, d) ((const uint8_t[4]){(a), (b), (c), (d)})

static inline void pk_put16(uint8_t out[2], uint16_t v) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)(v & 0xFF);
}

static inline void pk_ip6(uint8_t out[16], uint8_t last) {
    memset(out, 0, 16);
    out[0] = 0x20; out[1] = 0x01; out[2] = 0x0d; out[3] = 0xb8;
    out[15] = last;
}

static inline ParserResult pk_base(int v6) {
    ParserResult r;
    memset(&r, 0, sizeof r);
    r.len = 60;
    r.code = (uint8_t)SUCCES;
    r.ip_start = 14;
    if (v6) { r.type = IPV6; r.version = 6; }
    else    { r.type = IPV4; r.version = 4; r.ihl = 5; }
    return r;
}

static inline ParserResult pk_tcp4(const uint8_t *src, uint16_t sp, const uint8_t *dst, uint16_t dp, uint8_t flags) {
    ParserResult r = pk_base(0);
    memcpy(r.ip_data.ipv4.src_ip, src, L_IPV4);
    memcpy(r.ip_data.ipv4.dst_ip, dst, L_IPV4);
    r.ip_data.ipv4.proto = (uint8_t)TCP;
    pk_put16(r.data.tcp.src_port, sp);
    pk_put16(r.data.tcp.dst_port, dp);
    r.data.tcp.flags = flags;
    return r;
}

static inline ParserResult pk_udp4(const uint8_t *src, uint16_t sp, const uint8_t *dst, uint16_t dp) {
    ParserResult r = pk_base(0);
    memcpy(r.ip_data.ipv4.src_ip, src, L_IPV4);
    memcpy(r.ip_data.ipv4.dst_ip, dst, L_IPV4);
    r.ip_data.ipv4.proto = (uint8_t)UDP;
    pk_put16(r.data.udp.src_port, sp);
    pk_put16(r.data.udp.dst_port, dp);
    return r;
}

static inline ParserResult pk_icmp4(const uint8_t *src, const uint8_t *dst, int type, int code) {
    ParserResult r = pk_base(0);
    memcpy(r.ip_data.ipv4.src_ip, src, L_IPV4);
    memcpy(r.ip_data.ipv4.dst_ip, dst, L_IPV4);
    r.ip_data.ipv4.proto = (uint8_t)ICMP;
    r.data.icmp.type = type;
    r.data.icmp.code = code;
    return r;
}

static inline ParserResult pk_tcp6(const uint8_t *src, uint16_t sp, const uint8_t *dst, uint16_t dp, uint8_t flags) {
    ParserResult r = pk_base(1);
    memcpy(r.ip_data.ipv6.src_ip, src, L_IPV6);
    memcpy(r.ip_data.ipv6.dst_ip, dst, L_IPV6);
    r.ip_data.ipv6.next_header = (uint8_t)TCP;
    pk_put16(r.data.tcp.src_port, sp);
    pk_put16(r.data.tcp.dst_port, dp);
    r.data.tcp.flags = flags;
    return r;
}

static inline ParserResult pk_udp6(const uint8_t *src, uint16_t sp, const uint8_t *dst, uint16_t dp) {
    ParserResult r = pk_base(1);
    memcpy(r.ip_data.ipv6.src_ip, src, L_IPV6);
    memcpy(r.ip_data.ipv6.dst_ip, dst, L_IPV6);
    r.ip_data.ipv6.next_header = (uint8_t)UDP;
    pk_put16(r.data.udp.src_port, sp);
    pk_put16(r.data.udp.dst_port, dp);
    return r;
}

#endif
