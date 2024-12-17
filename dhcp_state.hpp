// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP_STATE_HPP_
#define NDHS_DHCP_STATE_HPP_

#include <vector>
#include <ipaddr.h>
#include <nlsocket.hpp>

enum class addr_type { null, v4, v6 };

struct dhcpv6_entry {
    char duid[128];
    in6_addr address;
    size_t duid_len;
    uint32_t lifetime;
    uint32_t iaid;
};

struct dhcpv4_entry {
    uint8_t macaddr[6];
    in6_addr address;
    uint32_t lifetime;
};

void create_blobs();
bool emplace_bind4(size_t linenum, const char *interface);
bool emplace_bind6(size_t linenum, const char *interface);
int emplace_interface(size_t linenum, const char *interface, uint8_t preference);
bool emplace_dhcp6_state(size_t linenum, int ifindex,
                         const char *duid, size_t duid_len,
                         uint32_t iaid, const in6_addr *v6_addr, uint32_t default_lifetime);
bool emplace_dhcp4_state(size_t linenum, int ifindex, const uint8_t *macaddr,
                         const in6_addr *v4_addr, uint32_t default_lifetime);
bool emplace_dns_server(size_t linenum, int ifindex,
                        const in6_addr *addr, addr_type atype);
bool emplace_ntp_server(size_t linenum, int ifindex,
                        const in6_addr *addr, addr_type atype);
bool emplace_subnet(int ifindex, const in6_addr *addr);
bool emplace_gateway(size_t linenum, int ifindex, const in6_addr *addr);
bool emplace_broadcast(int ifindex, const in6_addr *addr);
bool emplace_dynamic_range(size_t linenum, int ifindex,
                           const in6_addr *lo_addr, const in6_addr *hi_addr,
                           uint32_t dynamic_lifetime);
bool emplace_dynamic_v6(size_t linenum, int ifindex);
bool emplace_dns_search(size_t linenum, int ifindex, const char *label, size_t label_len);
const dhcpv6_entry *query_dhcp6_state(int ifindex,
                                      const char *duid, size_t duid_len,
                                      uint32_t iaid);
const dhcpv4_entry *query_dhcp4_state(int ifindex, const uint8_t *hwaddr);
const std::vector<in6_addr> *query_dns6_servers(int ifindex);
const std::vector<in6_addr> *query_dns4_servers(int ifindex);
std::pair<const char *, size_t> query_dns4_search_blob(int ifindex);
std::pair<const char *, size_t> query_dns6_search_blob(int ifindex);
const std::vector<in6_addr> *query_ntp6_servers(int ifindex);
const std::vector<in6_addr> *query_ntp4_servers(int ifindex);
std::pair<const char *, size_t> query_ntp6_fqdns_blob(int ifindex);
const std::vector<in6_addr> *query_ntp6_multicasts(int ifindex);
const std::vector<in6_addr> *query_gateway(int ifindex);
const in6_addr *query_subnet(int ifindex);
const in6_addr *query_broadcast(int ifindex);
bool query_dynamic_range(int ifindex, in6_addr *lo, in6_addr *hi);
bool query_use_dynamic_v4(int ifindex, uint32_t *dynamic_lifetime);
bool query_use_dynamic_v6(int ifindex, uint32_t *dynamic_lifetime);
bool query_unused_addr_v6(int ifindex, const in6_addr *addr);
size_t bound_interfaces_count();
void bound_interfaces_foreach(void (*fn)(const struct netif_info *, bool, bool, uint8_t, void *), void *userptr);

#endif
