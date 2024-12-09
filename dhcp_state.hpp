// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP_STATE_HPP_
#define NDHS_DHCP_STATE_HPP_

#include <vector>
#include <nk/net/ip_address.hpp>
#include <nlsocket.hpp>

enum class addr_type { null, v4, v6 };

struct dhcpv6_entry {
    char duid[128];
    nk::ip_address address;
    size_t duid_len;
    uint32_t lifetime;
    uint32_t iaid;
};

struct dhcpv4_entry {
    char macaddr[6];
    nk::ip_address address;
    uint32_t lifetime;
};

void create_blobs();
bool emplace_bind4(size_t linenum, const char *interface);
bool emplace_bind6(size_t linenum, const char *interface);
bool emplace_interface(size_t linenum, const char *interface, uint8_t preference);
bool emplace_dhcp6_state(size_t linenum, const char *interface,
                         const char *duid, size_t duid_len,
                         uint32_t iaid, std::string_view v6_addr, uint32_t default_lifetime);
bool emplace_dhcp4_state(size_t linenum, const char *interface, const char *macstr,
                         std::string_view v4_addr, uint32_t default_lifetime);
bool emplace_dns_server(size_t linenum, const char *interface,
                        std::string_view addr, addr_type atype);
bool emplace_ntp_server(size_t linenum, const char *interface,
                        std::string_view addr, addr_type atype);
bool emplace_subnet(size_t linenum, const char *interface, std::string_view addr);
bool emplace_gateway(size_t linenum, const char *interface, std::string_view addr);
bool emplace_broadcast(size_t linenum, const char *interface, std::string_view addr);
bool emplace_dynamic_range(size_t linenum, const char *interface,
                           std::string_view lo_addr, std::string_view hi_addr,
                           uint32_t dynamic_lifetime);
bool emplace_dynamic_v6(size_t linenum, const char *interface);
bool emplace_dns_search(size_t linenum, const char *interface, std::string &&label);
const dhcpv6_entry *query_dhcp6_state(int ifindex,
                                      const char *duid, size_t duid_len,
                                      uint32_t iaid);
const dhcpv4_entry *query_dhcp4_state(int ifindex, const uint8_t *hwaddr);
const std::vector<nk::ip_address> *query_dns6_servers(int ifindex);
const std::vector<nk::ip_address> *query_dns4_servers(int ifindex);
const std::vector<uint8_t> *query_dns6_search_blob(int ifindex);
const std::vector<std::string> *query_dns_search(int ifindex);
const std::vector<nk::ip_address> *query_ntp6_servers(int ifindex);
const std::vector<nk::ip_address> *query_ntp4_servers(int ifindex);
const std::vector<uint8_t> *query_ntp6_fqdns_blob(int ifindex);
const std::vector<nk::ip_address> *query_ntp6_multicasts(int ifindex);
const std::vector<nk::ip_address> *query_gateway(int ifindex);
const nk::ip_address *query_subnet(int ifindex);
const nk::ip_address *query_broadcast(int ifindex);
const std::pair<nk::ip_address, nk::ip_address> *query_dynamic_range(int ifindex);
bool query_use_dynamic_v4(int ifindex, uint32_t *dynamic_lifetime);
bool query_use_dynamic_v6(int ifindex, uint32_t *dynamic_lifetime);
bool query_unused_addr_v6(int ifindex, const nk::ip_address &addr);
size_t bound_interfaces_count();
void bound_interfaces_foreach(void (*fn)(const struct netif_info *, bool, bool, uint8_t, void *), void *userptr);

#endif
