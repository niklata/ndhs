// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP_STATE_HPP_
#define NDHS_DHCP_STATE_HPP_

#include <vector>
#include <functional>
#include <nk/net/ip_address.hpp>

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
void emplace_bind(size_t linenum, const char *interface, bool is_v4);
bool emplace_interface(size_t linenum, const char *interface, uint8_t preference);
bool emplace_dhcp_state(size_t linenum, const char *interface,
                        const char *duid, size_t duid_len,
                        uint32_t iaid, std::string_view v6_addr, uint32_t default_lifetime);
bool emplace_dhcp_state(size_t linenum, const char *interface, const char *macstr,
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
const dhcpv6_entry* query_dhcp_state(const char *interface,
                                     const char *duid, size_t duid_len,
                                     uint32_t iaid);
const dhcpv4_entry* query_dhcp_state(const char *interface, const uint8_t *hwaddr);
const std::vector<nk::ip_address> *query_dns6_servers(const char *interface);
const std::vector<nk::ip_address> *query_dns4_servers(const char *interface);
const std::vector<uint8_t> *query_dns6_search_blob(const char *interface);
const std::vector<nk::ip_address> *query_ntp6_servers(const char *interface);
const std::vector<nk::ip_address> *query_ntp4_servers(const char *interface);
const std::vector<uint8_t> *query_ntp6_fqdns_blob(const char *interface);
const std::vector<nk::ip_address> *query_ntp6_multicasts(const char *interface);
const std::vector<nk::ip_address> *query_gateway(const char *interface);
const nk::ip_address *query_subnet(const char *interface);
const nk::ip_address *query_broadcast(const char *interface);
const std::pair<nk::ip_address, nk::ip_address> *query_dynamic_range(const char *interface);
const std::vector<std::string> *query_dns_search(const char *interface);
bool query_use_dynamic_v4(const char *interface, uint32_t &dynamic_lifetime);
bool query_use_dynamic_v6(const char *interface, uint32_t &dynamic_lifetime);
bool query_unused_addr_v6(const char *interface, const nk::ip_address &addr);
size_t bound_interfaces_count();
std::vector<std::string> bound_interfaces_names();
void bound_interfaces_foreach(std::function<void(const char *, bool, bool, uint8_t)> fn);

#endif
