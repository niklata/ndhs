// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP_STATE_HPP_
#define NDHS_DHCP_STATE_HPP_

#include <vector>
#include <functional>
#include <nk/net/ip_address.hpp>

enum class addr_type { null, v4, v6 };

struct dhcpv6_entry {
    dhcpv6_entry(uint32_t iaid_, const nk::ip_address &addr_, uint32_t lifetime_)
        : address(addr_), iaid(iaid_), lifetime(lifetime_) {}
    nk::ip_address address;
    uint32_t iaid;
    uint32_t lifetime;
};

struct dhcpv4_entry {
    dhcpv4_entry(const nk::ip_address &addr_, uint32_t lifetime_)
        : address(addr_), lifetime(lifetime_) {}
    nk::ip_address address;
    uint32_t lifetime;
};

void create_blobs();
bool emplace_bind(size_t linenum, std::string &&interface, bool is_v4);
bool emplace_interface(size_t linenum, const std::string &interface, uint8_t preference);
bool emplace_dhcp_state(size_t linenum, const std::string &interface, std::string &&duid,
                        uint32_t iaid, const std::string &v6_addr, uint32_t default_lifetime);
bool emplace_dhcp_state(size_t linenum, const std::string &interface, const std::string &macaddr,
                        const std::string &v4_addr, uint32_t default_lifetime);
bool emplace_dns_server(size_t linenum, const std::string &interface,
                        const std::string &addr, addr_type atype);
bool emplace_ntp_server(size_t linenum, const std::string &interface,
                        const std::string &addr, addr_type atype);
bool emplace_subnet(size_t linenum, const char *interface, const std::string &addr);
bool emplace_gateway(size_t linenum, const std::string &interface, const std::string &addr);
bool emplace_broadcast(size_t linenum, const char *interface, const std::string &addr);
bool emplace_dynamic_range(size_t linenum, const std::string &interface,
                           const std::string &lo_addr, const std::string &hi_addr,
                           uint32_t dynamic_lifetime);
bool emplace_dynamic_v6(size_t linenum, const std::string &interface);
bool emplace_dns_search(size_t linenum, const std::string &interface, std::string &&label);
const dhcpv6_entry* query_dhcp_state(const std::string &interface, const std::string &duid,
                                     uint32_t iaid);
const dhcpv4_entry* query_dhcp_state(const std::string &interface, const uint8_t *hwaddr);
const std::vector<nk::ip_address> *query_dns6_servers(const std::string &interface);
const std::vector<nk::ip_address> *query_dns4_servers(const std::string &interface);
const std::vector<uint8_t> *query_dns6_search_blob(const std::string &interface);
const std::vector<nk::ip_address> *query_ntp6_servers(const std::string &interface);
const std::vector<nk::ip_address> *query_ntp4_servers(const std::string &interface);
const std::vector<uint8_t> *query_ntp6_fqdns_blob(const std::string &interface);
const std::vector<nk::ip_address> *query_ntp6_multicasts(const std::string &interface);
const std::vector<nk::ip_address> *query_gateway(const std::string &interface);
const nk::ip_address *query_subnet(const std::string &interface);
const nk::ip_address *query_broadcast(const std::string &interface);
const std::pair<nk::ip_address, nk::ip_address> *query_dynamic_range(const std::string &interface);
const std::vector<std::string> *query_dns_search(const std::string &interface);
bool query_use_dynamic_v4(const std::string &interface, uint32_t &dynamic_lifetime);
bool query_use_dynamic_v6(const std::string &interface, uint32_t &dynamic_lifetime);
bool query_unused_addr(const std::string &interface, const nk::ip_address &addr);
size_t bound_interfaces_count();
std::vector<std::string> bound_interfaces_names();
void bound_interfaces_foreach(std::function<void(const std::string&, bool, bool, uint8_t)> fn);

#endif
