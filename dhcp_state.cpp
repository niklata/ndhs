// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unordered_map>
#include <optional>
#include <memory>
#include <string>
#include <cassert>
#include "dhcp_state.hpp"
extern "C" {
#include "nk/log.h"
}

struct interface_data
{
    interface_data(bool use_v4, bool use_v6)
        : dynamic_lifetime(0), preference(0), use_dhcpv4(use_v4), use_dhcpv6(use_v6),
          use_dynamic_v4(false), use_dynamic_v6(false) {}
    std::unordered_multimap<std::string, std::unique_ptr<dhcpv6_entry>> duid_mapping;
    std::unordered_map<std::string, std::unique_ptr<dhcpv4_entry>> macaddr_mapping;
    std::vector<nk::ip_address> gateway;
    std::vector<nk::ip_address> dns6_servers;
    std::vector<nk::ip_address> dns4_servers;
    std::vector<nk::ip_address> ntp6_servers;
    std::vector<nk::ip_address> ntp4_servers;
    std::vector<nk::ip_address> ntp6_multicasts;
    std::vector<std::string> dns_search;
    std::vector<std::string> ntp6_fqdns;
    nk::ip_address subnet;
    nk::ip_address broadcast;
    std::vector<uint8_t> dns_search_blob;
    std::vector<uint8_t> ntp6_fqdns_blob;
    std::pair<nk::ip_address, nk::ip_address> dynamic_range;
    uint32_t dynamic_lifetime;
    uint8_t preference;
    bool use_dhcpv4:1;
    bool use_dhcpv6:1;
    bool use_dynamic_v4:1;
    bool use_dynamic_v6:1;
};

static std::unordered_map<std::string, interface_data> interface_state;

// Performs DNS label wire encoding cf RFC1035 3.1
// Allocates memory frequently in order to make correctness easier to
// verify, but at least in this program, it will called only at
// reconfiguration.
static std::optional<std::vector<uint8_t>> dns_label(const std::string &ds)
{
    std::vector<uint8_t> ret;
    std::vector<std::pair<size_t, size_t>> locs;

    if (ds.size() <= 0)
        return ret;

    // First we build up a list of label start/end offsets.
    size_t s=0, idx=0;
    bool in_label(false);
    for (const auto &i: ds) {
        if (i == '.') {
            if (in_label) {
                locs.emplace_back(std::make_pair(s, idx));
                in_label = false;
            } else {
                return {}; // malformed input
            }
        } else {
            if (!in_label) {
                s = idx;
                in_label = true;
            }
        }
        ++idx;
    }
    // We don't demand a trailing dot.
    if (in_label) {
        locs.emplace_back(std::make_pair(s, idx));
        in_label = false;
    }

    // Now we just need to attach the label length octet followed
    // by the label contents.
    for (const auto &i: locs) {
        auto len = i.second - i.first;
        if (len > 63)
            return {}; // label too long
        ret.push_back(len);
        for (size_t j = i.first; j < i.second; ++j)
            ret.push_back(static_cast<uint8_t>(ds[j]));
    }
    // Terminating zero length label.
    if (ret.size())
        ret.push_back(0);
    if (ret.size() > 255)
        return {}; // domain name too long
    return ret;
}

static void create_dns_search_blob(std::vector<std::string> &dns_search,
                                   std::vector<uint8_t> &dns_search_blob)
{
    dns_search_blob.clear();
    for (const auto &dnsname: dns_search) {
        auto lbl = dns_label(dnsname);
        if (!lbl) {
            log_line("labelizing %s failed", dnsname.c_str());
            continue;
        }
        // See if the search blob size is too large to encode in a RA
        // dns search option.
        if (dns_search_blob.size() + lbl->size() > 8 * 254) {
            log_line("dns search list is too long, truncating");
            break;
        }
        dns_search_blob.insert(dns_search_blob.end(),
                               std::make_move_iterator(lbl->begin()),
                               std::make_move_iterator(lbl->end()));
    }
    assert(dns_search_blob.size() <= 8 * 254);
    dns_search.clear();
}

// Different from the dns search blob because we pre-include the
// suboption headers.
static void create_ntp6_fqdns_blob(std::vector<std::string> &ntp_fqdns,
                            std::vector<uint8_t> &ntp6_fqdns_blob)
{
    ntp6_fqdns_blob.clear();
    for (const auto &ntpname: ntp_fqdns) {
        auto lbl = dns_label(ntpname);
        if (!lbl) {
            log_line("labelizing %s failed", ntpname.c_str());
            continue;
        }
        ntp6_fqdns_blob.push_back(0);
        ntp6_fqdns_blob.push_back(3);
        uint16_t lblsize = lbl->size();
        ntp6_fqdns_blob.push_back(lblsize >> 8);
        ntp6_fqdns_blob.push_back(lblsize & 0xff);
        ntp6_fqdns_blob.insert(ntp6_fqdns_blob.end(),
                               std::make_move_iterator(lbl->begin()),
                               std::make_move_iterator(lbl->end()));
    }
}

void create_blobs()
{
    for (auto &i: interface_state) {
        create_dns_search_blob(i.second.dns_search, i.second.dns_search_blob);
        create_ntp6_fqdns_blob(i.second.ntp6_fqdns, i.second.ntp6_fqdns_blob);
    }
}

bool emplace_bind(size_t /* linenum */, std::string &&interface, bool is_v4)
{
    if (interface.empty())
        return false;
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) {
        interface_state.emplace(std::make_pair(std::move(interface),
                                               interface_data(is_v4, !is_v4)));
        return true;
    }
    if (is_v4) si->second.use_dhcpv4 = true;
    if (!is_v4) si->second.use_dhcpv6 = true;
    return true;
}

bool emplace_interface(size_t linenum, const std::string &interface, uint8_t preference)
{
    if (interface.empty())
        return false;
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) {
        log_line("interface specified at line %zu is not bound", linenum);
        return false;
    }
    si->second.preference = preference;
    return true;
}

bool emplace_dhcp_state(size_t linenum, const std::string &interface, std::string &&duid,
                        uint32_t iaid, const std::string &v6_addr, uint32_t default_lifetime)
{
    auto si = interface_state.find(interface);
    if (interface.empty() || si == interface_state.end()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    nk::ip_address ipa;
    if (!ipa.from_string(v6_addr)) {
        log_line("Bad IPv6 address at line %zu: %s", linenum, v6_addr.c_str());
        return false;
    }
    si->second.duid_mapping.emplace
        (std::make_pair(std::move(duid),
                        std::make_unique<dhcpv6_entry>(iaid, ipa, default_lifetime)));
    return true;
}

bool emplace_dhcp_state(size_t linenum, const std::string &interface, const std::string &macaddr,
                        const std::string &v4_addr, uint32_t default_lifetime)
{
    auto si = interface_state.find(interface);
    if (interface.empty() || si == interface_state.end()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    nk::ip_address ipa;
    if (!ipa.from_string(v4_addr) || !ipa.is_v4()) {
        log_line("Bad IPv4 address at line %zu: %s", linenum, v4_addr.c_str());
        return false;
    }
    uint8_t buf[7] = {0};
    for (unsigned i = 0; i < 6; ++i)
        buf[i] = strtol(macaddr.c_str() + 3*i, nullptr, 16);
    si->second.macaddr_mapping.emplace
        (std::make_pair(std::string{reinterpret_cast<char *>(buf), 6},
                        std::make_unique<dhcpv4_entry>(ipa, default_lifetime)));
    return true;
}

bool emplace_dns_server(size_t linenum, const std::string &interface,
                        const std::string &addr, addr_type atype)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    if (atype == addr_type::null) {
        log_line("Invalid address type at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    nk::ip_address ipa;
    auto bad_addr = !ipa.from_string(addr);
    if (atype == addr_type::v4) {
        if (bad_addr || !ipa.is_v4()) {
            log_line("Bad IPv4 address at line %zu: %s", linenum, addr.c_str());
            return false;
        }
        si->second.dns4_servers.emplace_back(std::move(ipa));
    } else {
        if (bad_addr || ipa.is_v4()) {
            log_line("Bad IPv6 address at line %zu: %s", linenum, addr.c_str());
            return false;
        }
        si->second.dns6_servers.emplace_back(std::move(ipa));
    }
    return true;
}

bool emplace_ntp_server(size_t linenum, const std::string &interface,
                        const std::string &addr, addr_type atype)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    if (atype == addr_type::null) {
        log_line("Invalid address type at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    nk::ip_address ipa;
    auto bad_addr = !ipa.from_string(addr);
    if (atype == addr_type::v4) {
        if (bad_addr || !ipa.is_v4()) {
            log_line("Bad IPv4 address at line %zu: %s", linenum, addr.c_str());
            return false;
        }
        si->second.ntp4_servers.emplace_back(std::move(ipa));
    } else {
        if (bad_addr || ipa.is_v4()) {
            log_line("Bad IPv6 address at line %zu: %s", linenum, addr.c_str());
            return false;
        }
        si->second.ntp6_servers.emplace_back(std::move(ipa));
    }
    return true;
}

bool emplace_subnet(size_t linenum, const std::string &interface, const std::string &addr)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    nk::ip_address ipa;
    if (!ipa.from_string(addr) || !ipa.is_v4()) {
        log_line("Bad IP address at line %zu: %s", linenum, addr.c_str());
        return false;
    }
    si->second.subnet = std::move(ipa);
    return true;
}

bool emplace_gateway(size_t linenum, const std::string &interface, const std::string &addr)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    nk::ip_address ipa;
    if (!ipa.from_string(addr) || !ipa.is_v4()) {
        log_line("Bad IPv4 address at line %zu: %s", linenum, addr.c_str());
        return false;
    }
    si->second.gateway.emplace_back(std::move(ipa));
    return true;
}

bool emplace_broadcast(size_t linenum, const std::string &interface, const std::string &addr)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    nk::ip_address ipa;
    if (!ipa.from_string(addr) || !ipa.is_v4()) {
        log_line("Bad IPv4 address at line %zu: %s", linenum, addr.c_str());
        return false;
    }
    si->second.broadcast = std::move(ipa);
    return true;
}

bool emplace_dynamic_range(size_t linenum, const std::string &interface,
                           const std::string &lo_addr, const std::string &hi_addr,
                           uint32_t dynamic_lifetime)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    nk::ip_address lo_ipa, hi_ipa;
    if (!lo_ipa.from_string(lo_addr) || !lo_ipa.is_v4()) {
        log_line("Bad IPv4 address at line %zu: %s", linenum, lo_addr.c_str());
        return false;
    }
    if (!hi_ipa.from_string(hi_addr) || !hi_ipa.is_v4()) {
        log_line("Bad IPv4 address at line %zu: %s", linenum, hi_addr.c_str());
        return false;
    }
    if (lo_ipa > hi_ipa)
        std::swap(lo_ipa, hi_ipa);
    si->second.dynamic_range = std::make_pair(std::move(lo_ipa), std::move(hi_ipa));
    si->second.dynamic_lifetime = dynamic_lifetime;
    si->second.use_dynamic_v4 = true;
    return true;
}

bool emplace_dynamic_v6(size_t linenum, const std::string &interface)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    si->second.use_dynamic_v6 = true;
    return true;
}

bool emplace_dns_search(size_t linenum, const std::string &interface, std::string &&label)
{
    if (interface.empty()) {
        log_line("No interface specified at line %zu", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    si->second.dns_search.emplace_back(std::move(label));
    return true;
}

const dhcpv6_entry *query_dhcp_state(const std::string &interface, const std::string &duid,
                                     uint32_t iaid)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    auto f = si->second.duid_mapping.equal_range(duid);
    for (auto i = f.first; i != f.second; ++i) {
        if (i->second->iaid == iaid)
            return i->second.get();
    }
    return nullptr;
}

const dhcpv4_entry* query_dhcp_state(const std::string &interface, const uint8_t *hwaddr)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    auto f = si->second.macaddr_mapping.find(std::string(reinterpret_cast<const char *>(hwaddr), 6));
    return f != si->second.macaddr_mapping.end() ? f->second.get() : nullptr;
}

const std::vector<nk::ip_address> *query_dns6_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.dns6_servers;
}

const std::vector<nk::ip_address> *query_dns4_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.dns4_servers;
}

const std::vector<uint8_t> *query_dns6_search_blob(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.dns_search_blob;
}

const std::vector<nk::ip_address> *query_ntp6_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.ntp6_servers;
}

const std::vector<nk::ip_address> *query_ntp4_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.ntp4_servers;
}

const std::vector<uint8_t> *query_ntp6_fqdns_blob(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.ntp6_fqdns_blob;
}

const std::vector<nk::ip_address> *query_ntp6_multicasts(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.ntp6_multicasts;
}

const std::vector<nk::ip_address> *query_gateway(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.gateway;
}

const nk::ip_address *query_subnet(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.subnet;
}

const nk::ip_address *query_broadcast(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.broadcast;
}

const std::pair<nk::ip_address, nk::ip_address> *
query_dynamic_range(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.dynamic_range;
}

const std::vector<std::string> *query_dns_search(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return nullptr;
    return &si->second.dns_search;
}

bool query_use_dynamic_v4(const std::string &interface, uint32_t &dynamic_lifetime)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    dynamic_lifetime = si->second.dynamic_lifetime;
    return si->second.use_dynamic_v4;
}

bool query_use_dynamic_v6(const std::string &interface, uint32_t &dynamic_lifetime)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    dynamic_lifetime = si->second.dynamic_lifetime;
    return si->second.use_dynamic_v6;
}

bool query_unused_addr(const std::string &interface, const nk::ip_address &addr)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return true;

    for (const auto &i: si->second.duid_mapping) {
        if (i.second->address == addr)
            return false;
    }
    return true;
}

size_t bound_interfaces_count()
{
    return interface_state.size();
}

std::vector<std::string> bound_interfaces_names()
{
    std::vector<std::string> ret;
    for (const auto &i: interface_state)
        ret.emplace_back(i.first);
    return ret;
}

void bound_interfaces_foreach(std::function<void(const std::string&, bool, bool, uint8_t)> fn)
{
    for (const auto &i: interface_state)
        fn(i.first, i.second.use_dhcpv4, i.second.use_dhcpv6, i.second.preference);
}

