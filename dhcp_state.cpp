// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <string>
#include <assert.h>
#include "dhcp_state.hpp"
extern "C" {
#include <net/if.h>
#include "nk/log.h"
}

extern NLSocket nl_socket;

struct interface_data
{
    interface_data(int ifindex_)
        : ifindex(ifindex_), dynamic_lifetime(0), preference(0), use_dhcpv4(false), use_dhcpv6(false),
          use_dynamic_v4(false), use_dynamic_v6(false)
    {}
    int ifindex;
    std::vector<dhcpv6_entry> s6addrs; // static assigned v6 leases
    std::vector<dhcpv4_entry> s4addrs; // static assigned v4 leases
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

static std::vector<interface_data> interface_state;

// Performs DNS label wire encoding cf RFC1035 3.1
// Returns negative values on error, positive values are the number
// of bytes added to the out buffer.
// return of -2 means input was invalid
// return of -1 means out buffer ran out of space
#define MAX_DNS_LABELS 256
static int dns_label(char *out, size_t outlen, std::string_view ds)
{
    size_t locx[MAX_DNS_LABELS * 2];
    size_t locn = 0;
    const char *out_st = out;

    if (ds.size() <= 0)
        return 0;

    // First we build up a list of label start/end offsets.
    size_t s = 0, idx = 0;
    bool in_label = false;
    for (const auto &i: ds) {
        if (i == '.') {
            if (in_label) {
                if (locn >= MAX_DNS_LABELS) return -2; // label too long
                locx[2 * locn    ] = s;
                locx[2 * locn + 1] = idx;
                ++locn;
                in_label = false;
            } else {
                return -2; // malformed input
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
        if (locn >= MAX_DNS_LABELS) return -2;
        locx[2 * locn    ] = s;
        locx[2 * locn + 1] = idx;
        ++locn;
        in_label = false;
    }

    // Now we just need to attach the label length octet followed
    // by the label contents.
    for (size_t i = 0, imax = locn; i < imax; ++i) {
        size_t st = locx[2 * i];
        size_t en = locx[2 * i + 1];
        size_t len = en >= st ? en - st : 0;
        if (len > 63) return -2; // label too long
        if (outlen < 1 + en - st) return -1; // out of space
        *out++ = len; --outlen;
        memcpy(out, &ds[st], en - st); outlen -= en - st;
    }
    // Terminating zero length label.
    if (outlen < 1) return -1; // out of space
    *out++ = 0; --outlen;

    // false means domain name is too long
    return out - out_st <= 255 ? out - out_st : -2;
}

static void create_ra6_dns_search_blob(const std::vector<std::string> &dns_search,
                                       std::vector<uint8_t> &dns_search_blob)
{
    size_t blen = 0;
    char buf[2048]; // must be >= 8*256 bytes

    dns_search_blob.clear();
    for (const auto &dnsname: dns_search) {
        int r = dns_label(buf + blen, sizeof buf - blen, dnsname);
        if (r < 0) {
            if (r == -1) {
                log_line("too many names in dns_search\n");
                break;
            } else {
                log_line("malformed input to dns_search\n");
                continue;
            }
        }
        blen += (size_t)r;
    }
    dns_search_blob.resize(blen);
    memcpy(dns_search_blob.data(), buf, blen);
    assert(dns_search_blob.size() <= 8 * 254);
}

// Different from the dns search blob because we pre-include the
// suboption headers.
static void create_d6_ntp_blob(const std::vector<std::string> &ntp_fqdns,
                               std::vector<uint8_t> &ntp6_fqdns_blob)
{
    size_t blen = 0;
    char buf[256]; // must be >= 256 bytes

    ntp6_fqdns_blob.clear();
    for (const auto &ntpname: ntp_fqdns) {
        if (blen + 2 >= sizeof buf) break;
        buf[blen++] = 0;
        buf[blen++] = 3;
        int r = dns_label(buf + blen, sizeof buf - blen, ntpname);
        if (r < 0) {
            blen -= 2; // back out prefix
            if (r == -1) {
                log_line("too many names in ntp_search\n");
                break;
            } else {
                log_line("malformed input to ntp_search\n");
                continue;
            }
        }
        size_t s = (size_t)r;
        if (blen + s + 2 >= sizeof buf) {
            blen -= 2; // back out prefix
            break;
        }
        blen += s;
        buf[blen++] = s >> 8;
        buf[blen++] = s & 0xff;
    }
    ntp6_fqdns_blob.resize(blen);
    memcpy(ntp6_fqdns_blob.data(), buf, blen);
    assert(ntp6_fqdns_blob.size() <= 255);
}

void create_blobs()
{
    for (auto &i: interface_state) {
        create_ra6_dns_search_blob(i.dns_search, i.dns_search_blob);
        i.dns_search.clear();
        create_d6_ntp_blob(i.ntp6_fqdns, i.ntp6_fqdns_blob);
        i.ntp6_fqdns.clear();
    }
}

// Faster and should be preferred
static interface_data *lookup_interface(int ifindex)
{
    for (auto &i: interface_state) {
        if (i.ifindex == ifindex) return &i;
    }
    return nullptr;
}

static interface_data *lookup_interface(const char *interface)
{
    auto ifinfo = nl_socket.get_ifinfo(interface);
    if (!ifinfo) return nullptr;
    return lookup_interface(ifinfo->index);
}

static interface_data *lookup_or_create_interface(const char *interface)
{
    if (!strlen(interface)) return nullptr;
    auto is = lookup_interface(interface);
    if (!is) {
        auto ifinfo = nl_socket.get_ifinfo(interface);
        if (!ifinfo) return nullptr;
        interface_state.emplace_back(ifinfo->index);
        is = &interface_state.back();
    }
    return is;
}

bool emplace_bind4(size_t linenum, const char *interface)
{
    auto is = lookup_or_create_interface(interface);
    if (!is) {
        log_line("interface specified at line %zu does not exist\n", linenum);
        return false;
    }
    is->use_dhcpv4 = true;
    return true;
}

bool emplace_bind6(size_t linenum, const char *interface)
{
    auto is = lookup_or_create_interface(interface);
    if (!is) {
        log_line("interface specified at line %zu does not exist\n", linenum);
        return false;
    }
    is->use_dhcpv6 = true;
    return true;
}

bool emplace_interface(size_t linenum, const char *interface, uint8_t preference)
{
    auto is = lookup_interface(interface);
    if (is) {
        is->preference = preference;
        return true;
    }
    log_line("interface specified at line %zu is not bound\n", linenum);
    return false;
}

bool emplace_dhcp6_state(size_t linenum, const char *interface,
                         const char *duid, size_t duid_len,
                         uint32_t iaid, const nk::ip_address &v6_addr, uint32_t default_lifetime)
{
    auto is = lookup_interface(interface);
    if (is) {
        dhcpv6_entry t;
        if (duid_len > sizeof t.duid) abort();
        memcpy(t.duid, duid, duid_len);
        t.address = v6_addr;
        t.duid_len = duid_len;
        t.lifetime = default_lifetime;
        t.iaid = iaid;
        is->s6addrs.push_back(t);
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_dhcp4_state(size_t linenum, const char *interface, const char *macstr,
                         const nk::ip_address &v4_addr, uint32_t default_lifetime)
{
    auto is = lookup_interface(interface);
    if (is) {
        if (!v4_addr.is_v4()) {
            log_line("Bad IPv4 address at line %zu\n", linenum);
            return false;
        }

        dhcpv4_entry t;
        uint8_t u[6];
        if (sscanf(macstr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &u[0], &u[1], &u[2], &u[3], &u[4], &u[5]) != 6) {
            log_line("Bad MAC address at line %zu: %s\n", linenum, macstr);
            return false;
        }
        memcpy(t.macaddr, u, sizeof t.macaddr);
        t.address = v4_addr;
        t.lifetime = default_lifetime;
        is->s4addrs.push_back(t);
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_dns_server(size_t linenum, const char *interface,
                        const nk::ip_address &addr, addr_type atype)
{
    if (atype == addr_type::null) {
        log_line("Invalid address type at line %zu\n", linenum);
        return false;
    }
    auto is = lookup_interface(interface);
    if (is) {
        if ((atype == addr_type::v4 && !addr.is_v4()) || (atype == addr_type::v6 && addr.is_v4())) {
            log_line("Bad IP address at line %zu\n", linenum);
            return false;
        }
        if (atype == addr_type::v4) {
            is->dns4_servers.emplace_back(addr);
        } else {
            is->dns6_servers.emplace_back(addr);
        }
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_ntp_server(size_t linenum, const char *interface,
                        const nk::ip_address &addr, addr_type atype)
{
    if (atype == addr_type::null) {
        log_line("Invalid address type at line %zu\n", linenum);
        return false;
    }
    auto is = lookup_interface(interface);
    if (is) {
        if ((atype == addr_type::v4 && !addr.is_v4()) || (atype == addr_type::v6 && addr.is_v4())) {
            log_line("Bad IP address at line %zu\n", linenum);
            return false;
        }
        if (atype == addr_type::v4) {
            is->ntp4_servers.emplace_back(addr);
        } else {
            is->ntp6_servers.emplace_back(addr);
        }
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_subnet(size_t linenum, const char *interface, const nk::ip_address &addr)
{
    auto is = lookup_interface(interface);
    if (is) {
        if (!addr.is_v4()) {
            log_line("Bad IP address at line %zu\n", linenum);
            return false;
        }
        is->subnet = addr;
        return true;
    }
    return false;
}

bool emplace_gateway(size_t linenum, const char *interface, const nk::ip_address &addr)
{
    auto is = lookup_interface(interface);
    if (is) {
        if (!addr.is_v4()) {
            log_line("Bad IP address at line %zu\n", linenum);
            return false;
        }
        is->gateway.emplace_back(addr);
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_broadcast(size_t linenum, const char *interface, const nk::ip_address &addr)
{
    auto is = lookup_interface(interface);
    if (is) {
        if (!addr.is_v4()) {
            log_line("Bad IP address at line %zu\n", linenum);
            return false;
        }
        is->broadcast = addr;
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_dynamic_range(size_t linenum, const char *interface,
                           const nk::ip_address &lo_addr, const nk::ip_address &hi_addr,
                           uint32_t dynamic_lifetime)
{
    auto is = lookup_interface(interface);
    if (is) {
        if (!lo_addr.is_v4() || !hi_addr.is_v4()) {
            log_line("Bad IPv4 address at line %zu\n", linenum);
            return false;
        }
        is->dynamic_range = lo_addr <= hi_addr ? std::make_pair(lo_addr, hi_addr)
                                               : std::make_pair(hi_addr, lo_addr);
        is->dynamic_lifetime = dynamic_lifetime;
        is->use_dynamic_v4 = true;
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_dynamic_v6(size_t linenum, const char *interface)
{
    auto is = lookup_interface(interface);
    if (is) {
        is->use_dynamic_v6 = true;
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

bool emplace_dns_search(size_t linenum, const char *interface, const char *label, size_t label_len)
{
    auto is = lookup_interface(interface);
    if (is) {
        is->dns_search.emplace_back(label, label_len);
        return true;
    }
    log_line("No interface specified at line %zu\n", linenum);
    return false;
}

const dhcpv6_entry *query_dhcp6_state(int ifindex,
                                      const char *duid, size_t duid_len,
                                      uint32_t iaid)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    for (auto &i: is->s6addrs) {
        if (i.duid_len == duid_len && i.iaid == iaid &&
            !memcmp(i.duid, duid, duid_len)) {
            return &i;
        }
    }
    return nullptr;
}

const dhcpv4_entry *query_dhcp4_state(int ifindex, const uint8_t *hwaddr)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    char buf[6];
    memcpy(buf, hwaddr, sizeof buf);
    for (auto &i: is->s4addrs) {
        if (!memcmp(i.macaddr, hwaddr, sizeof i.macaddr)) return &i;
    }
    return nullptr;
}

const std::vector<nk::ip_address> *query_dns6_servers(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->dns6_servers;
}

const std::vector<nk::ip_address> *query_dns4_servers(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->dns4_servers;
}

const std::vector<uint8_t> *query_dns6_search_blob(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->dns_search_blob;
}

const std::vector<std::string> *query_dns_search(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->dns_search;
}

const std::vector<nk::ip_address> *query_ntp6_servers(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->ntp6_servers;
}

const std::vector<nk::ip_address> *query_ntp4_servers(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->ntp4_servers;
}

const std::vector<uint8_t> *query_ntp6_fqdns_blob(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->ntp6_fqdns_blob;
}

const std::vector<nk::ip_address> *query_ntp6_multicasts(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->ntp6_multicasts;
}

const std::vector<nk::ip_address> *query_gateway(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->gateway;
}

const nk::ip_address *query_subnet(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->subnet;
}

const nk::ip_address *query_broadcast(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->broadcast;
}

const std::pair<nk::ip_address, nk::ip_address> *
query_dynamic_range(int ifindex)
{
    auto is = lookup_interface(ifindex);
    if (!is) return nullptr;
    return &is->dynamic_range;
}

bool query_use_dynamic_v4(int ifindex, uint32_t *dynamic_lifetime)
{
    auto is = lookup_interface(ifindex);
    if (!is) return false;
    *dynamic_lifetime = is->dynamic_lifetime;
    return is->use_dynamic_v4;
}

bool query_use_dynamic_v6(int ifindex, uint32_t *dynamic_lifetime)
{
    auto is = lookup_interface(ifindex);
    if (!is) return false;
    *dynamic_lifetime = is->dynamic_lifetime;
    return is->use_dynamic_v6;
}

bool query_unused_addr_v6(int ifindex, const nk::ip_address &addr)
{
    auto is = lookup_interface(ifindex);
    if (!is) return true;
    for (const auto &i: is->s6addrs) {
        if (i.address == addr) return false;
    }
    return true;
}

size_t bound_interfaces_count()
{
    return interface_state.size();
}

void bound_interfaces_foreach(void (*fn)(const struct netif_info *, bool, bool, uint8_t, void *), void *userptr)
{
    for (const auto &i: interface_state) {
        auto ifinfo = nl_socket.get_ifinfo(i.ifindex);
        if (!ifinfo) continue;
        fn(ifinfo, i.use_dhcpv4, i.use_dhcpv6, i.preference, userptr);
    }
}
