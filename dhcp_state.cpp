#include <unordered_map>
#include <format.hpp>
#include <asio.hpp>
#include "dhcp_state.hpp"

struct interface_data
{
    interface_data(bool use_v4, bool use_v6) : use_dhcpv4(use_v4), use_dhcpv6(use_v6) {}
    std::unordered_multimap<std::string, std::unique_ptr<dhcpv6_entry>> duid_mapping;
    std::unordered_map<std::string, std::unique_ptr<dhcpv4_entry>> macaddr_mapping;
    std::vector<asio::ip::address_v4> gateway;
    std::vector<asio::ip::address_v6> dns6_servers;
    std::vector<asio::ip::address_v4> dns4_servers;
    std::vector<asio::ip::address_v6> ntp6_servers;
    std::vector<asio::ip::address_v4> ntp4_servers;
    std::vector<asio::ip::address_v6> ntp6_multicasts;
    std::vector<std::string> dns_search;
    std::vector<std::string> ntp6_fqdns;
    asio::ip::address_v4 subnet;
    asio::ip::address_v4 broadcast;
    std::vector<uint8_t> dns_search_blob;
    std::vector<uint8_t> ntp6_fqdns_blob;
    std::pair<asio::ip::address_v4, asio::ip::address_v4> dynamic_range;
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
static std::vector<uint8_t> dns_label(const std::string &ds)
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
                throw std::runtime_error("malformed input");
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
            throw std::runtime_error("label too long");
        ret.push_back(len);
        for (size_t j = i.first; j < i.second; ++j)
            ret.push_back(ds[j]);
    }
    // Terminating zero length label.
    if (ret.size())
        ret.push_back(0);
    if (ret.size() > 255)
        throw std::runtime_error("domain name too long");
    return ret;
}

static void create_dns_search_blob(std::vector<std::string> &dns_search,
                                   std::vector<uint8_t> &dns_search_blob)
{
    dns_search_blob.clear();
    for (const auto &dnsname: dns_search) {
        std::vector<uint8_t> lbl;
        try {
            lbl = dns_label(dnsname);
        } catch (const std::runtime_error &e) {
            fmt::print(stderr, "labelizing {} failed: {}\n", dnsname, e.what());
            continue;
        }
        dns_search_blob.insert(dns_search_blob.end(),
                               std::make_move_iterator(lbl.begin()),
                               std::make_move_iterator(lbl.end()));
    }
    // See if the search blob size is too large to encode in a RA
    // dns search option.
    if (dns_search_blob.size() > 8 * 254)
        throw std::runtime_error("dns search list is too long");
    dns_search.clear();
}

// Different from the dns search blob because we pre-include the
// suboption headers.
static void create_ntp6_fqdns_blob(std::vector<std::string> &ntp_fqdns,
                            std::vector<uint8_t> &ntp6_fqdns_blob)
{
    ntp6_fqdns_blob.clear();
    for (const auto &ntpname: ntp_fqdns) {
        std::vector<uint8_t> lbl;
        try {
            lbl = dns_label(ntpname);
        } catch (const std::runtime_error &e) {
            fmt::print(stderr, "labelizing {} failed: {}\n", ntpname, e.what());
            continue;
        }
        ntp6_fqdns_blob.push_back(0);
        ntp6_fqdns_blob.push_back(3);
        uint16_t lblsize = lbl.size();
        ntp6_fqdns_blob.push_back(lblsize >> 8);
        ntp6_fqdns_blob.push_back(lblsize & 0xff);
        ntp6_fqdns_blob.insert(ntp6_fqdns_blob.end(),
                               std::make_move_iterator(lbl.begin()),
                               std::make_move_iterator(lbl.end()));
    }
}

void create_blobs()
{
    for (auto &i: interface_state) {
        create_dns_search_blob(i.second.dns_search, i.second.dns_search_blob);
        create_ntp6_fqdns_blob(i.second.ntp6_fqdns, i.second.ntp6_fqdns_blob);
    }
}

bool emplace_bind(size_t linenum, std::string &&interface, bool is_v4)
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
        fmt::print(stderr, "interface specified at line {} is not bound\n", linenum);
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
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    std::error_code ec;
    auto v6a = asio::ip::address_v6::from_string(v6_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv6 address at line {}: {}\n", linenum, v6_addr);
        return false;
    }
    fmt::print("STATEv6: {} {} {} {}\n", duid, iaid, v6_addr, default_lifetime);
    si->second.duid_mapping.emplace
        (std::make_pair(std::move(duid),
                        std::make_unique<dhcpv6_entry>(iaid, v6a, default_lifetime)));
    return true;
}

bool emplace_dhcp_state(size_t linenum, const std::string &interface, const std::string &macaddr,
                        const std::string &v4_addr, uint32_t default_lifetime)
{
    auto si = interface_state.find(interface);
    if (interface.empty() || si == interface_state.end()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    std::error_code ec;
    auto v4a = asio::ip::address_v4::from_string(v4_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, v4_addr);
        return false;
    }
    fmt::print("STATEv4: {} {} {}\n", macaddr, v4_addr, default_lifetime);
    uint8_t buf[7] = {0};
    for (unsigned i = 0; i < 6; ++i)
        buf[i] = strtol(macaddr.c_str() + 3*i, nullptr, 16);
    si->second.macaddr_mapping.emplace
        (std::make_pair(std::string{reinterpret_cast<char *>(buf), 6},
                        std::make_unique<dhcpv4_entry>(v4a, default_lifetime)));
    return true;
}

bool emplace_dns_server(size_t linenum, const std::string &interface,
                        const std::string &addr, addr_type atype)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    if (atype == addr_type::null) {
        fmt::print(stderr, "Invalid address type at line {}\n", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    std::error_code ec;
    if (atype == addr_type::v4) {
        auto v4a = asio::ip::address_v4::from_string(addr, ec);
        if (!ec) {
            si->second.dns4_servers.emplace_back(std::move(v4a));
            return true;
        } else
            fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, addr);
    } else {
        auto v6a = asio::ip::address_v6::from_string(addr, ec);
        if (!ec) {
            si->second.dns6_servers.emplace_back(std::move(v6a));
            return true;
        } else
            fmt::print(stderr, "Bad IPv6 address at line {}: {}\n", linenum, addr);
    }
    return false;
}

bool emplace_ntp_server(size_t linenum, const std::string &interface,
                        const std::string &addr, addr_type atype)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    if (atype == addr_type::null) {
        fmt::print(stderr, "Invalid address type at line {}\n", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    std::error_code ec;
    if (atype == addr_type::v4) {
        auto v4a = asio::ip::address_v4::from_string(addr, ec);
        if (!ec) {
            si->second.ntp4_servers.emplace_back(std::move(v4a));
            return true;
        } else
            fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, addr);
    } else {
        auto v6a = asio::ip::address_v6::from_string(addr, ec);
        if (!ec) {
            si->second.ntp6_servers.emplace_back(std::move(v6a));
            return true;
        } else
            fmt::print(stderr, "Bad IPv6 address at line {}: {}\n", linenum, addr);
    }
    return false;
}

bool emplace_subnet(size_t linenum, const std::string &interface, const std::string &addr)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    std::error_code ec;
    auto v4a = asio::ip::address_v4::from_string(addr, ec);
    if (!ec) {
        si->second.subnet = std::move(v4a);
        return true;
    } else
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, addr);
    return false;
}

bool emplace_gateway(size_t linenum, const std::string &interface, const std::string &addr)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    std::error_code ec;
    auto v4a = asio::ip::address_v4::from_string(addr, ec);
    if (!ec) {
        si->second.gateway.emplace_back(std::move(v4a));
        return true;
    } else
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, addr);
    return false;
}

bool emplace_broadcast(size_t linenum, const std::string &interface, const std::string &addr)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    std::error_code ec;
    auto v4a = asio::ip::address_v4::from_string(addr, ec);
    if (!ec) {
        si->second.broadcast = std::move(v4a);
        return true;
    } else
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, addr);
    return false;
}

bool emplace_dynamic_range(size_t linenum, const std::string &interface,
                           const std::string &lo_addr, const std::string &hi_addr,
                           uint32_t dynamic_lifetime)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
        return false;
    }
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) return false;
    std::error_code ec;
    auto v4a_lo = asio::ip::address_v4::from_string(lo_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, lo_addr);
        return false;
    }
    auto v4a_hi = asio::ip::address_v4::from_string(hi_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, hi_addr);
        return false;
    }
    if (v4a_lo > v4a_hi)
        std::swap(v4a_lo, v4a_hi);
    si->second.dynamic_range = std::make_pair(std::move(v4a_lo), std::move(v4a_hi));
    si->second.dynamic_lifetime = dynamic_lifetime;
    si->second.use_dynamic_v4 = true;
    return true;
}

bool emplace_dynamic_v6(size_t linenum, const std::string &interface)
{
    if (interface.empty()) {
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
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
        fmt::print(stderr, "No interface specified at line {}\n", linenum);
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

const std::vector<asio::ip::address_v6> &query_dns6_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.dns6_servers;
}

const std::vector<asio::ip::address_v4> &query_dns4_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.dns4_servers;
}

const std::vector<uint8_t> &query_dns6_search_blob(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.dns_search_blob;
}

const std::vector<asio::ip::address_v6> &query_ntp6_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.ntp6_servers;
}

const std::vector<asio::ip::address_v4> &query_ntp4_servers(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.ntp4_servers;
}

const std::vector<uint8_t> &query_ntp6_fqdns_blob(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.ntp6_fqdns_blob;
}

const std::vector<asio::ip::address_v6> &query_ntp6_multicasts(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.ntp6_multicasts;
}

const std::vector<asio::ip::address_v4> &query_gateway(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.gateway;
}

const asio::ip::address_v4 &query_subnet(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.subnet;
}

const asio::ip::address_v4 &query_broadcast(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.broadcast;
}

const std::pair<asio::ip::address_v4, asio::ip::address_v4> &
query_dynamic_range(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.dynamic_range;
}

const std::vector<std::string> &query_dns_search(const std::string &interface)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    return si->second.dns_search;
}

bool query_use_dynamic_v4(const std::string &interface, uint32_t &dynamic_lifetime)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    dynamic_lifetime = si->second.dynamic_lifetime;
    return si->second.use_dynamic_v4;
}

bool query_use_dynamic_v6(const std::string &interface, uint32_t &dynamic_lifetime)
{
    auto si = interface_state.find(interface);
    if (si == interface_state.end()) throw std::runtime_error("no such interface");
    dynamic_lifetime = si->second.dynamic_lifetime;
    return si->second.use_dynamic_v6;
}

bool query_unused_addr(const std::string &interface, const asio::ip::address_v6 &addr)
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

void bound_interfaces_foreach(std::function<void(const std::string&, bool, bool, uint8_t)> fn)
{
    for (const auto &i: interface_state)
        fn(i.first, i.second.use_dhcpv4, i.second.use_dhcpv6, i.second.preference);
}

