#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <format.hpp>
#include <nk/scopeguard.hpp>
#include <nk/str_to_int.hpp>
#include <asio.hpp>

#define MAX_LINE 2048

using aia6 = asio::ip::address_v6;
using aia4 = asio::ip::address_v4;

struct lease_state_v4
{
    lease_state_v4(aia4 &&addr_, const std::string &ma, int64_t et)
        : addr(std::move(addr_)), expire_time(et)
    {
        assert(ma.size() == 6);
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    lease_state_v4(aia4 &&addr_, const uint8_t *ma, int64_t et)
        : addr(std::move(addr_)), expire_time(et)
    {
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    lease_state_v4(const aia4 &addr_, const std::string &ma, int64_t et)
        : addr(addr_), expire_time(et)
    {
        assert(ma.size() == 6);
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    lease_state_v4(const aia4 &addr_, const uint8_t *ma, int64_t et)
        : addr(addr_), expire_time(et)
    {
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    aia4 addr;
    uint8_t macaddr[6];
    int64_t expire_time;
};

struct lease_state_v6
{
    lease_state_v6(aia6 &&addr_, std::string &&duid_, uint32_t iaid_, int64_t et)
        : addr(std::move(addr_)), duid(std::move(duid_)), iaid(iaid_), expire_time(et) {}
    lease_state_v6(const aia6 &addr_, const std::string &duid_, uint32_t iaid_, int64_t et)
        : addr(addr_), duid(duid_), iaid(iaid_), expire_time(et) {}
    aia6 addr;
    std::string duid;
    uint32_t iaid;
    int64_t expire_time;
};

// These vectors are sorted by addr.
using dynlease_map_v4 = std::vector<lease_state_v4>;
using dynlease_map_v6 = std::vector<lease_state_v6>;

// Maps interfaces to lease data.
static std::unordered_map<std::string, dynlease_map_v4> dyn_leases_v4;
static std::unordered_map<std::string, dynlease_map_v6> dyn_leases_v6;

static bool emplace_dynlease_state(size_t linenum, std::string &&interface,
                                   std::string &&v4_addr, const std::string &macaddr,
                                   int64_t expire_time)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) {
        auto x = dyn_leases_v4.emplace(std::make_pair(std::move(interface), dynlease_map_v4()));
        si = x.first;
    }
    std::error_code ec;
    auto v4a = aia4::from_string(v4_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, v4_addr);
        return false;
    }
    // We won't get duplicates unless someone manually edits the file.  If they do,
    // then they get what they deserve.
    si->second.emplace_back(std::move(v4a), macaddr, expire_time);
    return true;
}

static bool emplace_dynlease_state(size_t linenum, std::string &&interface,
                                   std::string &&v6_addr, std::string &&duid,
                                   uint32_t iaid, int64_t expire_time)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) {
        auto x = dyn_leases_v6.emplace(std::make_pair(std::move(interface), dynlease_map_v6()));
        si = x.first;
    }
    std::error_code ec;
    auto v6a = aia6::from_string(v6_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv6 address at line {}: {}\n", linenum, v6_addr);
        return false;
    }
    si->second.emplace_back(std::move(v6a), std::move(duid), iaid, expire_time);
    return true;
}

size_t dynlease4_count(const std::string &interface)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end())
        return 0;
    return si->second.size();
}

size_t dynlease6_count(const std::string &interface)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end())
        return 0;
    return si->second.size();
}

bool dynlease_add(const std::string &interface, const aia4 &v4_addr, const uint8_t *macaddr,
                  int64_t expire_time)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) {
        auto x = dyn_leases_v4.emplace(std::make_pair(interface, dynlease_map_v4()));
        si = x.first;
    }

    for (auto &i: si->second) {
        if (i.addr == v4_addr) {
            if (memcmp(&i.macaddr, macaddr, 6) == 0) {
                i.expire_time = expire_time;
                return true;
            }
            return false;
        }
    }
    si->second.emplace_back(std::move(v4_addr), macaddr, expire_time);
    return true;
}

bool dynlease_add(const std::string &interface, const aia6 &v6_addr,
                  const std::string &duid, uint32_t iaid, int64_t expire_time)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) {
        auto x = dyn_leases_v6.emplace(std::make_pair(std::move(interface), dynlease_map_v6()));
        si = x.first;
    }

    for (auto &i: si->second) {
        if (i.addr == v6_addr) {
            if (i.duid == duid && i.iaid == iaid) {
                i.expire_time = expire_time;
                return true;
            }
            return false;
        }
    }
    si->second.emplace_back(std::move(v6_addr), duid, iaid, expire_time);
    return true;
}

const aia4 &dynlease_query_refresh(const std::string &interface, const uint8_t *macaddr,
                                   int64_t expire_time)
{
    static aia4 blank{};
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) return blank;

    for (auto &i: si->second) {
        if (memcmp(&i.macaddr, macaddr, 6) == 0) {
            i.expire_time = expire_time;
            return i.addr;
        }
        return blank;
    }
    return blank;
}

const aia6 &dynlease_query_refresh(const std::string &interface, const std::string &duid,
                                   uint32_t iaid, int64_t expire_time)
{
    static aia6 blank{};
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return blank;

    for (auto &i: si->second) {
        if (i.duid == duid && i.iaid == iaid) {
            i.expire_time = expire_time;
            return i.addr;
        }
        return blank;
    }
    return blank;
}

bool dynlease_exists(const std::string &interface, const aia4 &v4_addr, const uint8_t *macaddr)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) return false;

    for (auto &i: si->second) {
        if (i.addr == v4_addr && memcmp(&i.macaddr, macaddr, 6) == 0) {
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            return ts.tv_sec < i.expire_time;
        }
    }
    return false;
}

bool dynlease_exists(const std::string &interface, const aia6 &v6_addr,
                     const std::string &duid, uint32_t iaid)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return false;

    for (auto &i: si->second) {
        if (i.addr == v6_addr && i.duid == duid && i.iaid == iaid) {
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            return ts.tv_sec < i.expire_time;
        }
    }
    return false;
}

bool dynlease_del(const std::string &interface, const aia4 &v4_addr, const uint8_t *macaddr)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) return false;

    const auto iend = si->second.end();
    for (auto i = si->second.begin(); i != iend; ++i) {
        if (i->addr == v4_addr && memcmp(&i->macaddr, macaddr, 6) == 0) {
            si->second.erase(i);
            return true;
        }
    }
    return false;
}

bool dynlease_del(const std::string &interface, const aia6 &v6_addr,
                  const std::string &duid, uint32_t iaid)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return false;

    const auto iend = si->second.end();
    for (auto i = si->second.begin(); i != iend; ++i) {
        if (i->addr == v6_addr && i->duid == duid && i->iaid == iaid) {
            si->second.erase(i);
            return true;
        }
    }
    return false;
}

bool dynlease_unused_addr(const std::string &interface, const asio::ip::address_v6 &addr)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return true;

    const auto iend = si->second.end();
    for (auto i = si->second.begin(); i != iend; ++i) {
        if (i->addr == addr)
            return false;
    }
    return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

bool dynlease_serialize(const std::string &path)
{
    const auto tmp_path = path + ".tmp";
    const auto f = fopen(tmp_path.c_str(), "w");
    if (!f) {
        fmt::print(stderr, "{}: failed to open '{}' for dynamic lease serialization\n",
                   __func__, path);
        return false;
    }
    SCOPE_EXIT{ fclose(f); unlink(tmp_path.c_str()); };
    std::string wbuf;
    for (const auto &i: dyn_leases_v4) {
        const auto &iface = i.first;
        const auto &ls = i.second;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            if (ts.tv_sec >= j.expire_time)
                continue;

            wbuf = fmt::format("v4 {} {} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x} {}\n",
                               iface, j.addr.to_string(),
                               j.macaddr[0], j.macaddr[1], j.macaddr[2],
                               j.macaddr[3], j.macaddr[4], j.macaddr[5], j.expire_time);
            const auto fs = fwrite(wbuf.c_str(), wbuf.size(), 1, f);
            if (fs != wbuf.size()) {
                fmt::print(stderr, "{}: short write {} < {}\n", __func__, fs, wbuf.size());
                return false;
            }
        }
    }
    for (const auto &i: dyn_leases_v6) {
        const auto &iface = i.first;
        const auto &ls = i.second;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            if (ts.tv_sec >= j.expire_time)
                continue;

            wbuf = fmt::format("v6 {} {} ", iface, j.addr.to_string());
            for (const auto &k: j.duid)
                wbuf.append(fmt::format("{:02x}", k));
            wbuf.append(" {} {}\n", j.iaid, j.expire_time);
            const auto fs = fwrite(wbuf.c_str(), wbuf.size(), 1, f);
            if (fs != wbuf.size()) {
                fmt::print(stderr, "{}: short write {} < {}\n", __func__, fs, wbuf.size());
                return false;
            }
        }
    }
    if (fflush(f)) {
        fmt::print(stderr, "{}: fflush failed: {}\n", __func__, strerror(errno));
        return false;
    }
    const auto fd = fileno(f);
    if (fdatasync(fd)) {
        fmt::print(stderr, "{}: fdatasync failed: {}\n", __func__, strerror(errno));
        return false;
    }
    if (rename(tmp_path.c_str(), path.c_str())) {
        fmt::print(stderr, "{}: rename failed: {}\n", __func__, strerror(errno));
        return false;
    }
    return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0) {}
    void newline() {
        duid.clear();
        macaddr.clear();
        v4_addr.clear();
        v6_addr.clear();
        interface.clear();
        iaid = 0;
        expire_time = 0;
    }
    const char *st;
    int cs;

    std::string duid;
    std::string macaddr;
    std::string v4_addr;
    std::string v6_addr;
    std::string interface;
    int64_t expire_time;
    uint32_t iaid;
};

static inline std::string lc_string(const char *s, size_t slen)
{
    auto r = std::string(s, slen);
    for (auto &i: r) i = tolower(i);
    return r;
}

%%{
    machine dynlease_line_m;
    access cps.;

    action St { cps.st = p; }

    action InterfaceEn { cps.interface = std::string(cps.st, p - cps.st); }
    action DuidEn { cps.duid = lc_string(cps.st, p - cps.st); }
    action IaidEn { cps.iaid = nk::str_to_u32(lc_string(cps.st, p - cps.st)); }
    action MacAddrEn { cps.macaddr = lc_string(cps.st, p - cps.st); }
    action V4AddrEn { cps.v4_addr = lc_string(cps.st, p - cps.st); }
    action V6AddrEn { cps.v6_addr = lc_string(cps.st, p - cps.st); }
    action ExpireTimeEn { cps.expire_time = nk::str_to_s64(std::string(cps.st, p - cps.st)); }

    action V4EntryEn {
        emplace_dynlease_state(linenum, std::move(cps.interface), std::move(cps.v4_addr),
                               cps.macaddr, cps.expire_time);
    }
    action V6EntryEn {
        emplace_dynlease_state(linenum, std::move(cps.interface), std::move(cps.v6_addr),
                               std::move(cps.duid), cps.iaid, cps.expire_time);
    }

    interface = alnum+ >St %InterfaceEn;
    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;
    expire_time = digit+ >St %ExpireTimeEn;

    v4_entry = space* 'v4' space+ interface space+ v4_addr space+ macaddr space+ expire_time space*;
    v6_entry = space* 'v6' space+ interface space+ v6_addr space+ duid space+ iaid space+ expire_time space*;

    main := v4_entry %V4EntryEn | v6_entry %V6EntryEn;
}%%

%% write data;

static int do_parse_dynlease_line(cfg_parse_state &cps, const char *p, size_t plen,
                             const size_t linenum)
{
    const char *pe = p + plen;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if (cps.cs >= dynlease_line_m_first_final)
        return 1;
    if (cps.cs == dynlease_line_m_error)
        return -1;
    return -2;
}

bool dynlease_deserialize(const std::string &path)
{
    char buf[MAX_LINE];
    const auto f = fopen(path.c_str(), "r");
    if (!f) {
        fmt::print(stderr, "{}: failed to open '{}' for dynamic lease deserialization\n",
                   __func__, path);
        return false;
    }
    SCOPE_EXIT{ fclose(f); };
    dyn_leases_v4.clear();
    dyn_leases_v6.clear();
    size_t linenum = 0;
    cfg_parse_state ps;
    while (!feof(f)) {
        auto fsv = fgets(buf, sizeof buf, f);
        auto llen = strlen(buf);
        if (buf[llen-1] == '\n')
            buf[--llen] = 0;
        ++linenum;
        if (!fsv) {
            if (!feof(f))
                fmt::print(stderr, "{}: io error fetching line of '{}'\n", __func__, path);
            break;
        }
        if (llen == 0)
            continue;
        ps.newline();
        auto r = do_parse_dynlease_line(ps, buf, llen, linenum);
        if (r < 0) {
            if (r == -2)
                fmt::print(stderr, "{}: Incomplete dynlease at line {}; ignoring\n",
                           __func__, linenum);
            else
                fmt::print(stderr, "{}: Malformed dynlease at line {}; ignoring.\n",
                           __func__, linenum);
            continue;
        }
    }
    return true;
}

