// -*- c++ -*-
// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <inttypes.h>
#include <string>
#include <vector>
#include <assert.h>
#include <nk/scopeguard.hpp>
#include <nk/net/ip_address.hpp>
extern "C" {
#include <net/if.h>
#include "nk/log.h"
}

#define MAX_LINE 2048

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

extern int64_t get_current_ts();

struct lease_state_v4
{
    lease_state_v4(const nk::ip_address &addr_, const char *macaddr_, int64_t et)
        : addr(addr_), expire_time(et)
    {
        memcpy(macaddr, macaddr_, 6);
    }
    nk::ip_address addr;
    uint8_t macaddr[6];
    int64_t expire_time;
};

struct lease_state_v6
{
    lease_state_v6(const nk::ip_address &addr_, const char *duid_, size_t duid_len_, uint32_t iaid_, int64_t et)
        : addr(addr_), duid_len(duid_len_), expire_time(et), iaid(iaid_)
    {
        memcpy(duid, duid_, duid_len_);
    }
    nk::ip_address addr;
    size_t duid_len;
    int64_t expire_time;
    uint32_t iaid;
    char duid[128]; // not null terminated
};

// The vectors here are sorted by addr.
struct dynlease_map_v4
{
    char ifname[IFNAMSIZ];
    std::vector<lease_state_v4> state;
};
struct dynlease_map_v6
{
    char ifname[IFNAMSIZ];
    std::vector<lease_state_v6> state;
};

// Maps interfaces to lease data.
static std::vector<dynlease_map_v4> dyn_leases_v4;
static std::vector<dynlease_map_v6> dyn_leases_v6;

std::vector<lease_state_v4> *lease_state4_by_name(const char *interface)
{
    for (auto &i: dyn_leases_v4) {
        if (!strcmp(i.ifname, interface)) {
            return &i.state;
        }
    }
    return nullptr;
}

std::vector<lease_state_v6> *lease_state6_by_name(const char *interface)
{
    for (auto &i: dyn_leases_v6) {
        if (!strcmp(i.ifname, interface)) {
            return &i.state;
        }
    }
    return nullptr;
}

static auto create_new_dynlease4_state(const char *interface)
{
    dynlease_map_v4 nn;
    memccpy(nn.ifname, interface, 0, sizeof nn.ifname);
    dyn_leases_v4.emplace_back(std::move(nn));
    return &dyn_leases_v4.back().state;
}

static auto create_new_dynlease6_state(const char *interface)
{
    dynlease_map_v6 nn;
    memccpy(nn.ifname, interface, 0, sizeof nn.ifname);
    dyn_leases_v6.emplace_back(std::move(nn));
    return &dyn_leases_v6.back().state;
}

static bool emplace_dynlease4_state(size_t linenum, const char *interface,
                                    const char *v4_addr, const char *macaddr,
                                    int64_t expire_time)
{
    auto is = lease_state4_by_name(interface);
    if (!is) is = create_new_dynlease4_state(interface);
    nk::ip_address ipa;
    if (!ipa.from_string(v4_addr)) {
        log_line("Bad IP address at line %zu: %s\n", linenum, v4_addr);
        return false;
    }
    // We won't get duplicates unless someone manually edits the file.  If they do,
    // then they get what they deserve.
    is->emplace_back(ipa, macaddr, expire_time);
    return true;
}

static bool emplace_dynlease6_state(size_t linenum, const char *interface,
                                    const char *v6_addr,
                                    const char *duid, size_t duid_len,
                                    uint32_t iaid, int64_t expire_time)
{
    auto is = lease_state6_by_name(interface);
    if (!is) is = create_new_dynlease6_state(interface);
    nk::ip_address ipa;
    if (!ipa.from_string(v6_addr)) {
        log_line("Bad IP address at line %zu: %s\n", linenum, v6_addr);
        return false;
    }
    is->emplace_back(ipa, duid, duid_len, iaid, expire_time);
    return true;
}

size_t dynlease4_count(const char *interface)
{
    auto is = lease_state4_by_name(interface);
    if (!is) return 0;
    return is->size();
}

size_t dynlease6_count(const char *interface)
{
    auto is = lease_state6_by_name(interface);
    if (!is) return 0;
    return is->size();
}

void dynlease_gc()
{
    for (auto &i: dyn_leases_v4) {
        std::erase_if(i.state, [](lease_state_v4 &x){ return x.expire_time < get_current_ts(); });
    }
    for (auto &i: dyn_leases_v6) {
        std::erase_if(i.state, [](lease_state_v6 &x){ return x.expire_time < get_current_ts(); });
    }
}

bool dynlease4_add(const char *interface, const nk::ip_address &v4_addr, const uint8_t *macaddr,
                   int64_t expire_time)
{
    auto is = lease_state4_by_name(interface);
    if (!is) is = create_new_dynlease4_state(interface);

    for (auto &i: *is) {
        if (i.addr == v4_addr) {
            if (memcmp(&i.macaddr, macaddr, 6) == 0) {
                i.expire_time = expire_time;
                return true;
            }
            return false;
        }
    }
    char tmac[6];
    memcpy(tmac, macaddr, sizeof tmac);
    is->emplace_back(std::move(v4_addr), tmac, expire_time);
    return true;
}

static bool duid_compare(const char *a, size_t al, const char *b, size_t bl)
{
    return al == bl && !memcmp(a, b, al);
}

bool dynlease6_add(const char *interface, const nk::ip_address &v6_addr,
                   const char *duid, size_t duid_len, uint32_t iaid, int64_t expire_time)
{
    auto is = lease_state6_by_name(interface);
    if (!is) is = create_new_dynlease6_state(interface);

    for (auto &i: *is) {
        if (i.addr == v6_addr) {
            if (!duid_compare(i.duid, i.duid_len, duid, duid_len) && i.iaid == iaid) {
                i.expire_time = expire_time;
                return true;
            }
            return false;
        }
    }
    is->emplace_back(std::move(v6_addr), duid, duid_len, iaid, expire_time);
    return true;
}

nk::ip_address dynlease4_query_refresh(const char *interface, const uint8_t *macaddr,
                                       int64_t expire_time)
{
    auto is = lease_state4_by_name(interface);
    if (!is) return {};

    for (auto &i: *is) {
        if (memcmp(&i.macaddr, macaddr, 6) == 0) {
            i.expire_time = expire_time;
            return i.addr;
        }
    }
    return {};
}

nk::ip_address dynlease6_query_refresh(const char *interface, const char *duid, size_t duid_len,
                                       uint32_t iaid, int64_t expire_time)
{
    auto is = lease_state6_by_name(interface);
    if (!is) return {};

    for (auto &i: *is) {
        if (!duid_compare(i.duid, i.duid_len, duid, duid_len) && i.iaid == iaid) {
            i.expire_time = expire_time;
            return i.addr;
        }
    }
    return {};
}

bool dynlease4_exists(const char *interface, const nk::ip_address &v4_addr, const uint8_t *macaddr)
{
    auto is = lease_state4_by_name(interface);
    if (!is) return false;

    for (auto &i: *is) {
        if (i.addr == v4_addr && memcmp(&i.macaddr, macaddr, 6) == 0) {
            return get_current_ts() < i.expire_time;
        }
    }
    return false;
}

bool dynlease6_exists(const char *interface, const nk::ip_address &v6_addr,
                      const char *duid, size_t duid_len, uint32_t iaid)
{
    auto is = lease_state6_by_name(interface);
    if (!is) return false;

    for (auto &i: *is) {
        if (i.addr == v6_addr && !duid_compare(i.duid, i.duid_len, duid, duid_len) && i.iaid == iaid) {
            return get_current_ts() < i.expire_time;
        }
    }
    return false;
}

bool dynlease4_del(const char *interface, const nk::ip_address &v4_addr, const uint8_t *macaddr)
{
    auto is = lease_state4_by_name(interface);
    if (!is) return false;

    for (auto i = is->begin(), iend = is->end(); i != iend; ++i) {
        if (i->addr == v4_addr && memcmp(&i->macaddr, macaddr, 6) == 0) {
            is->erase(i);
            return true;
        }
    }
    return false;
}

bool dynlease6_del(const char *interface, const nk::ip_address &v6_addr,
                  const char *duid, size_t duid_len, uint32_t iaid)
{
    auto is = lease_state6_by_name(interface);
    if (!is) return false;

    for (auto i = is->begin(), iend = is->end(); i != iend; ++i) {
        if (i->addr == v6_addr && !duid_compare(i->duid, i->duid_len, duid, duid_len) && i->iaid == iaid) {
            is->erase(i);
            return true;
        }
    }
    return false;
}

bool dynlease_unused_addr(const char *interface, const nk::ip_address &addr)
{
    auto is = lease_state6_by_name(interface);
    if (!is) return true;

    for (auto i = is->begin(), iend = is->end(); i != iend; ++i) {
        if (i->addr == addr)
            return false;
    }
    return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

bool dynlease_serialize(const char *path)
{
    char tmp_path[PATH_MAX];
    size_t pathlen = strlen(path);
    if (pathlen + 5 > sizeof tmp_path) abort();
    memcpy(tmp_path, path, pathlen);
    memcpy(tmp_path + pathlen, ".tmp", 5);

    const auto f = fopen(tmp_path, "w");
    if (!f) {
        log_line("%s: failed to open '%s' for dynamic lease serialization\n",
                 __func__, path);
        return false;
    }
    SCOPE_EXIT{ fclose(f); unlink(tmp_path); };
    for (const auto &i: dyn_leases_v4) {
        const auto iface = i.ifname;
        const auto &ls = i.state;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            if (get_current_ts() >= j.expire_time)
                continue;
            if (fprintf(f, "v4 %s %s %2.x%2.x%2.x%2.x%2.x%2.x %zu\n",
                        iface, j.addr.to_string().c_str(),
                        j.macaddr[0], j.macaddr[1], j.macaddr[2],
                        j.macaddr[3], j.macaddr[4], j.macaddr[5], j.expire_time) < 0) {
                log_line("%s: fprintf failed: %s\n", __func__, strerror(errno));
                return false;
            }
        }
    }
    for (const auto &i: dyn_leases_v6) {
        const auto iface = i.ifname;
        const auto &ls = i.state;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            if (get_current_ts() >= j.expire_time)
                continue;

            if (fprintf(f, "v6 %s %s ", iface, j.addr.to_string().c_str()) < 0) goto err0;
            for (const auto &k: j.duid) if (fprintf(f, "%.2hhx", k) < 0) goto err0;
            if (fprintf(f, " %u %lu\n", j.iaid, j.expire_time) < 0) goto err0;
            continue;
        err0:
            log_line("%s: fprintf failed: %s\n", __func__, strerror(errno));
            return false;
        }
    }
    if (fflush(f)) {
        log_line("%s: fflush failed: %s\n", __func__, strerror(errno));
        return false;
    }
    const auto fd = fileno(f);
    if (fdatasync(fd)) {
        log_line("%s: fdatasync failed: %s\n", __func__, strerror(errno));
        return false;
    }
    if (rename(tmp_path, path)) {
        log_line("%s: rename failed: %s\n", __func__, strerror(errno));
        return false;
    }
    return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

struct dynlease_parse_state {
    dynlease_parse_state() : st(nullptr), cs(0), parse_error(false) {}
    void newline() {
        memset(duid, 0, sizeof duid);
        duid_len = 0;
        memset(macaddr, 0, sizeof macaddr);
        memset(v4_addr, 0, sizeof v4_addr);
        memset(v6_addr, 0, sizeof v6_addr);
        memset(interface, 0, sizeof interface);
        iaid = 0;
        expire_time = 0;
        parse_error = false;
    }
    const char *st;
    int cs;

    int64_t expire_time;
    size_t duid_len;
    uint32_t iaid;
    bool parse_error;
    char duid[128];
    char interface[IFNAMSIZ];
    char v6_addr[48];
    char v4_addr[16];
    char macaddr[6];
};

static inline void lc_string_inplace(char *s, size_t len)
{
    for (size_t i = 0; i < len; ++i) s[i] = tolower(s[i]);
}

static void assign_strbuf(char *dest, size_t *destlen, size_t maxlen, const char *start, const char *end)
{
    ptrdiff_t d = end - start;
    size_t l = (size_t)d;
    if (d < 0 || l >= maxlen) abort();
    *(char *)mempcpy(dest, start, l) = 0;
    if (destlen) *destlen = l;
}

%%{
    machine dynlease_line_m;
    access cps.;

    action St { cps.st = p; }

    action InterfaceEn {
        assign_strbuf(cps.interface, nullptr, sizeof cps.interface, cps.st, p);
    }
    action DuidEn {
        assign_strbuf(cps.duid, &cps.duid_len, sizeof cps.duid, cps.st, p);
        lc_string_inplace(cps.duid, cps.duid_len);
    }
    action IaidEn {
        char buf[64];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, p, (size_t)blen); buf[blen] = 0;
        if (sscanf(cps.st, SCNu32, &cps.iaid) != 1) {
            cps.parse_error = true;
            fbreak;
        }
    }
    action MacAddrEn {
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof cps.macaddr) {
            cps.parse_error = true;
            fbreak;
        }
        memcpy(cps.macaddr, cps.st, 6);
        lc_string_inplace(cps.macaddr, sizeof cps.macaddr);
    }
    action V4AddrEn {
        size_t l;
        assign_strbuf(cps.v4_addr, &l, sizeof cps.v4_addr, cps.st, p);
        lc_string_inplace(cps.v4_addr, l);
    }
    action V6AddrEn {
        size_t l;
        assign_strbuf(cps.v6_addr, &l, sizeof cps.v6_addr, cps.st, p);
        lc_string_inplace(cps.v6_addr, l);
    }
    action ExpireTimeEn {
        char buf[64];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, p, (size_t)blen); buf[blen] = 0;
        if (sscanf(cps.st, SCNi64, &cps.expire_time) != 1) {
            cps.parse_error = true;
            fbreak;
        }
    }

    action V4EntryEn {
        emplace_dynlease4_state(linenum, cps.interface, cps.v4_addr,
                                cps.macaddr, cps.expire_time);
    }
    action V6EntryEn {
        emplace_dynlease6_state(linenum, cps.interface, cps.v6_addr,
                                cps.duid, cps.duid_len, cps.iaid, cps.expire_time);
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

static int do_parse_dynlease_line(dynlease_parse_state &cps, const char *p, size_t plen,
                             const size_t linenum)
{
    const char *pe = p + plen;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if (cps.parse_error) return -1;
    if (cps.cs >= dynlease_line_m_first_final)
        return 1;
    if (cps.cs == dynlease_line_m_error)
        return -1;
    return -2;
}

bool dynlease_deserialize(const char *path)
{
    char buf[MAX_LINE];
    const auto f = fopen(path, "r");
    if (!f) {
        log_line("%s: failed to open '%s' for dynamic lease deserialization\n",
                 __func__, path);
        return false;
    }
    SCOPE_EXIT{ fclose(f); };
    dyn_leases_v4.clear();
    dyn_leases_v6.clear();
    size_t linenum = 0;
    dynlease_parse_state ps;
    while (!feof(f)) {
        if (!fgets(buf, sizeof buf, f)) {
            if (!feof(f))
                log_line("%s: io error fetching line of '%s'\n", __func__, path);
            break;
        }
        auto llen = strlen(buf);
        if (llen == 0)
            continue;
        if (buf[llen-1] == '\n')
            buf[--llen] = 0;
        ++linenum;
        ps.newline();
        const auto r = do_parse_dynlease_line(ps, buf, llen, linenum);
        if (r < 0) {
            if (r == -2)
                log_line("%s: Incomplete dynlease at line %zu; ignoring\n",
                         __func__, linenum);
            else
                log_line("%s: Malformed dynlease at line %zu; ignoring.\n",
                         __func__, linenum);
            continue;
        }
    }
    return true;
}

