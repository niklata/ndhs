// -*- c++ -*-
// Copyright 2016-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <inttypes.h>
#include "dhcp_state.hpp"
extern "C" {
#include "ipaddr.h"
#include "nk/log.h"
#include <net/if.h>
}
extern void set_user_runas(const char *username, size_t len);
extern void set_chroot_path(const char *path, size_t len);
extern void set_s6_notify_fd(int fd);

#define MAX_LINE 2048

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0), last_addr(addr_type::null), ifindex(-1), default_lifetime(7200),
                        default_preference(0), parse_error(false) {}
    void newline() {
        // Do NOT clear ifindex here; it is stateful between lines!
        memset(duid, 0, sizeof duid);
        memset(ipaddr, 0, sizeof ipaddr);
        memset(ipaddr2, 0, sizeof ipaddr2);
        memset(macaddr, 0, sizeof macaddr);
        duid_len = 0;
        last_addr = addr_type::null;
        iaid = 0;
        parse_error = false;
    }
    const char *st;
    int cs;

    char duid[128];
    char ipaddr[48];
    char ipaddr2[48];
    uint8_t macaddr[6];
    size_t duid_len;
    addr_type last_addr;
    int ifindex;
    uint32_t iaid;
    uint32_t default_lifetime;
    uint8_t default_preference;
    bool parse_error;
};

#define MARKED_STRING() cps.st, (p > cps.st ? static_cast<size_t>(p - cps.st) : 0)

#include "parsehelp.h"

bool string_to_ipaddr(in6_addr *r, const char *s, size_t linenum)
{
    if (!ipaddr_from_string(r, s)) {
        log_line("ip address on line %zu is invalid\n", linenum);
        return false;
    }
    return true;
}

%%{
    machine cfg_line_m;
    access cps.;

    action St { cps.st = p; }

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
        memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
        if (sscanf(buf, "%" SCNu32, &cps.iaid) != 1) {
            cps.parse_error = true;
            fbreak;
        }
    }
    action MacAddrEn {
        char buf[32];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps.parse_error = true;
            fbreak;
        }
        *(char *)mempcpy(buf, cps.st, (size_t)blen) = 0;
        if (sscanf(buf, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                   &cps.macaddr[0], &cps.macaddr[1], &cps.macaddr[2],
                   &cps.macaddr[3], &cps.macaddr[4], &cps.macaddr[5]) != 6) {
            cps.parse_error = true;
            fbreak;
        }
    }
    action V4AddrEn {
        size_t l;
        assign_strbuf(cps.ipaddr, &l, sizeof cps.ipaddr, cps.st, p);
        lc_string_inplace(cps.ipaddr, l);
        cps.last_addr = addr_type::v4;
    }
    action V6AddrEn {
        size_t l;
        assign_strbuf(cps.ipaddr, &l, sizeof cps.ipaddr, cps.st, p);
        lc_string_inplace(cps.ipaddr, l);
        cps.last_addr = addr_type::v6;
    }
    action Bind4En {
        char buf[IFNAMSIZ];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= IFNAMSIZ) {
            log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, cps.st, (size_t)blen);
        buf[blen] = 0;
        emplace_bind4(linenum, buf);
    }
    action Bind6En {
        char buf[IFNAMSIZ];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= IFNAMSIZ) {
            log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, cps.st, (size_t)blen);
        buf[blen] = 0;
        emplace_bind6(linenum, buf);
    }
    action UserEn { set_user_runas(MARKED_STRING()); }
    action ChrootEn { set_chroot_path(MARKED_STRING()); }
    action S6NotifyEn {
        char buf[64];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
        int fd;
        if (sscanf(buf, "%d", &fd) != 1) {
            cps.parse_error = true;
            fbreak;
        }
        set_s6_notify_fd(fd);
    }
    action DefLifeEn {
        char buf[64];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
        if (sscanf(buf, "%" SCNu32, &cps.default_lifetime) != 1) {
            cps.parse_error = true;
            fbreak;
        }
    }
    action DefPrefEn {
        char buf[64];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof buf) {
            cps.parse_error = true;
            fbreak;
        }
        memcpy(buf, cps.st, (size_t)blen); buf[blen] = 0;
        if (sscanf(buf, "%" SCNu8, &cps.default_preference) != 1) {
            log_line("default_preference on line %zu out of range [0,255]\n", linenum);
            cps.parse_error = true;
            fbreak;
        }
    }
    action InterfaceEn {
        char interface[IFNAMSIZ];
        ptrdiff_t blen = p - cps.st;
        if (blen < 0 || blen >= (int)sizeof interface) {
            log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
            cps.parse_error = true;
            fbreak;
        }
        memcpy(interface, cps.st, (size_t)blen);
        interface[blen] = 0;
        cps.ifindex = emplace_interface(linenum, interface, cps.default_preference);
    }
    action DnsServerEn {
        in6_addr t;
        if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        emplace_dns_server(linenum, cps.ifindex, &t, cps.last_addr);
    }
    action DnsSearchEn {
        emplace_dns_search(linenum, cps.ifindex, MARKED_STRING());
    }
    action NtpServerEn {
        in6_addr t;
        if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        emplace_ntp_server(linenum, cps.ifindex, &t, cps.last_addr);
    }
    action GatewayEn {
        in6_addr t;
        if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        emplace_gateway_v4(linenum, cps.ifindex, &t);
    }
    action DynRangePreEn {
        memcpy(cps.ipaddr2, cps.ipaddr, sizeof cps.ipaddr2);
    }
    action DynRangeEn {
        in6_addr tlo;
        if (!string_to_ipaddr(&tlo, cps.ipaddr2, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        in6_addr thi;
        if (!string_to_ipaddr(&thi, cps.ipaddr, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        emplace_dynamic_range(linenum, cps.ifindex, &tlo, &thi, cps.default_lifetime);
    }
    action DynamicV6En {
        emplace_dynamic_v6(linenum, cps.ifindex);
    }
    action V4EntryEn {
        in6_addr t;
        if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        emplace_dhcp4_state(linenum, cps.ifindex, cps.macaddr, &t, cps.default_lifetime);
    }
    action V6EntryEn {
        in6_addr t;
        if (!string_to_ipaddr(&t, cps.ipaddr, linenum)) {
            cps.parse_error = true;
            fbreak;
        }
        emplace_dhcp6_state(linenum, cps.ifindex,
                            cps.duid, cps.duid_len,
                            cps.iaid, &t, cps.default_lifetime);
    }

    duid = xdigit+ >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;

    comment = space* ('#' any*)?;
    tcomment = (space+ '#' any*)?;
    bind4 = space* 'bind4' (space+ alnum+ >St %Bind4En)+ tcomment;
    bind6 = space* 'bind6' (space+ alnum+ >St %Bind6En)+ tcomment;
    user = space* 'user' space+ graph+ >St %UserEn tcomment;
    chroot = space* 'chroot' space+ graph+ >St %ChrootEn tcomment;
    s6_notify = space* 's6_notify' space+ digit+ >St %S6NotifyEn tcomment;
    default_lifetime = space* 'default_lifetime' space+ digit+ >St %DefLifeEn tcomment;
    default_preference = space* 'default_preference' space+ digit+ >St %DefPrefEn tcomment;
    interface = space* 'interface' space+ alnum+ >St %InterfaceEn tcomment;
    dns_server = space* 'dns_server' (space+ (v4_addr | v6_addr) %DnsServerEn)+ tcomment;
    dns_search = space* 'dns_search' (space+ graph+ >St %DnsSearchEn)+ tcomment;
    ntp_server = space* 'ntp_server' (space+ (v4_addr | v6_addr) %NtpServerEn)+ tcomment;
    gateway = space* 'gateway' space+ v4_addr %GatewayEn tcomment;
    dynamic_range = space* 'dynamic_range' space+ v4_addr %DynRangePreEn space+ v4_addr %DynRangeEn tcomment;
    dynamic_v6 = space* 'dynamic_v6' %DynamicV6En tcomment;
    v4_entry = space* 'v4' space+ macaddr space+ v4_addr tcomment;
    v6_entry = space* 'v6' space+ duid space+ iaid space+ v6_addr tcomment;

    main := comment | bind4 | bind6 | user | chroot | s6_notify | default_lifetime | default_preference
          | interface | dns_server | dns_search | ntp_server | gateway
          | dynamic_range | dynamic_v6 | v6_entry %V6EntryEn | v4_entry %V4EntryEn;
}%%

%% write data;

static int do_parse_cfg_line(cfg_parse_state &cps, const char *p, size_t plen,
                             const size_t linenum)
{
    const char *pe = p + plen;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if (cps.parse_error) return -1;
    if (cps.cs >= cfg_line_m_first_final)
        return 1;
    if (cps.cs == cfg_line_m_error)
        return -1;
    return -2;
}

bool parse_config(const char *path)
{
    bool ret = false;
    size_t linenum = 0;
    cfg_parse_state ps;
    char buf[MAX_LINE];
    FILE *f = fopen(path, "r");
    if (!f) {
        log_line("%s: failed to open config file '%s' for read: %s\n",
                 __func__, path, strerror(errno));
        goto out0;
    }
    while (!feof(f)) {
        if (!fgets(buf, sizeof buf, f)) {
            if (!feof(f)) {
                log_line("%s: io error fetching line of '%s'\n", __func__, path);
                goto out1;
            }
            break;
        }
        auto llen = strlen(buf);
        if (llen == 0)
            continue;
        if (buf[llen-1] == '\n')
            buf[--llen] = 0;
        ++linenum;
        ps.newline();
        const auto r = do_parse_cfg_line(ps, buf, llen, linenum);
        if (r < 0) {
            if (r == -2)
                log_line("%s: Incomplete configuration at line %zu; ignoring\n",
                         __func__, linenum);
            else
                log_line("%s: Malformed configuration at line %zu; ignoring.\n",
                         __func__, linenum);
            continue;
        }
    }
    create_blobs();
    ret = true;
out1:
    fclose(f);
out0:
    return ret;
}

