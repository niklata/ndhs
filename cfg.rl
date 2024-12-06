// Copyright 2016-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <string>
#include <cstdio>
#include <nk/scopeguard.hpp>
#include <nk/from_string.hpp>
#include "dhcp_state.hpp"
extern "C" {
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

extern void create_dns_search_blob();

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0), last_addr(addr_type::null), default_lifetime(7200),
                        default_preference(0), parse_error(false) {}
    void newline() {
        duid.clear();
        iaid.clear();
        macaddr.clear();
        ipaddr.clear();
        ipaddr2.clear();
        last_addr = addr_type::null;
        parse_error = false;
    }
    const char *st;
    int cs;

    std::string duid;
    std::string iaid;
    std::string macaddr;
    std::string ipaddr;
    std::string ipaddr2;
    addr_type last_addr;
    char interface[IFNAMSIZ];
    uint32_t default_lifetime;
    uint8_t default_preference;
    bool parse_error;
};

#define MARKED_STRING() cps.st, (p > cps.st ? static_cast<size_t>(p - cps.st) : 0)

static inline std::string lc_string(const char *s, size_t slen)
{
    auto r = std::string(s, slen);
    for (auto &i: r) i = tolower(i);
    return r;
}

%%{
    machine cfg_line_m;
    access cps.;

    action St { cps.st = p; }

    action DuidEn { cps.duid = lc_string(MARKED_STRING()); }
    action IaidEn { cps.iaid = lc_string(MARKED_STRING()); }
    action MacAddrEn { cps.macaddr = lc_string(MARKED_STRING()); }
    action V4AddrEn {
        cps.ipaddr = lc_string(MARKED_STRING());
        cps.last_addr = addr_type::v4;
    }
    action V6AddrEn {
        cps.ipaddr = lc_string(MARKED_STRING());
        cps.last_addr = addr_type::v6;
    }
    action Bind4En { emplace_bind(linenum, std::string(MARKED_STRING()), true); }
    action Bind6En { emplace_bind(linenum, std::string(MARKED_STRING()), false); }
    action UserEn { set_user_runas(MARKED_STRING()); }
    action ChrootEn { set_chroot_path(MARKED_STRING()); }
    action S6NotifyEn {
        if (auto t = nk::from_string<int>(MARKED_STRING())) set_s6_notify_fd(*t); else {
            cps.parse_error = true;
            fbreak;
        }
    }
    action DefLifeEn {
        if (auto t = nk::from_string<uint32_t>(MARKED_STRING())) cps.default_lifetime = *t; else {
            cps.parse_error = true;
            fbreak;
        }
    }
    action DefPrefEn {
        if (auto t = nk::from_string<uint8_t>(MARKED_STRING())) cps.default_preference = *t; else {
            log_line("default_preference on line %zu out of range [0,255]: %s\n",
                     linenum, std::string(MARKED_STRING()).c_str());
            cps.parse_error = true;
            fbreak;
        }
    }
    action InterfaceEn {
        size_t len = (size_t)(p - cps.st);
        if (p <= cps.st || len >= IFNAMSIZ) {
            log_line("interface name on line %zu is too long (>= %d)\n", linenum, IFNAMSIZ);
            cps.parse_error = true;
            fbreak;
        }
        memcpy(cps.interface, cps.st, len);
        cps.interface[len] = 0;
        emplace_interface(linenum, cps.interface, cps.default_preference);
    }
    action DnsServerEn {
        emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
    }
    action DnsSearchEn {
        emplace_dns_search(linenum, cps.interface, std::string(MARKED_STRING()));
    }
    action NtpServerEn {
        emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
    }
    action GatewayEn {
        emplace_gateway(linenum, cps.interface, cps.ipaddr);
    }
    action DynRangePreEn {
        cps.ipaddr2 = std::move(cps.ipaddr);
    }
    action DynRangeEn {
        emplace_dynamic_range(linenum, cps.interface, cps.ipaddr2, cps.ipaddr,
                              cps.default_lifetime);
    }
    action DynamicV6En {
        emplace_dynamic_v6(linenum, cps.interface);
    }
    action V4EntryEn {
        emplace_dhcp_state(linenum, cps.interface, cps.macaddr, cps.ipaddr,
                           cps.default_lifetime);
    }
    action V6EntryEn {
        if (auto iaid = nk::from_string<uint32_t>(cps.iaid)) {
            emplace_dhcp_state(linenum, cps.interface,
                               cps.duid.data(), cps.duid.size(),
                               *iaid, cps.ipaddr, cps.default_lifetime);
        } else {
            cps.parse_error = true;
            fbreak;
        }
    }

    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;

    comment = space* ('//' any*)?;
    tcomment = (space+ '//' any*)?;
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
    char buf[MAX_LINE];
    auto f = fopen(path, "r");
    if (!f) {
        log_line("%s: failed to open config file '%s' for read: %s\n",
                 __func__, path, strerror(errno));
        return false;
    }
    SCOPE_EXIT{ fclose(f); };
    size_t linenum = 0;
    cfg_parse_state ps;
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
    return true;
}

