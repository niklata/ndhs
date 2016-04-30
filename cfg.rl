/* cfg.rl - configure file parser for ndhs
 *
 * (c) 2016 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string>
#include <cstdio>
#include <nk/scopeguard.hpp>
#include <format.hpp>
#include <nk/from_string.hpp>
#include "dhcp_state.hpp"
extern void set_user_runas(size_t linenum, std::string &&username);
extern void set_chroot_path(size_t linenum, std::string &&path);

#define MAX_LINE 2048

extern void create_dns_search_blob();

/*

Our configuration file looks like:

dns_server <value>
dns_search <value>
default_lifetime <value>

// Comment
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]

v4 <MAC> <address> [lifetime=value]

*/

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0), last_addr(addr_type::null), default_lifetime(7200) {}
    void newline() {
        duid.clear();
        iaid.clear();
        macaddr.clear();
        ipaddr.clear();
        ipaddr2.clear();
        last_addr = addr_type::null;
    }
    const char *st;
    int cs;

    std::string duid;
    std::string iaid;
    std::string macaddr;
    std::string ipaddr;
    std::string ipaddr2;
    addr_type last_addr;
    std::string interface;
    uint32_t default_lifetime;
};

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

    action DuidEn { cps.duid = lc_string(cps.st, p - cps.st); }
    action IaidEn { cps.iaid = lc_string(cps.st, p - cps.st); }
    action MacAddrEn { cps.macaddr = lc_string(cps.st, p - cps.st); }
    action V4AddrEn {
        cps.ipaddr = lc_string(cps.st, p - cps.st);
        cps.last_addr = addr_type::v4;
    }
    action V6AddrEn {
        cps.ipaddr = lc_string(cps.st, p - cps.st);
        cps.last_addr = addr_type::v6;
    }
    action Bind4En { emplace_bind(linenum, std::string(cps.st, p - cps.st), true); }
    action Bind6En { emplace_bind(linenum, std::string(cps.st, p - cps.st), false); }
    action UserEn { set_user_runas(linenum, std::string(cps.st, p - cps.st)); }
    action ChrootEn { set_chroot_path(linenum, std::string(cps.st, p - cps.st)); }
    action DefLifeEn {
        cps.default_lifetime = nk::from_string<uint32_t>(std::string(cps.st, p - cps.st));
    }
    action InterfaceEn {
        cps.interface = std::string(cps.st, p - cps.st);
        emplace_interface(linenum, cps.interface);
    }
    action DnsServerEn {
        emplace_dns_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
    }
    action DnsSearchEn {
        emplace_dns_search(linenum, cps.interface, std::string(cps.st, p - cps.st));
    }
    action NtpServerEn {
        emplace_ntp_server(linenum, cps.interface, cps.ipaddr, cps.last_addr);
    }
    action SubnetEn {
        emplace_subnet(linenum, cps.interface, cps.ipaddr);
    }
    action GatewayEn {
        emplace_gateway(linenum, cps.interface, cps.ipaddr);
    }
    action BroadcastEn {
        emplace_broadcast(linenum, cps.interface, cps.ipaddr);
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
        emplace_dhcp_state(linenum, cps.interface, std::move(cps.duid),
                           nk::from_string<uint32_t>(cps.iaid),
                           cps.ipaddr, cps.default_lifetime);
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
    default_lifetime = space* 'default_lifetime' space+ digit+ >St %DefLifeEn tcomment;
    interface = space* 'interface' space+ alnum+ >St %InterfaceEn tcomment;
    dns_server = space* 'dns_server' (space+ (v4_addr | v6_addr) %DnsServerEn)+ tcomment;
    dns_search = space* 'dns_search' (space+ graph+ >St %DnsSearchEn)+ tcomment;
    ntp_server = space* 'ntp_server' (space+ (v4_addr | v6_addr) %NtpServerEn)+ tcomment;
    subnet = space* 'subnet' space+ v4_addr %SubnetEn tcomment;
    gateway = space* 'gateway' space+ v4_addr %GatewayEn tcomment;
    broadcast = space* 'broadcast' space+ v4_addr %BroadcastEn tcomment;
    dynamic_range = space* 'dynamic_range' space+ v4_addr %DynRangePreEn space+ v4_addr %DynRangeEn tcomment;
    dynamic_v6 = space* 'dynamic_v6' %DynamicV6En tcomment;
    v4_entry = space* 'v4' space+ macaddr space+ v4_addr tcomment;
    v6_entry = space* 'v6' space+ duid space+ iaid space+ v6_addr tcomment;

    main := comment | bind4 | bind6 | user | chroot | default_lifetime | interface
          | dns_server | dns_search | ntp_server | subnet | gateway | broadcast
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

    if (cps.cs >= cfg_line_m_first_final)
        return 1;
    if (cps.cs == cfg_line_m_error)
        return -1;
    return -2;
}

void parse_config(const std::string &path)
{
    char buf[MAX_LINE];
    auto f = fopen(path.c_str(), "r");
    if (!f) {
        fmt::print(stderr, "{}: failed to open config file \"{}\" for read: {}\n",
                   __func__, path, strerror(errno));
        return;
    }
    SCOPE_EXIT{ fclose(f); };
    size_t linenum = 0;
    cfg_parse_state ps;
    while (!feof(f)) {
        if (!fgets(buf, sizeof buf, f)) {
            if (!feof(f))
                fmt::print(stderr, "{}: io error fetching line of '{}'\n", __func__, path);
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
                fmt::print(stderr, "{}: Incomplete configuration at line {}; ignoring\n",
                           __func__, linenum);
            else
                fmt::print(stderr, "{}: Malformed configuration at line {}; ignoring.\n",
                           __func__, linenum);
            continue;
        }
    }
    create_blobs();
    //std::exit(EXIT_SUCCESS);
}

