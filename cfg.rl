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
#include <nk/str_to_int.hpp>
#include "dhcp_state.hpp"

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
    cfg_parse_state() : st(nullptr), cs(0), default_lifetime(7200) {}
    void newline() {
        duid.clear();
        iaid.clear();
        macaddr.clear();
        v4_addr.clear();
        v4_addr2.clear();
        v6_addr.clear();
    }
    const char *st;
    int cs;

    std::string duid;
    std::string iaid;
    std::string macaddr;
    std::string v4_addr;
    std::string v4_addr2;
    std::string v6_addr;
    std::string interface;
    uint32_t default_lifetime;
};

%%{
    machine cfg_line_m;
    access cps.;

    action St { cps.st = p; }

    # XXX: Normalize to lowercase!
    action DuidEn { cps.duid = std::string(cps.st, p - cps.st); }
    action IaidEn { cps.iaid = std::string(cps.st, p - cps.st); }
    action MacAddrEn { cps.macaddr = std::string(cps.st, p - cps.st); }
    action V4AddrEn { cps.v4_addr = std::string(cps.st, p - cps.st); }
    action V6AddrEn { cps.v6_addr = std::string(cps.st, p - cps.st); }

    action Bind4En { emplace_bind(linenum, std::string(cps.st, p - cps.st), true); }
    action Bind6En { emplace_bind(linenum, std::string(cps.st, p - cps.st), false); }
    action DefLifeEn { cps.default_lifetime = nk::str_to_u32(std::string(cps.st, p - cps.st)); }
    action InterfaceEn {
        cps.interface = std::string(cps.st, p - cps.st);
        emplace_interface(linenum, cps.interface);
    }
    action DnsServerEn {
        const auto is_v4 = !!cps.v4_addr.size();
        emplace_dns_server(linenum, cps.interface, is_v4 ? cps.v4_addr : cps.v6_addr, is_v4);
    }
    action DnsSearchEn {
        emplace_dns_search(linenum, cps.interface, std::string(cps.st, p - cps.st));
    }
    action NtpServerEn {
        const auto is_v4 = !!cps.v4_addr.size();
        emplace_ntp_server(linenum, cps.interface, is_v4 ? cps.v4_addr : cps.v6_addr, is_v4);
    }
    action SubnetEn {
        emplace_subnet(linenum, cps.interface, cps.v4_addr);
    }
    action GatewayEn {
        emplace_gateway(linenum, cps.interface, cps.v4_addr);
    }
    action BroadcastEn {
        emplace_broadcast(linenum, cps.interface, cps.v4_addr);
    }
    action DynRangePreEn {
        cps.v4_addr2 = std::move(cps.v4_addr);
    }
    action DynRangeEn {
        emplace_dynamic_range(linenum, cps.interface, cps.v4_addr2, cps.v4_addr,
                              cps.default_lifetime);
    }
    action V4EntryEn {
        emplace_dhcp_state(linenum, cps.interface, cps.macaddr, cps.v4_addr,
                           cps.default_lifetime);
    }
    action V6EntryEn {
        emplace_dhcp_state(linenum, cps.interface, std::move(cps.duid), nk::str_to_u32(cps.iaid),
                           cps.v6_addr, cps.default_lifetime);
    }

    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;

    comment = space* ('//' any*)?;
    bind4 = space* 'bind4' (space+ alnum+ >St %Bind4En)+ comment;
    bind6 = space* 'bind6' (space+ alnum+ >St %Bind6En)+ comment;
    default_lifetime = space* 'default_lifetime' space+ digit+ >St %DefLifeEn comment;
    interface = space* 'interface' space+ alnum+ >St %InterfaceEn comment;
    dns_server = space* 'dns_server' space+ (v4_addr | v6_addr) %DnsServerEn comment;
    dns_search = space* 'dns_search' space+ graph+ >St %DnsSearchEn comment;
    ntp_server = space* 'ntp_server' space+ (v4_addr | v6_addr) %NtpServerEn comment;
    subnet = space* 'subnet' space+ v4_addr %SubnetEn comment;
    gateway = space* 'gateway' space+ v4_addr %GatewayEn comment;
    broadcast = space* 'broadcast' space+ v4_addr %BroadcastEn comment;
    dynamic_range = space* 'dynamic_range' space+ v4_addr %DynRangePreEn space+ v4_addr %DynRangeEn comment;
    v4_entry = space* 'v4' space+ macaddr space+ v4_addr comment;
    v6_entry = space* 'v6' space+ duid space+ iaid space+ v6_addr comment;

    main := comment | bind4 | bind6 | default_lifetime | interface | dns_server
          | dns_search | ntp_server | subnet | gateway | broadcast | dynamic_range
          | v6_entry %V6EntryEn | v4_entry %V4EntryEn;
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
        auto r = do_parse_cfg_line(ps, buf, llen, linenum);
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

