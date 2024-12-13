// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include "rng.hpp"
#include "nlsocket.hpp"
#include "multicast6.hpp"
#include "dhcp6.hpp"
#include "dynlease.hpp"
#include "attach_bpf.h"
#include "duid.hpp"
extern "C" {
#include "nk/io.h"
}

#define MAX_DYN_LEASES 1000u
#define MAX_DYN_ATTEMPTS 100u

extern NLSocket nl_socket;
extern int64_t get_current_ts();

static nk::ip_address mask_v6_addr(const nk::ip_address &addr, uint8_t mask)
{
    nk::ip_address ret;
    uint8_t b[16];
    addr.raw_v6bytes(b);
    const auto keep_bytes = mask / 8u;
    const auto keep_r_bits = mask % 8u;
    b[keep_bytes] &= ~(0xffu >> keep_r_bits);
    for (unsigned i = keep_bytes + 1; i < 16; ++i) b[i] = 0u;
    ret.from_v6bytes(b);
    return ret;
}
static nk::ip_address v6_addr_random(const nk::ip_address &prefix, uint8_t prefixlen)
{
    nk::ip_address ret;
    uint8_t b[16];
    const auto keep_bytes = prefixlen / 8u;
    const auto keep_r_bits = prefixlen % 8u;
    prefix.raw_v6bytes(b);
    unsigned i = 15;
    for (; i > keep_bytes; --i) b[i] = nk_random_u64();
    uint8_t c = nk_random_u64();
    b[i] |= c & (0xff >> keep_r_bits);
    ret.from_v6bytes(b);
    return ret;
}

bool D6Listener::create_dhcp6_socket()
{
    auto tfd = nk::sys::handle{ socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP) };
    if (!tfd) {
        log_line("dhcp6: Failed to create v6 UDP socket on %s: %s\n", ifname_, strerror(errno));
        return false;
    }
    nk::ip_address mc6_alldhcp_ras;
    if (!mc6_alldhcp_ras.from_string("ff02::1:2")) return false;
    if (!attach_multicast(tfd(), ifname_, mc6_alldhcp_ras)) return false;
    attach_bpf(tfd());

    sockaddr_in6 sai;
    memset(&sai, 0, sizeof sai); // s6_addr is set to any here
    sai.sin6_family = AF_INET6;
    sai.sin6_port = htons(547);
    if (bind(tfd(), (const sockaddr *)&sai, sizeof sai)) {
        log_line("dhcp6: Failed to bind to UDP 547 on %s: %s\n", ifname_, strerror(errno));
        return false;
    }

    swap(fd_, tfd);
    return true;
}

bool D6Listener::init(const char *ifname, uint8_t preference)
{
    using_bpf_ = false;
    preference_ = preference;
    size_t ifname_src_size = strlen(ifname);
    if (ifname_src_size >= sizeof ifname_) {
        log_line("D6Listener: Interface name (%s) too long\n", ifname);
        return false;
    }
    *static_cast<char *>(mempcpy(ifname_, ifname, ifname_src_size)) = 0;

    auto ifinfo = nl_socket.get_ifinfo(ifname_);
    if (!ifinfo) {
        log_line("dhcp6: Failed to get interface index for %s\n", ifname_);
        return false;
    }
    ifindex_ = ifinfo->index;

    log_line("dhcp6: DHCPv6 Preference is %u on %s\n", preference_, ifname_);

    for (const auto &i: ifinfo->addrs) {
        if (i.scope == netif_addr::Scope::Global && !i.address.is_v4()) {
            local_ip_ = i.address;
            prefixlen_ = i.prefixlen;
            local_ip_prefix_ = mask_v6_addr(local_ip_, prefixlen_);
            char abuf[48];
            char abufp[48];
            if (!local_ip_.to_string(abuf, sizeof abuf)) abort();
            if (!local_ip_prefix_.to_string(abufp, sizeof abufp)) abort();
            log_line("dhcp6: IP address for %s is %s/%u.  Prefix is %s.\n",
                     ifname, abuf, +prefixlen_, abufp);
        } else if (i.scope == netif_addr::Scope::Link && !i.address.is_v4()) {
            link_local_ip_ = i.address;
            char abuf[48];
            if (!link_local_ip_.to_string(abuf, sizeof abuf)) abort();
            log_line("dhcp6: Link-local IP address for %s is %s.\n", ifname, abuf);
        }
    }

    if (!create_dhcp6_socket()) return false;

    return true;
}

void D6Listener::process_input()
{
    char buf[8192];
    for (;;) {
        sockaddr_storage sai;
        socklen_t sailen = sizeof sai;
        auto buflen = recvfrom(fd_(), buf, sizeof buf, MSG_DONTWAIT, (sockaddr *)&sai, &sailen);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("dhcp6: recvfrom failed on %s: %s\n", ifname_, strerror(err));
        }
        process_receive(buf, static_cast<size_t>(buflen), sai, sailen);
    }
}

void D6Listener::attach_bpf(int fd)
{
    using_bpf_ = attach_bpf_dhcp6_info(fd, ifname_);
}

static const char * dhcp6_msgtype_to_string(dhcp6_msgtype m)
{
    switch (m) {
    default: return "unknown";
    case dhcp6_msgtype::solicit: return "solicit";
    case dhcp6_msgtype::advertise: return "advertise";
    case dhcp6_msgtype::request: return "request";
    case dhcp6_msgtype::confirm: return "confirm";
    case dhcp6_msgtype::renew: return "renew";
    case dhcp6_msgtype::rebind: return "rebind";
    case dhcp6_msgtype::reply: return "reply";
    case dhcp6_msgtype::release: return "release";
    case dhcp6_msgtype::decline: return "decline";
    case dhcp6_msgtype::reconfigure: return "reconfigure";
    case dhcp6_msgtype::information_request: return "information_request";
    case dhcp6_msgtype::relay_forward: return "relay_forward";
    case dhcp6_msgtype::relay_reply: return "relay_reply";
    }
}

static const char * dhcp6_opt_to_string(uint16_t opttype)
{
    switch (opttype) {
    case  1: return "Client Identifier";
    case  2: return "Server Identifier";
    case  3: return "Identity Association (IA) Non-Temporary";
    case  4: return "Identity Association (IA) Temporary";
    case  5: return "Identity Association (IA) Address";
    case  6: return "Option Request";
    case  7: return "Preference";
    case  8: return "Elapsed Time";
    case  9: return "Relay Message";
    case 11: return "Authentication";
    case 12: return "Server Unicast";
    case 13: return "Status Code";
    case 14: return "Rapid Commit";
    case 15: return "User Class";
    case 16: return "Vendor Class";
    case 17: return "Vendor Options";
    case 18: return "Interface ID";
    case 19: return "Reconfigure Message";
    case 20: return "Reconfigure Accept";
    case 23: return "DNS Recursive Servers"; // RFC3646
    case 24: return "DNS Domain Search List"; // RFC3646
    case 39: return "Client FQDN"; // RFC4704
    case 56: return "NTP Server"; // RFC5908
    default: log_line("Unknown DHCP Option type %u\n", opttype);
             return "Unknown";
    }
}

bool D6Listener::allot_dynamic_ip(const d6msg_state &d6s, sbufs &ss, uint32_t iaid,
                                  d6_statuscode::code failcode, bool &use_dynamic)
{
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v6(ifindex_, &dynamic_lifetime)) {
        if (!emit_IA_code(d6s, ss, iaid, failcode)) return false;
        use_dynamic = false;
        return true;
    }

    log_line("dhcp6: Checking dynamic IP on %s...\n", ifname_);

    const auto expire_time = get_current_ts() + dynamic_lifetime;

    auto v6a = dynlease6_query_refresh(ifname_, d6s.client_duid.data(), d6s.client_duid.size(), iaid, expire_time);
    if (v6a != nk::ip_address(nk::ip_address::any{})) {
        dhcpv6_entry de;
        de.duid_len = d6s.client_duid.size();
        if (de.duid_len > sizeof de.duid) abort();
        memcpy(de.duid, d6s.client_duid.data(), de.duid_len);
        de.address = v6a;
        de.lifetime = dynamic_lifetime;
        de.iaid = iaid;
        if (!emit_IA_addr(d6s, ss, &de)) return false;
        char abuf[48];
        if (!v6a.to_string(abuf, sizeof abuf)) abort();
        log_line("dhcp6: Assigned existing dynamic IP (%s) on %s\n", abuf, ifname_);
        use_dynamic = true;
        return true;
    }
    // This check guards against OOM via DoS.
    if (dynlease6_count(ifname_) >= MAX_DYN_LEASES) {
        log_line("dhcp6: Maximum number of dynamic leases (%u) reached on %s\n",
                 MAX_DYN_LEASES, ifname_);
        if (!emit_IA_code(d6s, ss, iaid, failcode)) return false;
        use_dynamic = false;
        return true;
    }
    log_line("dhcp6: Selecting an unused dynamic IP on %s\n", ifname_);

    // Given a prefix, choose a random address.  Then check it against our
    // existing static and dynamic leases.  If no collision, assign a
    // dynamic lease to the random address and return it.
    for (unsigned attempt = 0; attempt < MAX_DYN_ATTEMPTS; ++attempt) {
        v6a = v6_addr_random(local_ip_prefix_, prefixlen_);
        if (!query_unused_addr_v6(ifindex_, v6a)) continue;
        const auto assigned = dynlease6_add(ifname_, v6a, d6s.client_duid.data(),
                                            d6s.client_duid.size(), iaid, expire_time);
        if (assigned) {
            dhcpv6_entry de;
            de.duid_len = d6s.client_duid.size();
            if (de.duid_len > sizeof de.duid) abort();
            memcpy(de.duid, d6s.client_duid.data(), de.duid_len);
            de.address = v6a;
            de.lifetime = dynamic_lifetime;
            de.iaid = iaid;
            if (!emit_IA_addr(d6s, ss, &de)) return false;
            use_dynamic = true;
            return true;
        }
    }
    log_line("dhcp6: Unable to select an unused dynamic IP after %u attempts on %s\n",
             MAX_DYN_ATTEMPTS, ifname_);
    if (!emit_IA_code(d6s, ss, iaid, failcode)) return false;
    use_dynamic = false;
    return true;
}

#define OPT_STATUSCODE_SIZE (4)

bool D6Listener::attach_status_code(const d6msg_state &, sbufs &ss,
                                    d6_statuscode::code scode)
{
    static char ok_str[] = "OK";
    static char nak_str[] = "NO";
    dhcp6_opt header;
    header.type(13);
    header.length(OPT_STATUSCODE_SIZE);
    if (!header.write(ss)) return false;
    d6_statuscode sc(scode);
    if (!sc.write(ss)) return false;
    if (scode == d6_statuscode::code::success) {
        for (int i = 0; ok_str[i]; ++i) {
            if (ss.si == ss.se) return false;
            *ss.si++ = ok_str[i];
        }
    } else {
        for (int i = 0; nak_str[i]; ++i) {
            if (ss.si == ss.se) return false;
            *ss.si++ = nak_str[i];
        }
    }
    return true;
}

bool D6Listener::write_response_header(const d6msg_state &d6s, sbufs &ss,
                                       dhcp6_msgtype mtype)
{
    dhcp6_header send_d6hdr(d6s.header); // to copy the xid
    send_d6hdr.msg_type(mtype);
    if (!send_d6hdr.write(ss)) return false;

    dhcp6_opt_serverid send_serverid(g_server_duid, sizeof g_server_duid);
    if (!send_serverid.write(ss)) return false;

    dhcp6_opt send_clientid;
    if (d6s.client_duid_blob_size == 0 ||
        (ptrdiff_t)d6s.client_duid_blob_size > ss.se - ss.si) return false;
    send_clientid.type(1);
    send_clientid.length(d6s.client_duid_blob_size);
    if (!send_clientid.write(ss)) return false;
    memcpy(ss.si, d6s.client_duid_blob, d6s.client_duid_blob_size);
    ss.si += d6s.client_duid_blob_size;

    if (preference_ > 0) {
        dhcp6_opt send_pref;
        send_pref.type(7);
        send_pref.length(1);
        if (!send_pref.write(ss)) return false;
        if (ss.si == ss.se) return false;
        *ss.si++ = static_cast<char>(preference_);
    }
    return true;
}

// We control what IAs are valid, and we never assign multiple address to a single
// IA.  Thus there's no reason to care about that case.
bool D6Listener::emit_IA_addr(const d6msg_state &, sbufs &ss, const dhcpv6_entry *v)
{
    dhcp6_opt header;
    header.type(3);
    header.length(d6_ia::size + dhcp6_opt::size + d6_ia_addr::size);
    if (!header.write(ss)) return false;
    d6_ia ia;
    ia.iaid = v->iaid;
    ia.t1_seconds = static_cast<uint32_t>(0.5 * v->lifetime);
    ia.t2_seconds = static_cast<uint32_t>(0.8 * v->lifetime);
    if (!ia.write(ss)) return false;
    header.type(5);
    header.length(d6_ia_addr::size);
    if (!header.write(ss)) return false;
    d6_ia_addr addr;
    addr.addr = v->address;
    addr.prefer_lifetime = v->lifetime;
    addr.valid_lifetime = v->lifetime;
    if (!addr.write(ss)) return false;
    return true;
}

bool D6Listener::emit_IA_code(const d6msg_state &d6s, sbufs &ss, uint32_t iaid,
                              d6_statuscode::code scode)
{
    dhcp6_opt header;
    header.type(3);
    header.length(d6_ia::size + dhcp6_opt::size + OPT_STATUSCODE_SIZE);
    if (!header.write(ss)) return false;
    d6_ia ia;
    ia.iaid = iaid;
    ia.t1_seconds = 0;
    ia.t2_seconds = 0;
    if (!ia.write(ss)) return false;
    if (!attach_status_code(d6s, ss, scode)) return false;
    return true;
}

// Returns false if no addresses would be assigned.
bool D6Listener::attach_address_info(const d6msg_state &d6s, sbufs &ss,
                                     d6_statuscode::code failcode, bool *has_addrs)
{
    bool ha{false};
    // Look through IAs and send IA with assigned address as an option.
    for (const auto &i: d6s.ias) {
        log_line("dhcp6: Querying duid='%s' iaid=%u...\n",
                 d6s.client_duid.c_str(), i.iaid);
        if (auto x = query_dhcp6_state(ifindex_, d6s.client_duid.data(), d6s.client_duid.size(), i.iaid)) {
            ha = true;
            char abuf[48];
            if (!x->address.to_string(abuf, sizeof abuf)) abort();
            log_line("dhcp6: Found static address %s on %s\n", abuf, ifname_);
            if (!emit_IA_addr(d6s, ss, x)) return false;
            continue;
        }
        bool use_dynamic;
        if (!allot_dynamic_ip(d6s, ss, i.iaid, failcode, use_dynamic)) return false;
        if (use_dynamic) ha = true;
    }
    if (!ha) log_line("dhcp6: Unable to assign any IPs on %s!\n", ifname_);
    if (has_addrs) *has_addrs = ha;
    return true;
}

// If opt_req.size() == 0 then send DnsServers, DomainList,
// and NtpServer.  Otherwise, for each of these types,
// see if it is in the opt_req before adding it to the reply.
bool D6Listener::attach_dns_ntp_info(const d6msg_state &d6s, sbufs &ss)
{
    const auto dns6_servers = query_dns6_servers(ifindex_);
    if (!dns6_servers) return true;

    if (d6s.optreq_dns && dns6_servers->size()) {
        dhcp6_opt send_dns;
        send_dns.type(23);
        send_dns.length(dns6_servers->size() * 16);
        if (!send_dns.write(ss)) return false;
        for (const auto &i: *dns6_servers) {
            if (ss.se - ss.si < 16) return false;
            i.raw_v6bytes(ss.si);
            ss.si += 16;
        }
    }
    auto [dns6_search_blob, dns6_search_blob_size] = query_dns6_search_blob(ifindex_);
    if (d6s.optreq_dns_search && (dns6_search_blob && dns6_search_blob_size)) {
        dhcp6_opt send_dns_search;
        send_dns_search.type(24);
        send_dns_search.length(dns6_search_blob_size);
        if (!send_dns_search.write(ss)) return false;
        if (ss.se - ss.si < (ptrdiff_t)dns6_search_blob_size) return false;
        memcpy(ss.si, dns6_search_blob, dns6_search_blob_size);
        ss.si += dns6_search_blob_size;
    }
    const auto ntp6_servers = query_ntp6_servers(ifindex_);
    const auto ntp6_multicasts = query_ntp6_multicasts(ifindex_);
    auto [ntp6_fqdns_blob, ntp6_fqdns_blob_size] = query_ntp6_fqdns_blob(ifindex_);
    if (d6s.optreq_ntp
        && ((ntp6_servers && ntp6_servers->size())
            || (ntp6_multicasts && ntp6_multicasts->size())
            || (ntp6_fqdns_blob && ntp6_fqdns_blob_size))) {
        uint16_t len(0);
        dhcp6_opt send_ntp;
        send_ntp.type(56);
        if (ntp6_servers) len += 4 + ntp6_servers->size() * 16;
        if (ntp6_multicasts) len += 4 + ntp6_multicasts->size() * 16;
        if (ntp6_fqdns_blob) len += ntp6_fqdns_blob_size;
        send_ntp.length(len);
        if (!send_ntp.write(ss)) return false;

        for (const auto &i: *ntp6_servers) {
            dhcp6_opt n6_svr;
            n6_svr.type(1);
            n6_svr.length(16);
            if (!n6_svr.write(ss)) return false;
            if (ss.se - ss.si < 16) return false;
            i.raw_v6bytes(ss.si);
            ss.si += 16;
        }
        for (const auto &i: *ntp6_multicasts) {
            dhcp6_opt n6_mc;
            n6_mc.type(2);
            n6_mc.length(16);
            if (!n6_mc.write(ss)) return false;
            if (ss.se - ss.si < 16) return false;
            i.raw_v6bytes(ss.si);
            ss.si += 16;
        }
        if (ntp6_fqdns_blob_size) {
            if (ss.se - ss.si < (ptrdiff_t)ntp6_fqdns_blob_size) return false;
            memcpy(ss.si, ntp6_fqdns_blob, ntp6_fqdns_blob_size);
            ss.si += ntp6_fqdns_blob_size;
        }
    }
    if (d6s.optreq_sntp) {
        uint16_t len(0);
        dhcp6_opt send_sntp;
        send_sntp.type(31);
        if (ntp6_servers) len += ntp6_servers->size() * 16;
        send_sntp.length(len);
        if (!send_sntp.write(ss)) return false;
        for (const auto &i: *ntp6_servers) {
            if (ss.se - ss.si < 16) return false;
            i.raw_v6bytes(ss.si);
            ss.si += 16;
        }
    }
    return true;
}

bool D6Listener::confirm_match(const d6msg_state &d6s, bool &confirmed)
{
    confirmed = false;
    for (const auto &i: d6s.ias) {
        log_line("dhcp6: Querying duid='%s' iaid=%u...\n", d6s.client_duid.c_str(), i.iaid);
        if (i.ia_na_addrs.empty()) return false; // See RFC8415 18.3.3 p3
        for (const auto &j: i.ia_na_addrs) {
            if (!j.addr.compare_mask(local_ip_prefix_, prefixlen_)) {
                char abuf[48];
                if (!j.addr.to_string(abuf, sizeof abuf)) abort();
                log_line("dhcp6: Invalid prefix for IA IP %s on %s. NAK.\n", abuf, ifname_);
                return true;
            } else {
                log_line("dhcp6: IA iaid=%u has a valid prefix on %s\n", i.iaid, ifname_);
            }
        }
    }
    confirmed = true;
    return true;
}

bool D6Listener::mark_addr_unused(const d6msg_state &d6s, sbufs &ss)
{
    for (const auto &i: d6s.ias) {
        bool freed_ia_addr{false};
        log_line("dhcp6: Marking duid='%s' iaid=%u unused on %s...\n", d6s.client_duid.c_str(), i.iaid, ifname_);
        auto x = query_dhcp6_state(ifindex_, d6s.client_duid.data(), d6s.client_duid.size(), i.iaid);
        for (const auto &j: i.ia_na_addrs) {
            if (x && j.addr == x->address) {
                log_line("dhcp6: found static lease on %s\n", ifname_);
                freed_ia_addr = true;
            } else if (dynlease6_del(ifname_, j.addr, d6s.client_duid.data(), d6s.client_duid.size(), i.iaid)) {
                log_line("dhcp6: found dynamic lease on %s\n", ifname_);
                freed_ia_addr = true;
            }
        }
        if (!freed_ia_addr) {
            if (!emit_IA_code(d6s, ss, i.iaid, d6_statuscode::code::nobinding)) return false;
            log_line("dhcp6: no dynamic lease found on %s\n", ifname_);
        }
    }
    return true;
}

bool D6Listener::handle_solicit_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss,
        !d6s.use_rapid_commit ? dhcp6_msgtype::advertise
                              : dhcp6_msgtype::reply)) return false;

    // RFC7550 says servers MUST NOT return top-level Status Code noaddrsavail.
    bool valid;
    if (!attach_address_info(d6s, ss, d6_statuscode::code::noaddrsavail, &valid)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;

    if (valid && d6s.use_rapid_commit) {
        dhcp6_opt rapid_commit;
        rapid_commit.type(14);
        rapid_commit.length(0);
        if (!rapid_commit.write(ss)) return false;
    }
    return true;
}

bool D6Listener::handle_request_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    if (!attach_address_info(d6s, ss, d6_statuscode::code::noaddrsavail)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    return true;
}

bool D6Listener::handle_confirm_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    bool confirmed;
    if (!confirm_match(d6s, confirmed)) return false;
    if (!attach_status_code(d6s, ss, confirmed
        ? d6_statuscode::code::success : d6_statuscode::code::notonlink)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    return true;
}

bool D6Listener::handle_renew_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    if (!attach_address_info(d6s, ss, d6_statuscode::code::nobinding)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    return true;
}

bool D6Listener::handle_rebind_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    if (!attach_address_info(d6s, ss, d6_statuscode::code::nobinding)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    return true;
}

bool D6Listener::handle_information_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    log_line("dhcp6: Sending Information Message in response on %s\n", ifname_);
    return true;
}

bool D6Listener::handle_release_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    if (!mark_addr_unused(d6s, ss)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    return true;
}

bool D6Listener::handle_decline_msg(const d6msg_state &d6s, sbufs &ss)
{
    if (!write_response_header(d6s, ss, dhcp6_msgtype::reply)) return false;
    if (!mark_addr_unused(d6s, ss)) return false;
    if (!attach_dns_ntp_info(d6s, ss)) return false;
    return true;
}

#define OPTIONS_CONSUME(BLD_VAL) do { \
    if (!options_consume(d6s, (BLD_VAL))) { \
        log_line("dhcp6: Received malformed message on %s\n", ifname_); \
        return; \
    } \
} while (0)

bool D6Listener::options_consume(d6msg_state &d6s, size_t v)
{
    for (auto &i: d6s.prev_opt) {
        if (i.second < v) return false; // option_depth would underflow
        i.second -= v;
    }
    while (!d6s.prev_opt.empty() && d6s.prev_opt.back().second == 0)
        d6s.prev_opt.pop_back();
    for (const auto &i: d6s.prev_opt) {
        // Tricky: Guard against client sending invalid suboption lengths.
        if (i.second <= 0) return false; // depth ran out of length but has suboption size left
    }
    return true;
}

bool D6Listener::serverid_incorrect(const d6msg_state &d6s) const
{
    return d6s.server_duid_blob_size != sizeof g_server_duid
        || memcmp(d6s.server_duid_blob, g_server_duid, sizeof g_server_duid);
}

void D6Listener::process_receive(char *buf, size_t buflen,
                                 const sockaddr_storage &sai, socklen_t sailen)
{
    if (sailen < sizeof(sockaddr_in6)) {
        log_line("dhcp6: Received too-short address family on %s: %u\n", ifname_, sailen);
        return;
    }
    char sip_str[32];
    if (!sa6_to_string(sip_str, sizeof sip_str, &sai, sailen)) {
        log_line("dhcp6: Failed to stringize sender ip on %s\n", ifname_);
        return;
    }

    sbufs rs{ buf, buf + buflen };
    if (!using_bpf_) {
        // Discard if the DHCP6 length < the size of a DHCP6 header.
        if (buflen < dhcp6_header::size) {
            log_line("dhcp6: Packet from %s is too short (%zu) on %s\n",
                     sip_str, buflen, ifname_);
            return;
        }
    }

    d6msg_state d6s;
    if (!d6s.header.read(rs)) {
        log_line("dhcp6: Packet from %s has no valid option headers on %s\n",
                 sip_str, ifname_);
        return;
    }
    OPTIONS_CONSUME(d6s.header.size);

    log_line("dhcp6: Message (%s) on %s\n",
             dhcp6_msgtype_to_string(d6s.header.msg_type()), ifname_);

    // These message types are not allowed to be sent to servers.
    if (!using_bpf_) {
        switch (d6s.header.msg_type()) {
        case dhcp6_msgtype::advertise:
        case dhcp6_msgtype::reply:
        case dhcp6_msgtype::reconfigure:
        case dhcp6_msgtype::relay_reply:
            return;
        default: break;
        }
    }

     while (rs.brem() >= 4) {
         dhcp6_opt opt;
         if (!opt.read(rs)) return;
         OPTIONS_CONSUME(opt.size);
         log_line("dhcp6: Option '%s' length=%d on %s\n",
                  dhcp6_opt_to_string(opt.type()), opt.length(), ifname_);
         auto l = opt.length();
         auto ot = opt.type();

         if (l > rs.brem()) {
             log_line("dhcp6: Option is too long on %s\n", ifname_);
             return;
         }

         if (ot == 1) { // ClientID
             d6s.client_duid.reserve(2*l);
             if (l > sizeof d6s.client_duid_blob) {
                 log_line("dhcp6: client DUID is too long on %s\n", ifname_);
                 return;
             }
             d6s.client_duid_blob_size = l;
             memcpy(d6s.client_duid_blob, rs.si, l);
             rs.si += l;
             OPTIONS_CONSUME(l);
             for (size_t j = 0; j < d6s.client_duid_blob_size; ++j) {
                 char tbuf[16];
                 snprintf(tbuf, sizeof tbuf, "%.2hhx", static_cast<uint8_t>(d6s.client_duid_blob[j]));
                 d6s.client_duid.append(tbuf);
             }
             if (d6s.client_duid_blob_size > 0)
                log_line("dhcp6: DUID %s on %s\n", d6s.client_duid.c_str(), ifname_);
         } else if (ot == 2) { // ServerID
             if (l > sizeof d6s.server_duid_blob) {
                 log_line("dhcp6: server DUID is too long on %s\n", ifname_);
                 return;
             }
             d6s.server_duid_blob_size = l;
             memcpy(d6s.server_duid_blob, rs.si, l);
             rs.si += l;
             OPTIONS_CONSUME(l);
         } else if (ot == 3) { // Option_IA_NA
             if (l < 12) {
                 log_line("dhcp6: Client-sent option IA_NA has a bad length on %s\n", ifname_);
                 return;
             }
             d6s.ias.emplace_back();
             if (!d6s.ias.back().read(rs)) return;
             OPTIONS_CONSUME(d6s.ias.back().size);

             const auto na_options_len = l - 12;
             if (na_options_len > 0)
                 d6s.prev_opt.emplace_back(std::make_pair(3, na_options_len));

             log_line("dhcp6: IA_NA: iaid=%u t1=%us t2=%us opt_len=%u on %s\n",
                      d6s.ias.back().iaid, d6s.ias.back().t1_seconds,
                      d6s.ias.back().t2_seconds, na_options_len, ifname_);
         } else if (ot == 5) { // Address
             if (l < 24) {
                 log_line("dhcp6: Client-sent option IAADDR has a bad length (%u) on %s\n", l, ifname_);
                 return;
             }
             if (d6s.prev_opt.size() != 1) {
                 log_line("dhcp6: Client-sent option IAADDR is not nested on %s\n", ifname_);
                 return;
             }
             if (d6s.prev_opt.back().first != 3) {
                 log_line("dhcp6: Client-sent option IAADDR must follow IA_NA on %s\n", ifname_);
                 return;
             }
             if (d6s.ias.empty())
                 suicide("dhcp6: d6.ias is empty on %s\n", ifname_);
             d6s.ias.back().ia_na_addrs.emplace_back();
             if (d6s.ias.back().ia_na_addrs.empty())
                 suicide("dhcp6: d6.ias.back().ia_na_addrs is empty on %s\n", ifname_);
             if (!d6s.ias.back().ia_na_addrs.back().read(rs)) return;
             OPTIONS_CONSUME(d6s.ias.back().ia_na_addrs.back().size);

             auto iaa_options_len = l - 24;
             if (iaa_options_len > 0)
                 d6s.prev_opt.emplace_back(std::make_pair(5, iaa_options_len));

             char abuf[48];
             if (!d6s.ias.back().ia_na_addrs.back().addr.to_string(abuf, sizeof abuf)) abort();
             log_line("dhcp6: IA Address: %s prefer=%us valid=%us opt_len=%d on %s\n",
                      abuf,
                      d6s.ias.back().ia_na_addrs.back().prefer_lifetime,
                      d6s.ias.back().ia_na_addrs.back().valid_lifetime,
                      iaa_options_len, ifname_);

         } else if (ot == 6) { // OptionRequest
             if (l % 2) {
                 log_line("dhcp6: Client-sent option Request has a bad length (%d) on %s\n", l, ifname_);
                 return;
             }
             d6s.optreq_exists = true;
             l /= 2;
             while (l--) {
                 char b[2];
                 b[1] = *rs.si++;
                 b[0] = *rs.si++;
                 OPTIONS_CONSUME(2);
                 uint16_t v;
                 memcpy(&v, b, 2);
                 switch (v) {
                 case 23: d6s.optreq_dns = true; break;
                 case 24: d6s.optreq_dns_search = true; break;
                 case 31: d6s.optreq_sntp = true; break;
                 case 32: d6s.optreq_info_refresh_time = true; break;
                 case 56: d6s.optreq_ntp = true; break;
                 default: break;
                 }
             }
             log_line("dhcp6: Option Request%s%s%s%s%s on %s\n",
                      d6s.optreq_dns ? " DNS" : "",
                      d6s.optreq_dns_search ? " DNS_SEARCH" : "",
                      d6s.optreq_sntp ? " SNTP" : "",
                      d6s.optreq_info_refresh_time ? " INFO_REFRESH" : "",
                      d6s.optreq_ntp ? " NTP" : "",
                      ifname_);
         } else if (ot == 8) { // ElapsedTime
             // 16-bit hundreths of a second since start of exchange
             if (l != 2) {
                 log_line("dhcp6: Client-sent option ElapsedTime has a bad length on %s\n", ifname_);
                 return;
             }
             char b[2];
             b[1] = *rs.si++;
             b[0] = *rs.si++;
             OPTIONS_CONSUME(2);
             memcpy(&d6s.elapsed_time, b, 2);
         } else if (ot == 14) { // Rapid Commit
             if (l != 0) {
                 log_line("dhcp6: Client-sent option Rapid Commit has a bad length on %s\n", ifname_);
                 return;
             }
             d6s.use_rapid_commit = true;
         } else if (ot == 39) { // Client FQDN
             log_line("dhcp6: FQDN Length: %d\n", l);
             if (l < 3) {
                 log_line("dhcp6: Client-sent option Client FQDN has a bad length on %s\n", ifname_);
                 return;
             }
             uint8_t flags, namelen;
             memcpy(&flags, rs.si++, 1);
             memcpy(&namelen, rs.si++, 1);
             OPTIONS_CONSUME(2);
             l -= 2;
             if (l != namelen) {
                 log_line("dhcp6: Client-sent option Client FQDN namelen disagrees with length on %s\n", ifname_);
                 return;
             }
             log_line("dhcp6: FQDN Flags='%u', NameLen='%u' on %s\n", flags, namelen, ifname_);
             log_line("dhcp6: Client FQDN: flags='%u' '%.*s' on %s\n", flags, namelen, rs.si, ifname_);
             rs.si += l;
             OPTIONS_CONSUME(l);
         } else {
             rs.si += l;
             OPTIONS_CONSUME(l);
         }
     }

     if (!d6s.optreq_exists) {
         // These message types MUST include Option Request (cf. RFC 8415 21.27)
         switch (d6s.header.msg_type()) {
         case dhcp6_msgtype::solicit:
         case dhcp6_msgtype::request:
         case dhcp6_msgtype::renew:
         case dhcp6_msgtype::rebind:
         case dhcp6_msgtype::information_request:
             log_line("Client sent invalid %s -- no Option Request is present\n", dhcp6_msgtype_to_string(d6s.header.msg_type()));
             return;
         default: break;
         }
     }

     char sbuf[4096];
     sbufs ss{ &sbuf[0], &sbuf[4096] };

     // Clients are required to send a client identifier.
     if (d6s.client_duid.empty() &&
         d6s.header.msg_type() != dhcp6_msgtype::information_request) {
         return;
     }

     switch (d6s.header.msg_type()) {
     case dhcp6_msgtype::solicit:
         if (d6s.server_duid_blob_size) return;
         if (!handle_solicit_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::request:
         if (serverid_incorrect(d6s)) return;
         if (!handle_request_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::confirm:
         if (d6s.server_duid_blob_size) return;
         if (!handle_confirm_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::renew:
         if (serverid_incorrect(d6s)) return;
         if (!handle_renew_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::rebind:
         if (d6s.server_duid_blob_size) return;
         if (!handle_rebind_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::release:
         if (serverid_incorrect(d6s)) return;
         if (!handle_release_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::decline:
         if (serverid_incorrect(d6s)) return;
         if (!handle_decline_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::information_request:
         if (d6s.server_duid_blob_size && serverid_incorrect(d6s)) return;
         if (!d6s.ias.empty()) return;
         if (!handle_information_msg(d6s, ss)) return;
         break;
     default: return;
     }

     sockaddr_in6 sao;
     memcpy(&sao, &sai, sizeof sao);
     sao.sin6_port = htons(546);
     size_t slen = ss.si > sbuf ? static_cast<size_t>(ss.si - sbuf) : 0;
     if (safe_sendto(fd_(), sbuf, slen, 0, (const sockaddr *)&sao, sizeof sao) < 0) {
         log_line("dhcp6: sendto (%s) failed on %s: %s\n", sip_str, ifname_, strerror(errno));
         return;
     }
}

