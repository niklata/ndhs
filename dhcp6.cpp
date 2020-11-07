#include <poll.h>
#include "rng.hpp"
#include "nlsocket.hpp"
#include "multicast6.hpp"
#include "dhcp6.hpp"
#include "dynlease.hpp"
#include "attach_bpf.h"
#include "asio_addrcmp.hpp"
#include "duid.hpp"
extern "C" {
#include "nk/io.h"
}

#define MAX_DYN_LEASES 1000u
#define MAX_DYN_ATTEMPTS 100u

extern std::unique_ptr<NLSocket> nl_socket;
static auto mc6_alldhcp_ras = asio::ip::address_v6::from_string("ff02::1:2");
extern int64_t get_current_ts();

static asio::ip::address_v6 mask_v6_addr(const asio::ip::address_v6 &addr, uint8_t mask)
{
    auto b = addr.to_bytes();
    const auto keep_bytes = mask / 8u;
    const auto keep_r_bits = mask % 8u;
    b[keep_bytes] &= ~(0xffu >> keep_r_bits);
    for (unsigned i = keep_bytes + 1; i < 16; ++i)
        b[i] = 0u;
    return asio::ip::address_v6(b, addr.scope_id());
}
static asio::ip::address_v6 v6_addr_random(const asio::ip::address_v6 &prefix, uint8_t prefixlen)
{
    const auto keep_bytes = prefixlen / 8u;
    const auto keep_r_bits = prefixlen % 8u;
    auto b = prefix.to_bytes();
    unsigned i = 15;
    for (; i > keep_bytes; --i)
        b[i] = random_u64();
    uint8_t c = random_u64();
    b[i] |= c & (0xff >> keep_r_bits);
    return asio::ip::address_v6(b, prefix.scope_id());
}

bool D6Listener::create_dhcp6_socket()
{
    auto tfd = nk::sys::handle{ socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP) };
    if (!tfd) {
        log_warning("dhcp6: Failed to create v6 UDP socket on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }
    if (!attach_multicast(tfd(), ifname_, mc6_alldhcp_ras))
        return false;
    attach_bpf(tfd());

    sockaddr_in6 sai;
    memset(&sai, 0, sizeof sai); // s6_addr is set to any here
    sai.sin6_family = AF_INET6;
    sai.sin6_port = htons(547);
    if (bind(tfd(), reinterpret_cast<const sockaddr *>(&sai), sizeof sai)) {
        log_warning("dhcp6: Failed to bind to UDP 547 on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }

    swap(fd_, tfd);
    return true;
}

bool D6Listener::init(const std::string &ifname, uint8_t preference)
{
    ifname_ = ifname;
    using_bpf_ = false;
    preference_ = preference;

    {
        auto ifinfo = nl_socket->get_ifinfo(ifname_);
        if (!ifinfo.value()) {
            log_warning("dhcp6: Failed to get interface index for %s", ifname_.c_str());
            return false;
        }

        log_line("dhcp6: DHCPv6 Preference is %u on %s", preference_, ifname_.c_str());

        for (const auto &i: ifinfo.value()->addrs) {
            if (i.scope == netif_addr::Scope::Global && i.address.is_v6()) {
                local_ip_ = i.address.to_v6();
                prefixlen_ = i.prefixlen;
                local_ip_prefix_ = mask_v6_addr(local_ip_, prefixlen_);
                log_line("dhcp6: IP address for %s is %s/%u.  Prefix is %s.",
                         ifname.c_str(), local_ip_.to_string().c_str(), +prefixlen_,
                         local_ip_prefix_.to_string().c_str());
            } else if (i.scope == netif_addr::Scope::Link && i.address.is_v6()) {
                link_local_ip_ = i.address.to_v6();
                log_line("dhcp6: Link-local IP address for %s is %s.",
                         ifname.c_str(), link_local_ip_.to_string().c_str());
            }
        }
    }
    if (!create_dhcp6_socket()) return false;

    thd_ = std::thread([this]() {
        struct pollfd pfds[1];
        memset(pfds, 0, sizeof pfds);
        pfds[0].fd = fd_();
        pfds[0].events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
        for (;;) {
            if (poll(pfds, 1, -1) < 0) {
                if (errno != EINTR)
                    suicide("dhcp6: poll failed on %s", ifname_.c_str());
            }
            if (pfds[0].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                pfds[0].revents &= ~(POLLHUP|POLLERR|POLLRDHUP);
                suicide("dhcp6: socket closed unexpectedly on %s", ifname_.c_str());
            }
            if (pfds[0].revents & POLLIN) {
                pfds[0].revents &= ~POLLIN;
                char buf[8192];
                for (;;) {
                    sockaddr_in6 sai;
                    socklen_t sailen = sizeof sai;
                    auto buflen = recvfrom(fd_(), buf, sizeof buf, MSG_DONTWAIT, reinterpret_cast<sockaddr *>(&sai), &sailen);
                    if (buflen == -1) {
                        int err = errno;
                        if (err == EINTR) continue;
                        if (err == EAGAIN || err == EWOULDBLOCK) break;
                        suicide("dhcp6: recvfrom failed on %s: %s", ifname_.c_str(), strerror(err));
                    }
                    process_receive(buf, buflen, sai, sailen);
                }
            }
        }
    });
    thd_.detach();
    return true;
}

void D6Listener::attach_bpf(int fd)
{
    using_bpf_ = attach_bpf_dhcp6_info(fd, ifname_.c_str());
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
    default: log_line("Unknown DHCP Option type %u", opttype);
             return "Unknown";
    }
}

bool D6Listener::allot_dynamic_ip(const d6msg_state &d6s, sbufs &ss, uint32_t iaid,
                                  d6_statuscode::code failcode, bool &use_dynamic)
{
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v6(ifname_, dynamic_lifetime)) {
        if (!emit_IA_code(d6s, ss, iaid, failcode)) return false;
        use_dynamic = false;
        return true;
    }

    log_line("dhcp6: Checking dynamic IP on %s...", ifname_.c_str());

    const auto expire_time = get_current_ts() + dynamic_lifetime;

    auto v6a = dynlease_query_refresh(ifname_, d6s.client_duid, iaid, expire_time);
    if (v6a != asio::ip::address_v6::any()) {
        dhcpv6_entry de(iaid, v6a, dynamic_lifetime);
        if (!emit_IA_addr(d6s, ss, &de)) return false;
        log_line("dhcp6: Assigned existing dynamic IP (%s) on %s", v6a.to_string().c_str(), ifname_.c_str());
        use_dynamic = true;
        return true;
    }
    // This check guards against OOM via DoS.
    if (dynlease6_count(ifname_) >= MAX_DYN_LEASES) {
        log_line("dhcp6: Maximum number of dynamic leases (%u) reached on %s",
                 MAX_DYN_LEASES, ifname_.c_str());
        if (!emit_IA_code(d6s, ss, iaid, failcode)) return false;
        use_dynamic = false;
        return true;
    }
    log_line("dhcp6: Selecting an unused dynamic IP on %s", ifname_.c_str());

    // Given a prefix, choose a random address.  Then check it against our
    // existing static and dynamic leases.  If no collision, assign a
    // dynamic lease to the random address and return it.
    for (unsigned attempt = 0; attempt < MAX_DYN_ATTEMPTS; ++attempt) {
        v6a = v6_addr_random(local_ip_prefix_, prefixlen_);
        if (!query_unused_addr(ifname_, v6a)) continue;
        const auto assigned = dynlease_add(ifname_, v6a, d6s.client_duid, iaid, expire_time);
        if (assigned) {
            dhcpv6_entry de(iaid, v6a, dynamic_lifetime);
            if (!emit_IA_addr(d6s, ss, &de)) return false;
            use_dynamic = true;
            return true;
        }
    }
    log_line("dhcp6: Unable to select an unused dynamic IP after %u attempts on %s",
             MAX_DYN_ATTEMPTS, ifname_.c_str());
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
    if (auto t = header.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    d6_statuscode sc(scode);
    if (auto t = sc.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    if (scode == d6_statuscode::code::success) {
        for (int i = 0; ok_str[i]; ++i) {
            if (ss.si == ss.se) return false;
            *(ss.si)++ = ok_str[i];
        }
    } else {
        for (int i = 0; nak_str[i]; ++i) {
            if (ss.si == ss.se) return false;
            *(ss.si)++ = nak_str[i];
        }
    }
    return true;
}

bool D6Listener::write_response_header(const d6msg_state &d6s, sbufs &ss,
                                       dhcp6_msgtype mtype)
{
    dhcp6_header send_d6hdr;
    send_d6hdr.msg_type(mtype);
    send_d6hdr.xid(d6s.header.xid());
    if (auto t = send_d6hdr.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;

    dhcp6_opt_serverid send_serverid(g_server_duid, sizeof g_server_duid);
    if (auto t = send_serverid.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;

    dhcp6_opt send_clientid;
    send_clientid.type(1);
    send_clientid.length(d6s.client_duid_blob.size());
    if (auto t = send_clientid.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    for (const auto &i: d6s.client_duid_blob) {
        if (ss.si == ss.se) return false;
        *(ss.si)++ = i;
    }

    if (preference_ > 0) {
        dhcp6_opt send_pref;
        send_pref.type(7);
        send_pref.length(1);
        if (auto t = send_pref.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
        if (ss.si == ss.se) return false;
        *(ss.si)++ = preference_;
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
    if (auto t = header.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    d6_ia ia;
    ia.iaid = v->iaid;
    ia.t1_seconds = static_cast<uint32_t>(0.5 * v->lifetime);
    ia.t2_seconds = static_cast<uint32_t>(0.8 * v->lifetime);
    if (auto t = ia.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    header.type(5);
    header.length(d6_ia_addr::size);
    if (auto t = header.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    d6_ia_addr addr;
    addr.addr = v->address;
    addr.prefer_lifetime = v->lifetime;
    addr.valid_lifetime = v->lifetime;
    if (auto t = addr.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    return true;
}

bool D6Listener::emit_IA_code(const d6msg_state &d6s, sbufs &ss, uint32_t iaid,
                              d6_statuscode::code scode)
{
    dhcp6_opt header;
    header.type(3);
    header.length(d6_ia::size + dhcp6_opt::size + OPT_STATUSCODE_SIZE);
    if (auto t = header.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
    d6_ia ia;
    ia.iaid = iaid;
    ia.t1_seconds = 0;
    ia.t2_seconds = 0;
    if (auto t = ia.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
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
        log_line("dhcp6: Querying duid='%s' iaid=%u...",
                 d6s.client_duid.c_str(), i.iaid);
        if (auto x = query_dhcp_state(ifname_, d6s.client_duid, i.iaid)) {
            ha = true;
            log_line("dhcp6: Found static address %s on %s", x->address.to_string().c_str(), ifname_.c_str());
            if (!emit_IA_addr(d6s, ss, x)) return false;
            continue;
        }
        bool use_dynamic;
        if (!allot_dynamic_ip(d6s, ss, i.iaid, failcode, use_dynamic)) return false;
        if (use_dynamic) ha = true;
    }
    if (!ha) log_line("dhcp6: Unable to assign any IPs on %s!", ifname_.c_str());
    if (has_addrs) *has_addrs = ha;
    return true;
}

// If opt_req.size() == 0 then send DnsServers, DomainList,
// and NtpServer.  Otherwise, for each of these types,
// see if it is in the opt_req before adding it to the reply.
bool D6Listener::attach_dns_ntp_info(const d6msg_state &d6s, sbufs &ss)
{
    const auto dns6_servers = query_dns6_servers(ifname_);
    if (!dns6_servers) return true;

    if ((!d6s.optreq_exists || d6s.optreq_dns) && dns6_servers->size()) {
        dhcp6_opt send_dns;
        send_dns.type(23);
        send_dns.length(dns6_servers->size() * 16);
        if (auto t = send_dns.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
        for (const auto &i: *dns6_servers) {
            const auto d6b = i.to_bytes();
            for (const auto &j: d6b) {
                if (ss.si == ss.se) return false;
                *(ss.si)++ = j;
            }
        }
    }
    const auto dns6_search_blob = query_dns6_search_blob(ifname_);
    if ((!d6s.optreq_exists || d6s.optreq_dns_search)
        && (dns6_search_blob && dns6_search_blob->size())) {
        dhcp6_opt send_dns_search;
        send_dns_search.type(24);
        send_dns_search.length(dns6_search_blob->size());
        if (auto t = send_dns_search.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
        for (const auto &i: *dns6_search_blob) {
            if (ss.si == ss.se) return false;
            *(ss.si)++ = i;
        }
    }
    const auto ntp6_servers = query_ntp6_servers(ifname_);
    const auto ntp6_multicasts = query_ntp6_multicasts(ifname_);
    const auto ntp6_fqdns_blob = query_ntp6_fqdns_blob(ifname_);
    if ((!d6s.optreq_exists || d6s.optreq_ntp)
        && ((ntp6_servers && ntp6_servers->size())
            || (ntp6_multicasts && ntp6_multicasts->size())
            || (ntp6_fqdns_blob && ntp6_fqdns_blob->size()))) {
        uint16_t len(0);
        dhcp6_opt send_ntp;
        send_ntp.type(56);
        if (ntp6_servers) len += 4 + ntp6_servers->size() * 16;
        if (ntp6_multicasts) len += 4 + ntp6_multicasts->size() * 16;
        if (ntp6_fqdns_blob) len += ntp6_fqdns_blob->size();
        send_ntp.length(len);
        if (auto t = send_ntp.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;

        for (const auto &i: *ntp6_servers) {
            dhcp6_opt n6_svr;
            n6_svr.type(1);
            n6_svr.length(16);
            if (auto t = n6_svr.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b) {
                if (ss.si == ss.se) return false;
                *(ss.si)++ = j;
            }
        }
        for (const auto &i: *ntp6_multicasts) {
            dhcp6_opt n6_mc;
            n6_mc.type(2);
            n6_mc.length(16);
            if (auto t = n6_mc.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b) {
                if (ss.si == ss.se) return false;
                *(ss.si)++ = j;
            }
        }
        for (const auto &i: *ntp6_fqdns_blob) {
            if (ss.si == ss.se) return false;
            *(ss.si)++ = i;
        }
    }
    if (d6s.optreq_sntp) {
        uint16_t len(0);
        dhcp6_opt send_sntp;
        send_sntp.type(31);
        if (ntp6_servers) len += ntp6_servers->size() * 16;
        send_sntp.length(len);
        if (auto t = send_sntp.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
        for (const auto &i: *ntp6_servers) {
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b) {
                if (ss.si == ss.se) return false;
                *(ss.si)++ = j;
            }
        }
    }
    return true;
}

bool D6Listener::confirm_match(const d6msg_state &d6s, bool &confirmed)
{
    confirmed = false;
    for (const auto &i: d6s.ias) {
        log_line("dhcp6: Querying duid='%s' iaid=%u...", d6s.client_duid.c_str(), i.iaid);
        if (i.ia_na_addrs.empty()) return false; // See RFC8415 18.3.3 p3
        for (const auto &j: i.ia_na_addrs) {
            if (!asio::compare_ipv6(j.addr.to_bytes(), local_ip_prefix_.to_bytes(), prefixlen_)) {
                log_line("dhcp6: Invalid prefix for IA IP %s on %s. NAK.", j.addr.to_string().c_str(), ifname_.c_str());
                return true;
            } else {
                log_line("dhcp6: IA iaid=%u has a valid prefix on %s", i.iaid, ifname_.c_str());
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
        log_line("dhcp6: Marking duid='%s' iaid=%u unused on %s...", d6s.client_duid.c_str(), i.iaid, ifname_.c_str());
        auto x = query_dhcp_state(ifname_, d6s.client_duid, i.iaid);
        for (const auto &j: i.ia_na_addrs) {
            if (x && j.addr == x->address) {
                log_line("dhcp6: found static lease on %s", ifname_.c_str());
                freed_ia_addr = true;
            } else if (dynlease_del(ifname_, j.addr, d6s.client_duid.c_str(), i.iaid)) {
                log_line("dhcp6: found dynamic lease on %s", ifname_.c_str());
                freed_ia_addr = true;
            }
        }
        if (!freed_ia_addr) {
            if (!emit_IA_code(d6s, ss, i.iaid, d6_statuscode::code::nobinding)) return false;
            log_line("dhcp6: no dynamic lease found on %s", ifname_.c_str());
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
        if (auto t = rapid_commit.write(ss.si, ss.se - ss.si); t >=0) ss.si += t; else return false;
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
    log_line("dhcp6: Sending Information Message in response on %s", ifname_.c_str());
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
        log_line("dhcp6: Received malformed message on %s", ifname_.c_str()); \
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
    return d6s.server_duid_blob.size() != sizeof g_server_duid
        || memcmp(d6s.server_duid_blob.data(), g_server_duid, sizeof g_server_duid);
}

void D6Listener::process_receive(char *buf, std::size_t buflen,
                                 const sockaddr_in6 &sai, socklen_t sailen)
{
    (void)sailen;
    char sip_str[32];
    if (!sa6_to_string(sip_str, sizeof sip_str, &sai)) {
        log_line("dhcp6: Failed to stringize sender ip on %s", ifname_.c_str());
        return;
    }

    sbufs rs{ buf, buf + buflen };
    if (!using_bpf_) {
        // Discard if the DHCP6 length < the size of a DHCP6 header.
        if (buflen < dhcp6_header::size) {
            log_line("dhcp6: Packet from %s is too short (%zu) on %s",
                     sip_str, buflen, ifname_.c_str());
            return;
        }
    }

    d6msg_state d6s;
    if (auto t = d6s.header.read(rs.si, rs.se - rs.si); t >= 0) {
        rs.si += t;
        OPTIONS_CONSUME(t);
    } else {
        log_line("dhcp6: Packet from %s has no valid option headers on %s",
                 sip_str, ifname_.c_str());
        return;
    }

    log_line("dhcp6: Message (%s) on %s",
             dhcp6_msgtype_to_string(d6s.header.msg_type()), ifname_.c_str());

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

     while ((rs.se - rs.si) >= 4) {
         dhcp6_opt opt;
         if (auto t = opt.read(rs.si, rs.se - rs.si); t >= 0) {
             rs.si += t;
             OPTIONS_CONSUME(t);
         } else return;
         log_line("dhcp6: Option '%s' length=%zu on %s",
                  dhcp6_opt_to_string(opt.type()), opt.length(), ifname_.c_str());
         auto l = opt.length();
         auto ot = opt.type();

         if (l > (rs.se - rs.si)) {
             log_line("dhcp6: Option is too long on %s", ifname_.c_str());
             return;
         }

         if (ot == 1) { // ClientID
             d6s.client_duid_blob.reserve(l);
             d6s.client_duid.reserve(2*l);
             while (l--) {
                 uint8_t c = *(rs.si)++;
                 d6s.client_duid_blob.push_back(c);
                 char tbuf[16];
                 snprintf(tbuf, sizeof tbuf, "%.2hhx", c); // fixed len, safe
                 d6s.client_duid.append(tbuf);
                 OPTIONS_CONSUME(1);
             }
             if (d6s.client_duid.size() > 0)
                log_line("dhcp6: DUID %s on %s", d6s.client_duid.c_str(), ifname_.c_str());
         } else if (ot == 2) { // ServerID
             d6s.server_duid_blob.reserve(l);
             std::string tmpstr;
             while (l--) {
                 uint8_t c = *(rs.si)++;
                 d6s.server_duid_blob.push_back(c);
                 char tbuf[16];
                 snprintf(tbuf, sizeof tbuf, "%.2hhx", c); // fixed len, safe
                 tmpstr.append(tbuf);
                 OPTIONS_CONSUME(1);
             }
             if (tmpstr.size() > 0)
                log_line("dhcp6: Server DUID '%s' len %zu on %s", tmpstr,
                         d6s.server_duid_blob.size(), ifname_.c_str());
         } else if (ot == 3) { // Option_IA_NA
             if (l < 12) {
                 log_line("dhcp6: Client-sent option IA_NA has a bad length on %s", ifname_.c_str());
                 return;
             }
             d6s.ias.emplace_back();
             if (auto t = d6s.ias.back().read(rs.si, rs.se - rs.si); t >= 0) {
                 rs.si += t;
                 OPTIONS_CONSUME(t);
             } else
                 return;

             const auto na_options_len = l - 12;
             if (na_options_len > 0)
                 d6s.prev_opt.emplace_back(std::make_pair(3, na_options_len));

             log_line("dhcp6: IA_NA: iaid=%u t1=%us t2=%us opt_len=%u on %s",
                      d6s.ias.back().iaid, d6s.ias.back().t1_seconds,
                      d6s.ias.back().t2_seconds, na_options_len, ifname_.c_str());
         } else if (ot == 5) { // Address
             if (l < 24) {
                 log_line("dhcp6: Client-sent option IAADDR has a bad length (%u) on %s", l, ifname_.c_str());
                 return;
             }
             if (d6s.prev_opt.size() != 1) {
                 log_line("dhcp6: Client-sent option IAADDR is not nested on %s", ifname_.c_str());
                 return;
             }
             if (d6s.prev_opt.back().first != 3) {
                 log_line("dhcp6: Client-sent option IAADDR must follow IA_NA on %s", ifname_.c_str());
                 return;
             }
             if (d6s.ias.empty())
                 suicide("dhcp6: d6.ias is empty on %s", ifname_.c_str());
             d6s.ias.back().ia_na_addrs.emplace_back();
             if (d6s.ias.back().ia_na_addrs.empty())
                 suicide("dhcp6: d6.ias.back().ia_na_addrs is empty on %s", ifname_.c_str());
             if (auto t = d6s.ias.back().ia_na_addrs.back().read(rs.si, rs.se - rs.si); t >= 0) {
                 rs.si += t;
                 OPTIONS_CONSUME(t);
             } else return;

             auto iaa_options_len = l - 24;
             if (iaa_options_len > 0)
                 d6s.prev_opt.emplace_back(std::make_pair(5, iaa_options_len));

             log_line("dhcp6: IA Address: %s prefer=%us valid=%us opt_len=%zu on %s",
                      d6s.ias.back().ia_na_addrs.back().addr.to_string().c_str(),
                      d6s.ias.back().ia_na_addrs.back().prefer_lifetime,
                      d6s.ias.back().ia_na_addrs.back().valid_lifetime,
                      iaa_options_len, ifname_.c_str());

         } else if (ot == 6) { // OptionRequest
             if (l % 2) {
                 log_line("dhcp6: Client-sent option Request has a bad length (%zu) on %s", l, ifname_.c_str());
                 return;
             }
             d6s.optreq_exists = true;
             l /= 2;
             while (l--) {
                 char b[2];
                 b[1] = *(rs.si)++;
                 b[0] = *(rs.si)++;
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
             log_line("dhcp6: Option Request%s%s%s%s%s on %s",
                      d6s.optreq_dns ? " DNS" : "",
                      d6s.optreq_dns_search ? " DNS_SEARCH" : "",
                      d6s.optreq_sntp ? " SNTP" : "",
                      d6s.optreq_info_refresh_time ? " INFO_REFRESH" : "",
                      d6s.optreq_ntp ? " NTP" : "",
                      ifname_.c_str());
         } else if (ot == 8) { // ElapsedTime
             // 16-bit hundreths of a second since start of exchange
             if (l != 2) {
                 log_line("dhcp6: Client-sent option ElapsedTime has a bad length on %s", ifname_.c_str());
                 return;
             }
             char b[2];
             b[1] = *(rs.si)++;
             b[0] = *(rs.si)++;
             OPTIONS_CONSUME(2);
             memcpy(&d6s.elapsed_time, b, 2);
         } else if (ot == 14) { // Rapid Commit
             if (l != 0) {
                 log_line("dhcp6: Client-sent option Rapid Commit has a bad length on %s", ifname_.c_str());
                 return;
             }
             d6s.use_rapid_commit = true;
         } else if (ot == 39) { // Client FQDN
             log_line("dhcp6: FQDN Length: %zu", l);
             if (l < 3) {
                 log_line("dhcp6: Client-sent option Client FQDN has a bad length on %s", ifname_.c_str());
                 return;
             }
             char flags;
             uint8_t namelen;
             namelen = *(rs.si)++;
             flags = *(rs.si)++;
             OPTIONS_CONSUME(2);
             l -= 2;
             if (l != namelen) {
                 log_line("dhcp6: Client-sent option Client FQDN namelen disagrees with length on %s", ifname_.c_str());
                 return;
             }
             d6s.fqdn_.clear();
             d6s.fqdn_.reserve(namelen);
             log_line("dhcp6: FQDN Flags='{}', NameLen='{}' on %s", +flags, +namelen, ifname_.c_str());
             while (l--) {
                 char c = *(rs.si)++;
                 OPTIONS_CONSUME(1);
                 d6s.fqdn_.push_back(c);
             }
             log_line("dhcp6: Client FQDN: flags='%u' '%s' on %s",
                      static_cast<uint8_t>(flags), d6s.fqdn_.c_str(), ifname_.c_str());
         } else {
             while (l--) {
                 rs.si += l;
                 OPTIONS_CONSUME(l);
             }
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
         if (!d6s.server_duid_blob.empty()) return;
         if (!handle_solicit_msg(d6s, ss)) return;
     case dhcp6_msgtype::request:
         if (serverid_incorrect(d6s)) return;
         if (!handle_request_msg(d6s, ss)) return;
     case dhcp6_msgtype::confirm:
         if (!d6s.server_duid_blob.empty()) return;
         if (!handle_confirm_msg(d6s, ss)) return;
         break;
     case dhcp6_msgtype::renew:
         if (serverid_incorrect(d6s)) return;
         if (!handle_renew_msg(d6s, ss)) return;
     case dhcp6_msgtype::rebind:
         if (!d6s.server_duid_blob.empty()) return;
         if (!handle_rebind_msg(d6s, ss)) return;
     case dhcp6_msgtype::release:
         if (serverid_incorrect(d6s)) return;
         if (!handle_release_msg(d6s, ss)) return;
     case dhcp6_msgtype::decline:
         if (serverid_incorrect(d6s)) return;
         if (!handle_decline_msg(d6s, ss)) return;
     case dhcp6_msgtype::information_request:
         if (!d6s.server_duid_blob.empty() && serverid_incorrect(d6s)) return;
         if (!d6s.ias.empty()) return;
         if (!handle_information_msg(d6s, ss)) return;
     default: return;
     }

     const size_t slen = ss.si - sbuf;
     if (safe_sendto(fd_(), sbuf, slen, 0, reinterpret_cast<const sockaddr *>(&sai), sizeof sai) < 0) {
         log_warning("dhcp6: sendto failed on %s: %s", ifname_.c_str(), strerror(errno));
         return;
     }
}

