#include <format.hpp>
#include <nk/xorshift.hpp>
#include "nlsocket.hpp"
#include "multicast6.hpp"
#include "dhcp6.hpp"
#include "dynlease.hpp"
#include "attach_bpf.h"
#include "asio_addrcmp.hpp"
#include "duid.hpp"

#define MAX_DYN_LEASES 1000u
#define MAX_DYN_ATTEMPTS 100u

extern std::unique_ptr<NLSocket> nl_socket;
extern nk::rng::xoroshiro128p g_random_prng;
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
        b[i] = g_random_prng();
    uint8_t c = g_random_prng();
    b[i] |= c & (0xff >> keep_r_bits);
    return asio::ip::address_v6(b, prefix.scope_id());
}

D6Listener::D6Listener(asio::io_service &io_service,
                       const std::string &ifname, uint8_t preference)
  : socket_(io_service), ifname_(ifname), using_bpf_(false), preference_(preference)
{
    int ifidx = nl_socket->get_ifindex(ifname_);
    const auto &ifinfo = nl_socket->interfaces.at(ifidx);

    fmt::print("DHCPv6 Preference for interface {} is {}.\n", ifname_, preference_);

    for (const auto &i: ifinfo.addrs) {
        if (i.scope == netif_addr::Scope::Global && i.address.is_v6()) {
            local_ip_ = i.address.to_v6();
            prefixlen_ = i.prefixlen;
            local_ip_prefix_ = mask_v6_addr(local_ip_, prefixlen_);
            fmt::print(stderr, "IP address for {} is {}/{}.  Prefix is {}.\n",
                       ifname, local_ip_, +prefixlen_, local_ip_prefix_);
        } else if (i.scope == netif_addr::Scope::Link && i.address.is_v6()) {
            link_local_ip_ = i.address.to_v6();
            fmt::print(stderr, "Link-local IP address for {} is {}.\n",
                       ifname, link_local_ip_);
        }
    }
    socket_.open(asio::ip::udp::v6());
    attach_multicast(socket_.native(), ifname, mc6_alldhcp_ras);
    attach_bpf(socket_.native());
    socket_.bind(asio::ip::udp::endpoint(asio::ip::address_v6::any(), 547));

    radv6_listener_ = std::make_unique<RA6Listener>(io_service, ifname);

    start_receive();
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
    default:
             fmt::print("Unknown DHCP Option type: {}\n", opttype);
             return "Unknown";
    }
}

bool D6Listener::allot_dynamic_ip(const d6msg_state &d6s, std::ostream &os, uint32_t iaid,
                                  d6_statuscode::code failcode)
{
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v6(ifname_, dynamic_lifetime)) {
        emit_IA_code(d6s, os, iaid, failcode);
        return false;
    }

    fmt::print("\tChecking dynamic IP...\n");

    const auto expire_time = get_current_ts() + dynamic_lifetime;

    auto v6a = dynlease_query_refresh(ifname_, d6s.client_duid, iaid, expire_time);
    if (v6a != asio::ip::address_v6::any()) {
        dhcpv6_entry de(iaid, v6a, dynamic_lifetime);
        emit_IA_addr(d6s, os, &de);
        fmt::print("\tAssigned existing dynamic IP: {}.\n", v6a.to_string());
        return true;
    }
    // This check guards against OOM via DoS.
    if (dynlease6_count(ifname_) >= MAX_DYN_LEASES) {
        fmt::print("\tMaximum number of dynamic leases on {} ({}) reached.\n",
                   ifname_, MAX_DYN_LEASES);
        emit_IA_code(d6s, os, iaid, failcode);
        return false;
    }
    fmt::print("\tSelecting an unused dynamic IP.\n");

    // Given a prefix, choose a random address.  Then check it against our
    // existing static and dynamic leases.  If no collision, assign a
    // dynamic lease to the random address and return it.
    for (unsigned attempt = 0; attempt < MAX_DYN_ATTEMPTS; ++attempt) {
        v6a = v6_addr_random(local_ip_prefix_, prefixlen_);
        if (!query_unused_addr(ifname_, v6a)) continue;
        const auto assigned = dynlease_add(ifname_, v6a, d6s.client_duid, iaid, expire_time);
        if (assigned) {
            dhcpv6_entry de(iaid, v6a, dynamic_lifetime);
            emit_IA_addr(d6s, os, &de);
            return true;
        }
    }
    fmt::print("\tUnable to select an unused dynamic IP after {} attempts.\n",
               MAX_DYN_ATTEMPTS);
    emit_IA_code(d6s, os, iaid, failcode);
    return false;
}

#define OPT_STATUSCODE_SIZE (4)

void D6Listener::attach_status_code(const d6msg_state &d6s, std::ostream &os,
                                    d6_statuscode::code scode)
{
    static char ok_str[] = "OK";
    static char nak_str[] = "NO";
    dhcp6_opt header;
    header.type(13);
    header.length(OPT_STATUSCODE_SIZE);
    os << header;
    d6_statuscode sc(scode);
    os << sc;
    if (scode == d6_statuscode::code::success) {
        for (int i = 0; ok_str[i]; ++i)
            os << ok_str[i];
    } else {
        for (int i = 0; nak_str[i]; ++i)
            os << nak_str[i];
    }
}

void D6Listener::write_response_header(const d6msg_state &d6s, std::ostream &os,
                                       dhcp6_msgtype mtype)
{
    dhcp6_header send_d6hdr;
    send_d6hdr.msg_type(mtype);
    send_d6hdr.xid(d6s.header.xid());
    os << send_d6hdr;

    dhcp6_opt_serverid send_serverid(g_server_duid, sizeof g_server_duid);
    os << send_serverid;

    dhcp6_opt send_clientid;
    send_clientid.type(1);
    send_clientid.length(d6s.client_duid_blob.size());
    os << send_clientid;
    for (const auto &i: d6s.client_duid_blob)
        os << i;

    if (preference_ > 0) {
        dhcp6_opt send_pref;
        send_pref.type(7);
        send_pref.length(1);
        os << send_pref;
        os << preference_;
    }
}

// We control what IAs are valid, and we never assign multiple address to a single
// IA.  Thus there's no reason to care about that case.
void D6Listener::emit_IA_addr(const d6msg_state &d6s, std::ostream &os, const dhcpv6_entry *v)
{
    dhcp6_opt header;
    header.type(3);
    header.length(d6_ia::size + dhcp6_opt::size + d6_ia_addr::size);
    os << header;
    d6_ia ia;
    ia.iaid = v->iaid;
    ia.t1_seconds = static_cast<uint32_t>(0.5 * v->lifetime);
    ia.t2_seconds = static_cast<uint32_t>(0.8 * v->lifetime);
    os << ia;
    header.type(5);
    header.length(d6_ia_addr::size);
    os << header;
    d6_ia_addr addr;
    addr.addr = v->address;
    addr.prefer_lifetime = v->lifetime;
    addr.valid_lifetime = v->lifetime;
    os << addr;
}

void D6Listener::emit_IA_code(const d6msg_state &d6s, std::ostream &os, uint32_t iaid,
                              d6_statuscode::code scode)
{
    dhcp6_opt header;
    header.type(3);
    header.length(d6_ia::size + dhcp6_opt::size + OPT_STATUSCODE_SIZE);
    os << header;
    d6_ia ia;
    ia.iaid = iaid;
    ia.t1_seconds = 0;
    ia.t2_seconds = 0;
    os << ia;
    attach_status_code(d6s, os, scode);
}

// Returns false if no addresses would be assigned.
bool D6Listener::attach_address_info(const d6msg_state &d6s, std::ostream &os,
                                     d6_statuscode::code failcode)
{
    bool ret{false};
    // Look through IAs and send IA with assigned address as an option.
    for (const auto &i: d6s.ias) {
        printf("Querying duid='%s' iaid=%u...\n", d6s.client_duid.c_str(), i.iaid);
        auto x = query_dhcp_state(ifname_, d6s.client_duid, i.iaid);
        if (x) {
            ret = true;
            fmt::print("\tFound static address: {}\n", x->address.to_string());
            emit_IA_addr(d6s, os, x);
            continue;
        }
        if (allot_dynamic_ip(d6s, os, i.iaid, failcode)) {
            ret = true;
            continue;
        }
        emit_IA_code(d6s, os, i.iaid, failcode);
    }
    if (!ret)
        fmt::print("\tUnable to assign any IPs!\n");
    return ret;
}

// If opt_req.size() == 0 then send DnsServers, DomainList,
// and NtpServer.  Otherwise, for each of these types,
// see if it is in the opt_req before adding it to the reply.
void D6Listener::attach_dns_ntp_info(const d6msg_state &d6s, std::ostream &os)
{
    const auto dns6_servers = query_dns6_servers(ifname_);
    if ((!d6s.optreq_exists || d6s.optreq_dns) && dns6_servers.size()) {
        dhcp6_opt send_dns;
        send_dns.type(23);
        send_dns.length(dns6_servers.size() * 16);
        os << send_dns;
        for (const auto &i: dns6_servers) {
            const auto d6b = i.to_bytes();
            for (const auto &j: d6b)
                os << j;
        }
    }
    const auto dns6_search_blob = query_dns6_search_blob(ifname_);
    if ((!d6s.optreq_exists || d6s.optreq_dns_search)
        && dns6_search_blob.size()) {
        dhcp6_opt send_dns_search;
        send_dns_search.type(24);
        send_dns_search.length(dns6_search_blob.size());
        os << send_dns_search;
        for (const auto &i: dns6_search_blob)
            os << i;
    }
    const auto ntp6_servers = query_ntp6_servers(ifname_);
    const auto ntp6_multicasts = query_ntp6_multicasts(ifname_);
    const auto ntp6_fqdns_blob = query_ntp6_fqdns_blob(ifname_);
    const auto n6s_size = ntp6_servers.size();
    const auto n6m_size = ntp6_multicasts.size();
    const auto n6d_size = ntp6_fqdns_blob.size();
    if ((!d6s.optreq_exists || d6s.optreq_ntp)
        && (n6s_size || n6m_size || n6d_size)) {
        uint16_t len(0);
        dhcp6_opt send_ntp;
        send_ntp.type(56);
        if (n6s_size)
            len += 4 + n6s_size * 16;
        if (n6m_size)
            len += 4 + n6m_size * 16;
        if (n6d_size)
            len += n6d_size;
        send_ntp.length(len);
        os << send_ntp;

        for (const auto &i: ntp6_servers) {
            uint16_t soc(1);
            uint16_t sol(16);
            os << soc << sol;
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b)
                os << j;
        }
        for (const auto &i: ntp6_multicasts) {
            uint16_t soc(2);
            uint16_t sol(16);
            os << soc << sol;
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b)
                os << j;
        }
        for (const auto &i: ntp6_fqdns_blob)
            os << i;
    }
    if (d6s.optreq_sntp) {
        uint16_t len(0);
        dhcp6_opt send_sntp;
        send_sntp.type(31);
        if (n6s_size)
            len += n6s_size * 16;
        send_sntp.length(len);
        for (const auto &i: ntp6_servers) {
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b)
                os << j;
        }
    }
}

bool D6Listener::confirm_match(const d6msg_state &d6s, std::ostream &os)
{
    bool any_bad{false};
    for (const auto &i: d6s.ias) {
        bool bad_link{false};
        fmt::print("Querying duid='{}' iaid={}...\n", d6s.client_duid, i.iaid);
        for (const auto &j: i.ia_na_addrs) {
            if (!asio::compare_ipv6(j.addr.to_bytes(), local_ip_prefix_.to_bytes(), prefixlen_)) {
                fmt::print("Invalid prefix for IA IP: {}. NAK.\n", j);
                any_bad = bad_link = true;
                emit_IA_code(d6s, os, i.iaid, d6_statuscode::code::notonlink);
                break;
            }
        }
        if (!bad_link) fmt::print("\tIA iaid={} has a valid prefix.\n", i.iaid);
        emit_IA_code(d6s, os, i.iaid, d6_statuscode::code::success);
    }
    return any_bad;
}

bool D6Listener::mark_addr_unused(const d6msg_state &d6s, std::ostream &os)
{
    bool freed_addr{false};
    for (const auto &i: d6s.ias) {
        bool freed_ia_addr{false};
        fmt::print("Marking duid='{}' iaid={} unused...", d6s.client_duid, i.iaid);
        auto x = query_dhcp_state(ifname_, d6s.client_duid, i.iaid);
        for (const auto &j: i.ia_na_addrs) {
            if (x && j.addr == x->address) {
                fmt::print(" found static lease\n");
                freed_ia_addr = freed_addr = true;
            } else if (dynlease_del(ifname_, j.addr, d6s.client_duid.c_str(), i.iaid)) {
                fmt::print(" found dynamic lease\n");
                freed_ia_addr = freed_addr = true;
            }
        }
        if (!freed_ia_addr) {
            emit_IA_code(d6s, os, i.iaid, d6_statuscode::code::nobinding);
            fmt::print(" no dynamic lease found\n");
        }
    }
    return freed_addr;
}

void D6Listener::handle_solicit_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, !d6s.use_rapid_commit ? dhcp6_msgtype::advertise
                                                         : dhcp6_msgtype::reply);

    // RFC7550 says servers MUST NOT return top-level Status Code noaddrsavail.
    const auto valid = attach_address_info(d6s, os, d6_statuscode::code::noaddrsavail);
    attach_dns_ntp_info(d6s, os);

    if (valid && d6s.use_rapid_commit) {
        dhcp6_opt rapid_commit;
        rapid_commit.type(14);
        rapid_commit.length(0);
        os << rapid_commit;
    }
}

void D6Listener::handle_request_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    attach_address_info(d6s, os, d6_statuscode::code::noaddrsavail);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_confirm_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    confirm_match(d6s, os);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_renew_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    attach_address_info(d6s, os, d6_statuscode::code::nobinding);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_rebind_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    attach_address_info(d6s, os, d6_statuscode::code::nobinding);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_information_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);
    attach_dns_ntp_info(d6s, os);
    fmt::print("Sending Information Message in response.\n");
}

void D6Listener::handle_release_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);
    mark_addr_unused(d6s, os);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_decline_msg(const d6msg_state &d6s, asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);
    mark_addr_unused(d6s, os);
    attach_dns_ntp_info(d6s, os);
}

#define BYTES_LEFT_DEC(BLD_VAL) bytes_left_dec(d6s, bytes_left, (BLD_VAL))

#define CONSUME_OPT(CO_MSG) \
         fmt::print(stderr, (CO_MSG)); \
         while (l--) { \
             is.get(); \
             BYTES_LEFT_DEC(1); \
         } \
         continue

size_t D6Listener::bytes_left_dec(d6msg_state &d6s, std::size_t &bytes_left, size_t v) {
    if (bytes_left < v)
        throw std::out_of_range("bytes_left would underflow\n");
    bytes_left -= v;
    size_t option_depth{0};
    for (auto &i: d6s.prev_opt) {
        ++option_depth;
        if (i.second < v)
            throw std::out_of_range(fmt::format("{} depth would underflow\n", option_depth));
        i.second -= v;
    }
    while (!d6s.prev_opt.empty() && d6s.prev_opt.back().second == 0)
        d6s.prev_opt.pop_back();
    option_depth = 0;
    for (const auto &i: d6s.prev_opt) {
        ++option_depth;
        // Tricky: Guard against client sending invalid suboption lengths.
        if (i.second <= 0)
            throw std::out_of_range(fmt::format("{} depth ran out of length but has suboption size left\n"));
    }
    return bytes_left;
}

bool D6Listener::serverid_incorrect(const d6msg_state &d6s) const
{
    return d6s.server_duid_blob.size() != sizeof g_server_duid
        || memcmp(d6s.server_duid_blob.data(), g_server_duid, sizeof g_server_duid);
}

void D6Listener::start_receive()
{
    recv_buffer_.consume(recv_buffer_.size());
    socket_.async_receive_from
        (recv_buffer_.prepare(8192), sender_endpoint_,
         [this](const std::error_code &error, std::size_t bytes_xferred)
         {
             recv_buffer_.commit(bytes_xferred);

             std::size_t bytes_left = bytes_xferred;
             if (!using_bpf_) {
                 // Discard if the DHCP6 length < the size of a DHCP6 header.
                 if (bytes_xferred < dhcp6_header::size) {
                    fmt::print(stderr, "DHCP6 from {} is too short: {}\n",
                               sender_endpoint_, bytes_xferred);
                    start_receive();
                    return;
                 }
             }

             std::istream is(&recv_buffer_);
             d6msg_state d6s;
             is >> d6s.header;
             BYTES_LEFT_DEC(dhcp6_header::size);

             fmt::print(stderr, "DHCP Message: {}\n",
                        dhcp6_msgtype_to_string(d6s.header.msg_type()));

             // These message types are not allowed to be sent to servers.
             if (!using_bpf_) {
                 switch (d6s.header.msg_type()) {
                 case dhcp6_msgtype::advertise:
                 case dhcp6_msgtype::reply:
                 case dhcp6_msgtype::reconfigure:
                 case dhcp6_msgtype::relay_reply:
                     start_receive(); return;
                 default: break;
                 }
             }

             while (bytes_left >= 4) {
                 //fmt::print(stderr, "bytes_left={}\n", bytes_left);
                 dhcp6_opt opt;
                 is >> opt;
                 fmt::print(stderr, "Option: '{}' length={}\n",
                            dhcp6_opt_to_string(opt.type()), opt.length());
                 BYTES_LEFT_DEC(dhcp6_opt::size);
                 auto l = opt.length();
                 auto ot = opt.type();

                 if (l > bytes_left) {
                     fmt::print(stderr, "Option is too long.\n");
                     while (bytes_left) {
                         BYTES_LEFT_DEC(1);
                         is.get();
                     }
                     continue;
                 }

                 if (ot == 1) { // ClientID
                     d6s.client_duid_blob.reserve(l);
                     d6s.client_duid.reserve(2*l);
                     while (l--) {
                         uint8_t c = is.get();
                         d6s.client_duid_blob.push_back(c);
                         d6s.client_duid.append(fmt::sprintf("%02.x", c));
                         BYTES_LEFT_DEC(1);
                     }
                     if (d6s.client_duid.size() > 0)
                        fmt::print("\tDUID: {}\n", d6s.client_duid);
                 } else if (ot == 2) { // ServerID
                     d6s.server_duid_blob.reserve(l);
                     std::string tmpstr;
                     while (l--) {
                         uint8_t c = is.get();
                         d6s.server_duid_blob.push_back(c);
                         tmpstr.append(fmt::sprintf("%02.x", c));
                         BYTES_LEFT_DEC(1);
                     }
                     if (tmpstr.size() > 0)
                        fmt::print("\tServer DUID: '{}' len: {}\n", tmpstr,
                                   d6s.server_duid_blob.size());
                 } else if (ot == 3) { // Option_IA_NA
                     if (l < 12) {
                         CONSUME_OPT("Client-sent option IA_NA has a bad length.  Ignoring.\n");
                     }
                     d6s.ias.emplace_back();
                     is >> d6s.ias.back();
                     BYTES_LEFT_DEC(d6_ia::size);

                     const auto na_options_len = l - 12;
                     if (na_options_len > 0)
                         d6s.prev_opt.emplace_back(std::make_pair(3, na_options_len));

                     fmt::printf("\tIA_NA: iaid=%u t1=%us t2=%us opt_len=%u\n",
                                d6s.ias.back().iaid, d6s.ias.back().t1_seconds,
                                d6s.ias.back().t2_seconds, na_options_len);
                 } else if (ot == 5) { // Address
                     if (l < 24) {
                         CONSUME_OPT("Client-sent option IAADDR has a bad length.  Ignoring.\n");
                     }
                     if (d6s.prev_opt.size() != 1) {
                         CONSUME_OPT("Client-sent option IAADDR is not nested.  Ignoring.\n");
                     }
                     if (d6s.prev_opt.back().first != 3) {
                         CONSUME_OPT("Client-sent option IAADDR must follow IA_NA.  Ignoring.\n");
                     }
                     if (d6s.ias.empty())
                         throw std::logic_error("d6.ias is empty");
                     d6s.ias.back().ia_na_addrs.emplace_back();
                     if (d6s.ias.back().ia_na_addrs.empty())
                         throw std::logic_error("d6.ias.back().ia_na_addrs is empty");
                     is >> d6s.ias.back().ia_na_addrs.back();
                     BYTES_LEFT_DEC(d6_ia_addr::size);

                     auto iaa_options_len = l - 24;
                     if (iaa_options_len > 0)
                         d6s.prev_opt.emplace_back(std::make_pair(5, iaa_options_len));

                     fmt::print("\tIA Address: {} prefer={}s valid={}s opt_len={}\n",
                                d6s.ias.back().ia_na_addrs.back().addr.to_string(),
                                d6s.ias.back().ia_na_addrs.back().prefer_lifetime,
                                d6s.ias.back().ia_na_addrs.back().valid_lifetime,
                                iaa_options_len);

                 } else if (ot == 6) { // OptionRequest
                     if (l % 2) {
                         CONSUME_OPT("Client-sent option Request has a bad length.  Ignoring.\n");
                     }
                     d6s.optreq_exists = true;
                     l /= 2;
                     fmt::print("\tOption Request:");
                     while (l--) {
                         char b[2];
                         b[1] = is.get();
                         b[0] = is.get();
                         BYTES_LEFT_DEC(2);
                         uint16_t v;
                         memcpy(&v, b, 2);
                         switch (v) {
                         case 23: d6s.optreq_dns = true; fmt::print(" DNS"); break;
                         case 24: d6s.optreq_dns_search = true; fmt::print(" DNS_SEARCH"); break;
                         case 31: d6s.optreq_sntp = true; fmt::print(" SNTP"); break;
                         case 32: d6s.optreq_info_refresh_time = true; fmt::print(" INFO_REFRESH"); break;
                         case 56: d6s.optreq_ntp = true; fmt::print(" NTP"); break;
                         default: fmt::print(" {}", v); break;
                         }
                     }
                     fmt::print("\n");
                     fmt::print("\tOptions requested: dns={} dns_search={} info_refresh={} ntp={}\n",
                                d6s.optreq_dns, d6s.optreq_dns_search,
                                d6s.optreq_info_refresh_time, d6s.optreq_ntp);
                 } else if (ot == 8) { // ElapsedTime
                     // 16-bit hundreths of a second since start of exchange
                     if (l != 2) {
                         CONSUME_OPT("Client-sent option ElapsedTime has a bad length.  Ignoring.\n");
                     }
                     char b[2];
                     b[1] = is.get();
                     b[0] = is.get();
                     BYTES_LEFT_DEC(2);
                     memcpy(&d6s.elapsed_time, b, 2);
                 } else if (ot == 14) { // Rapid Commit
                     if (l != 0) {
                         CONSUME_OPT("Client-sent option Rapid Commit has a bad length.  Ignoring.\n");
                     }
                     d6s.use_rapid_commit = true;
                 } else if (ot == 39) { // Client FQDN
                     fmt::print("\tFQDN Length: {}\n", l);
                     if (l < 3) {
                         CONSUME_OPT("Client-sent option Client FQDN has a bad length.  Ignoring.\n");
                     }
                     char flags;
                     uint8_t namelen;
                     flags = is.get();
                     namelen = is.get();
                     BYTES_LEFT_DEC(2);
                     l -= 2;
                     if (l != namelen) {
                         CONSUME_OPT("Client-sent option Client FQDN namelen disagrees with length.  Ignoring.\n");
                     }
                     d6s.fqdn_.clear();
                     d6s.fqdn_.reserve(namelen);
                     fmt::print("\tFQDN Flags='{}', NameLen='{}'\n", +flags, +namelen);
                     while (l--) {
                        char c;
                        c = is.get();
                        BYTES_LEFT_DEC(1);
                        d6s.fqdn_.push_back(c);
                     }
                     fmt::print("\tClient FQDN: flags={} '{}'\n",
                                static_cast<uint8_t>(flags), d6s.fqdn_);
                 } else {
                     while (l--) {
                         is.get();
                         BYTES_LEFT_DEC(1);
                     }
                 }
             }

             std::error_code ec;
             asio::streambuf send_buffer;

             // Clients are required to send a client identifier.
             if (d6s.client_duid.empty() &&
                 d6s.header.msg_type() != dhcp6_msgtype::information_request)
                 goto skip_send;

             switch (d6s.header.msg_type()) {
             case dhcp6_msgtype::solicit:
                 if (!d6s.server_duid_blob.empty()) goto skip_send;
                 handle_solicit_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::request:
                 if (serverid_incorrect(d6s)) goto skip_send;
                 handle_request_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::confirm:
                 if (!d6s.server_duid_blob.empty()) goto skip_send;
                 handle_confirm_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::renew:
                 if (serverid_incorrect(d6s)) goto skip_send;
                 handle_renew_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::rebind:
                 if (!d6s.server_duid_blob.empty()) goto skip_send;
                 handle_rebind_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::release:
                 if (serverid_incorrect(d6s)) goto skip_send;
                 handle_release_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::decline:
                 if (serverid_incorrect(d6s)) goto skip_send;
                 handle_decline_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::information_request:
                 if (!d6s.server_duid_blob.empty() && serverid_incorrect(d6s)) goto skip_send;
                 if (!d6s.ias.empty()) goto skip_send;
                 handle_information_msg(d6s, send_buffer); break;
             default: start_receive(); return;
             }

             socket_.send_to(send_buffer.data(), sender_endpoint_, 0, ec);
skip_send:
             start_receive();
         });
}

