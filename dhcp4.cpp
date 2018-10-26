/* dhcpclient.cpp - dhcp client request handling
 *
 * Copyright 2011-2017 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <fmt/format.h>
#include <nk/prng.hpp>
#include "dhcp4.hpp"
#include "dhcp_state.hpp"
#include "nlsocket.hpp"
#include "dynlease.hpp"
extern "C" {
#include "options.h"
}

extern std::unique_ptr<NLSocket> nl_socket;
extern nk::rng::prng g_random_prng;
extern int64_t get_current_ts();

static std::unique_ptr<ClientStates> client_states_v4;
static void init_client_states_v4(asio::io_service &io_service)
{
    static bool was_initialized;
    if (was_initialized) return;
    client_states_v4 = std::make_unique<ClientStates>(io_service);
}

D4Listener::D4Listener(asio::io_service &io_service, const std::string &ifname)
 : socket_(io_service), ifname_(ifname)
{
    init_client_states_v4(io_service);
    const auto endpoint = asio::ip::udp::endpoint(asio::ip::address_v4::any(), 67);
    socket_.open(endpoint.protocol());
    socket_.set_option(asio::ip::udp::socket::broadcast(true));
    socket_.set_option(asio::ip::udp::socket::do_not_route(true));
    socket_.set_option(asio::ip::udp::socket::reuse_address(true));
    socket_.bind(endpoint);
    int fd = socket_.native_handle();

    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        fmt::print(stderr, "failed to bind socket to device: {}\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int ifidx = nl_socket->get_ifindex(ifname_);
    const auto &ifinfo = nl_socket->interfaces.at(ifidx);
    for (const auto &i: ifinfo.addrs) {
        if (i.address.is_v4()) {
            local_ip_ = i.address.to_v4();
            fmt::print(stderr, "IP address for {} is {}.\n", ifname, local_ip_);
        }
    }
    if (!local_ip_.is_v4()) {
        fmt::print(stderr, "interface ({}) has no IP address\n", ifname);
        exit(EXIT_FAILURE);
    }

    start_receive();
}

void D4Listener::dhcpmsg_init(dhcpmsg &dm, char type, uint32_t xid) const
{
    memset(&dm, 0, sizeof (struct dhcpmsg));
    dm.op = 2; // BOOTREPLY (server)
    dm.htype = 1;
    dm.hlen = 6;
    dm.xid = xid;
    dm.cookie = htonl(DHCP_MAGIC);
    dm.options[0] = DCODE_END;
    memcpy(&dm.chaddr, &dhcpmsg_.chaddr, sizeof dhcpmsg_.chaddr);
    add_option_msgtype(&dm, type);
    add_option_serverid(&dm, local_ip());
}

uint32_t D4Listener::local_ip() const
{
    uint32_t ret;
    if (inet_pton(AF_INET, local_ip_.to_string().c_str(), &ret) != 1) {
        fmt::print(stderr, "inet_pton failed: {}\n", strerror(errno));
        return 0;
    }
    return ret;
}

void D4Listener::send_reply_do(const dhcpmsg &dm, SendReplyType srt)
{
    ssize_t endloc = get_end_option_idx(&dm);
    if (endloc < 0)
        return;

    std::error_code ignored_error;
    auto buf = asio::buffer((const char *)&dm, sizeof dm -
                            (sizeof dm.options - 1 - endloc));

    switch (srt) {
    case SendReplyType::UnicastCi: {
        auto uct = asio::ip::address_v4(ntohl(dhcpmsg_.ciaddr));
        socket_.send_to(buf, asio::ip::udp::endpoint(uct, 68), 0, ignored_error);
        break;
    }
    case SendReplyType::Broadcast: {
        auto remotebcast = remote_endpoint_.address().to_v4().broadcast();
        socket_.send_to(buf, asio::ip::udp::endpoint(remotebcast, 68),
                        0, ignored_error);
        break;
    }
    case SendReplyType::Relay: {
        auto relay = asio::ip::address_v4(ntohl(dhcpmsg_.giaddr));
        socket_.send_to(buf, asio::ip::udp::endpoint(relay, 67),
                        0, ignored_error);
        break;
    }
    case SendReplyType::UnicastYiCh: {
        auto uct = asio::ip::address_v4(ntohl(dhcpmsg_.yiaddr));
        socket_.send_to(buf, asio::ip::udp::endpoint(uct, 68), 0, ignored_error);
        break;
    }
    }
}

std::string D4Listener::ipStr(uint32_t ip) const
{
    char addrbuf[INET_ADDRSTRLEN];
    auto r = inet_ntop(AF_INET, &ip, addrbuf, sizeof addrbuf);
    if (!r)
        return std::string("");
    return std::string(addrbuf);
}

void D4Listener::send_reply(const dhcpmsg &reply)
{
    if (dhcpmsg_.giaddr)
        send_reply_do(reply, SendReplyType::Relay);
    else if (dhcpmsg_.ciaddr)
        send_reply_do(reply, SendReplyType::UnicastCi);
    else if (ntohs(dhcpmsg_.flags) & 0x8000u)
        send_reply_do(reply, SendReplyType::Broadcast);
    else if (dhcpmsg_.yiaddr)
        send_reply_do(reply, SendReplyType::UnicastYiCh);
    else
        send_reply_do(reply, SendReplyType::Broadcast);
}

bool D4Listener::iplist_option(dhcpmsg &reply, std::string &iplist, uint8_t code,
                               const std::vector<asio::ip::address_v4> &addrs)
{
        iplist.clear();
        iplist.reserve(addrs.size() * 4);
        for (const auto &i: addrs) {
            const auto ip32 = htonl(i.to_ulong());
            char ip8[4];
            memcpy(ip8, &ip32, sizeof ip8);
            iplist.append(ip8, 4);
        }
        if (!iplist.size()) return false;
        add_option_string(&reply, code, iplist.c_str(), iplist.size());
        return true;
}

bool D4Listener::allot_dynamic_ip(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign)
{
    using aia4 = asio::ip::address_v4;
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v4(ifname_, dynamic_lifetime))
        return false;

    fmt::print(stderr, "Checking dynamic IP.\n");

    const auto dr = query_dynamic_range(ifname_);
    const auto expire_time = get_current_ts() + dynamic_lifetime;

    auto v4a = dynlease_query_refresh(ifname_, hwaddr, expire_time);
    if (v4a != asio::ip::address_v4::any()) {
        reply.yiaddr = htonl(v4a.to_ulong());
        add_u32_option(&reply, DCODE_LEASET, htonl(dynamic_lifetime));
        fmt::print(stderr, "Assigned existing dynamic IP: {}.\n", v4a.to_string());
        return true;
    }
    fmt::print(stderr, "Selecting an unused dynamic IP.\n");

    // IP is randomly selected from the dynamic range.
    const auto al = dr.first.to_ulong();
    const auto ah = dr.second.to_ulong();
    const auto ar = ah - al;
    std::uniform_int_distribution<> dist(0, ar);
    unsigned long rqs = dist(g_random_prng);

    // OK, here we have bisected our range using rqs.
    // [al .. ah] => [al .. rqs .. ah]
    // So we scan from [rqs, ah], taking the first empty slot.
    // If no success, scan from [al, rqs), taking the first empty slot.
    // If no success, then all IPs are taken, so return false.
    for (unsigned long i = al + rqs; i <= ah; ++i) {
        const auto matched = do_assign ? dynlease_add(ifname_, aia4(i), hwaddr, expire_time)
                                       : dynlease_exists(ifname_, aia4(i), hwaddr);
        if (matched) {
            reply.yiaddr = htonl(i);
            add_u32_option(&reply, DCODE_LEASET, htonl(dynamic_lifetime));
            return true;
        }
    }
    for (unsigned long i = al; i < al + rqs; ++i) {
        const auto matched = do_assign ? dynlease_add(ifname_, aia4(i), hwaddr, expire_time)
                                       : dynlease_exists(ifname_, aia4(i), hwaddr);
        if (matched) {
            reply.yiaddr = htonl(i);
            add_u32_option(&reply, DCODE_LEASET, htonl(dynamic_lifetime));
            return true;
        }
    }
    return false;
}

bool D4Listener::create_reply(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign)
{
    auto dv4s = query_dhcp_state(ifname_, hwaddr);
    if (!dv4s) {
        if (!allot_dynamic_ip(reply, hwaddr, do_assign))
            return false;
    } else {
        reply.yiaddr = htonl(dv4s->address.to_ulong());
        add_u32_option(&reply, DCODE_LEASET, htonl(dv4s->lifetime));
    }
    try {
        add_option_subnet_mask(&reply, htonl(query_subnet(ifname_).to_ulong()));
        add_option_broadcast(&reply, htonl(query_broadcast(ifname_).to_ulong()));

        std::string iplist;
        const auto routers = query_gateway(ifname_);
        const auto dns4 = query_dns4_servers(ifname_);
        const auto ntp4 = query_ntp4_servers(ifname_);
        iplist_option(reply, iplist, DCODE_ROUTER, routers);
        iplist_option(reply, iplist, DCODE_DNS, dns4);
        iplist_option(reply, iplist, DCODE_NTPSVR, ntp4);
        const auto dns_search = query_dns_search(ifname_);
        if (dns_search.size()) {
            const auto &dn = dns_search.front();
            add_option_domain_name(&reply, dn.c_str(), dn.size());
        }
    } catch (const std::runtime_error &) { return false; }
    return true;
}

void D4Listener::reply_discover()
{
    fmt::print(stderr, "Got DHCP4 discover message\n");
    dhcpmsg reply;
    dhcpmsg_init(reply, DHCPOFFER, dhcpmsg_.xid);
    if (create_reply(reply, dhcpmsg_.chaddr, true))
        send_reply(reply);
}

void D4Listener::reply_request(bool is_direct)
{
    fmt::print(stderr, "Got DHCP4 request message\n");
    dhcpmsg reply;
    dhcpmsg_init(reply, DHCPACK, dhcpmsg_.xid);
    if (create_reply(reply, dhcpmsg_.chaddr, true)) {
        send_reply(reply);
    }
    client_states_v4->stateKill(dhcpmsg_.xid, dhcpmsg_.chaddr);
}

static asio::ip::address_v4 zero_v4(0lu);
void D4Listener::reply_inform()
{
    fmt::print(stderr, "Got DHCP4 inform message\n");
    struct dhcpmsg reply;
    dhcpmsg_init(reply, DHCPACK, dhcpmsg_.xid);
    if (create_reply(reply, dhcpmsg_.chaddr, false)) {
        // http://tools.ietf.org/html/draft-ietf-dhc-dhcpinform-clarify-06
        reply.htype = dhcpmsg_.htype;
        reply.hlen = dhcpmsg_.hlen;
        memcpy(&reply.chaddr, &dhcpmsg_.chaddr, sizeof reply.chaddr);
        reply.ciaddr = dhcpmsg_.ciaddr;
        // xid was already set equal
        reply.flags = dhcpmsg_.flags;
        reply.hops = 0;
        reply.secs = 0;
        reply.yiaddr = 0;
        reply.siaddr = 0;
        if (dhcpmsg_.ciaddr)
            send_reply_do(reply, SendReplyType::UnicastCi);
        else if (dhcpmsg_.giaddr) {
            auto fl = ntohs(reply.flags);
            reply.flags = htons(fl | 0x8000u);
            send_reply_do(reply, SendReplyType::Relay);
        } else if (remote_endpoint_.address() != zero_v4)
            send_reply_do(reply, SendReplyType::UnicastCi);
        else
            send_reply_do(reply, SendReplyType::Broadcast);
    }
}

void D4Listener::do_release() {
    auto valid = dynlease_exists(ifname_, remote_endpoint_.address().to_v4(), dhcpmsg_.chaddr);
    if (!valid) {
        fmt::print(stderr, "do_release: ignoring spoofed release request for {}.\n",
                   remote_endpoint_.address().to_string());
        std::fflush(stdout);
        return;
    }
    dynlease_del(ifname_, remote_endpoint_.address().to_v4(), dhcpmsg_.chaddr);
}

std::string D4Listener::getChaddr(const struct dhcpmsg &dm) const
{
    char mac[7];
    memcpy(mac, dm.chaddr, sizeof mac - 1);
    return std::string(mac, 6);
}

uint8_t D4Listener::validate_dhcp(size_t len) const
{
    if (len < offsetof(struct dhcpmsg, options))
        return DHCPNULL;
    if (ntohl(dhcpmsg_.cookie) != DHCP_MAGIC)
        return DHCPNULL;
    return get_option_msgtype(&dhcpmsg_);
}

void D4Listener::start_receive()
{
    socket_.async_receive_from
        (asio::buffer(recv_buffer_), remote_endpoint_,
         [this](const std::error_code &error, std::size_t bytes_xferred)
         {
             if (error) {
                 fmt::print(stderr, "dhcp4: Error during receive: {}\n", error);
                 exit(EXIT_FAILURE);
                 return;
             }

             bool direct_request = false;
             size_t msglen = std::min(bytes_xferred, sizeof dhcpmsg_);
             memset(&dhcpmsg_, 0, sizeof dhcpmsg_);
             memcpy(&dhcpmsg_, recv_buffer_.data(), msglen);
             uint8_t msgtype = validate_dhcp(msglen);
             if (!msgtype) {
                 start_receive();
                 return;
             }

             auto cs = client_states_v4->stateGet(dhcpmsg_.xid, dhcpmsg_.chaddr);
             if (cs == DHCPNULL) {
                 switch (msgtype) {
                 case DHCPREQUEST:
                     direct_request = true;
                 case DHCPDISCOVER:
                     cs = msgtype;
                     client_states_v4->stateAdd(dhcpmsg_.xid, dhcpmsg_.chaddr, cs);
                     break;
                 case DHCPINFORM:
                     // No need to track state since we just INFORM => ACK
                 case DHCPDECLINE:
                 case DHCPRELEASE:
                     cs = msgtype;
                     break;
                 default:
                     start_receive();
                     return;
                 }
             } else {
                 if (cs == DHCPDISCOVER && msgtype == DHCPREQUEST)
                     cs = DHCPREQUEST;
             }

             switch (cs) {
             case DHCPDISCOVER: reply_discover(); break;
             case DHCPREQUEST:  reply_request(direct_request); break;
             case DHCPINFORM:   reply_inform(); break;
             case DHCPDECLINE:
                                fmt::print(stderr, "Received a DHCPDECLINE.  Clients conflict?\n");
             case DHCPRELEASE:  do_release(); break;
             }
             start_receive();
         });
}

