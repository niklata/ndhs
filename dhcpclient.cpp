/* dhcpclient.cpp - dhcp client request handling
 *
 * (c) 2011-2016 Nicholas J. Kain <njkain at gmail dot com>
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

#include <net/if.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <format.hpp>

#include "dhcpclient.hpp"
#include "leasestore.hpp"
#include "dhcplua.hpp"
#include "clientid.hpp"

extern "C" {
#include "options.h"
}

namespace ba = boost::asio;

extern std::unique_ptr<LeaseStore> gLeaseStore;
extern std::unique_ptr<DhcpLua> gLua;

std::unique_ptr<ClientStates> client_states_v4;
void init_client_states_v4(ba::io_service &io_service)
{
    client_states_v4 = std::make_unique<ClientStates>(io_service);
}

ClientListener::ClientListener(ba::io_service &io_service,
                               const ba::ip::udp::endpoint &endpoint,
                               const std::string &ifname)
 : socket_(io_service)
{
    socket_.open(endpoint.protocol());
    socket_.set_option(ba::ip::udp::socket::broadcast(true));
    socket_.set_option(ba::ip::udp::socket::do_not_route(true));
    socket_.set_option(ba::ip::udp::socket::reuse_address(true));
    socket_.bind(endpoint);
    int fd = socket_.native();

    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        fmt::print(stderr, "failed to bind socket to device: {}\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        fmt::print(stderr, "failed to get list of interface ips: {}\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (strcmp(ifa->ifa_name, ifname.c_str()))
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        char lipbuf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                       lipbuf, sizeof lipbuf)) {
            fmt::print(stderr, "failed to parse IP for interface ({}): {}\n",
                       ifname, strerror(errno));
            exit(EXIT_FAILURE);
        }
        local_ip_ = ba::ip::address::from_string(lipbuf);
        break;
    }
    freeifaddrs(ifaddr);
    if (!local_ip_.is_v4()) {
        fmt::print(stderr, "interface ({}) has no IP address\n", ifname);
        exit(EXIT_FAILURE);
    }

    start_receive();
}

void ClientListener::dhcpmsg_init(dhcpmsg &dm, char type, uint32_t xid,
                                  const ClientID &clientid) const
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
    if (clientid.had_option()) {
        auto &cid = clientid.value();
        add_option_clientid(&dm, cid.data(), cid.size());
    }
}

uint32_t ClientListener::local_ip() const
{
    uint32_t ret;
    if (inet_pton(AF_INET, local_ip_.to_string().c_str(), &ret) != 1) {
        fmt::print(stderr, "inet_pton failed: {}\n", strerror(errno));
        return 0;
    }
    return ret;
}

void ClientListener::send_reply_do(const dhcpmsg &dm, SendReplyType srt)
{
    ssize_t endloc = get_end_option_idx(&dm);
    if (endloc < 0)
        return;

    boost::system::error_code ignored_error;
    auto buf = boost::asio::buffer((const char *)&dm, sizeof dm -
                                   (sizeof dm.options - 1 - endloc));

    switch (srt) {
    case SendReplyType::UnicastCi: {
        auto uct = ba::ip::address_v4(ntohl(dhcpmsg_.ciaddr));
        socket_.send_to(buf, ba::ip::udp::endpoint(uct, 68), 0, ignored_error);
        break;
    }
    case SendReplyType::Broadcast: {
        auto remotebcast = remote_endpoint_.address().to_v4().broadcast();
        socket_.send_to(buf, ba::ip::udp::endpoint(remotebcast, 68),
                        0, ignored_error);
        break;
    }
    case SendReplyType::Relay: {
        auto relay = ba::ip::address_v4(ntohl(dhcpmsg_.giaddr));
        socket_.send_to(buf, ba::ip::udp::endpoint(relay, 67),
                        0, ignored_error);
        break;
    }
    case SendReplyType::UnicastYiCh: {
        auto uct = ba::ip::address_v4(ntohl(dhcpmsg_.yiaddr));
        socket_.send_to(buf, ba::ip::udp::endpoint(uct, 68), 0, ignored_error);
        break;
    }
    }
}

std::string ClientListener::ipStr(uint32_t ip) const
{
    char addrbuf[INET_ADDRSTRLEN];
    auto r = inet_ntop(AF_INET, &ip, addrbuf, sizeof addrbuf);
    if (!r)
        return std::string("");
    return std::string(addrbuf);
}

uint64_t ClientListener::getNowTs(void) const {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

void ClientListener::send_reply(const dhcpmsg &reply)
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

void ClientListener::reply_discover(const ClientID &clientid)
{
    struct dhcpmsg reply;

    dhcpmsg_init(reply, DHCPOFFER, dhcpmsg_.xid, clientid);
    if (gLua->reply_discover(reply, local_ip_.to_string(),
                             remote_endpoint_.address().to_string(),
                             clientid)) {
        send_reply(reply);
    }
}

void ClientListener::reply_request(const ClientID &clientid, bool is_direct)
{
    struct dhcpmsg reply;
    std::string leaseip;

    dhcpmsg_init(reply, DHCPACK, dhcpmsg_.xid, clientid);
    if (gLua->reply_request(reply, local_ip_.to_string(),
                            remote_endpoint_.address().to_string(),
                            clientid)) {
        leaseip = ipStr(reply.yiaddr);
        if (!leaseip.size())
            goto out;
        gLeaseStore->addLease(local_ip_.to_string(), clientid, leaseip,
                              getNowTs() + get_option_leasetime(&reply));
        send_reply(reply);
    }
out:
    client_states_v4->stateKill(dhcpmsg_.xid, clientid);
}

static ba::ip::address_v4 zero_v4(0lu);
void ClientListener::reply_inform(const ClientID &clientid)
{
    struct dhcpmsg reply;

    dhcpmsg_init(reply, DHCPACK, dhcpmsg_.xid, clientid);
    if (gLua->reply_inform(reply, local_ip_.to_string(),
                           remote_endpoint_.address().to_string(), clientid)) {
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

void ClientListener::do_release(const ClientID &clientid) {
    std::string lip =
        gLeaseStore->getLease(socket_.local_endpoint().address().to_string(),
                              clientid);
    if (lip != remote_endpoint_.address().to_string()) {
        fmt::print("do_release: ignoring spoofed release request.  {} != {}.\n",
                   remote_endpoint_.address().to_string(), lip);
        std::fflush(stdout);
        return;
    }
    gLeaseStore->delLease(socket_.local_endpoint().address().to_string(),
                          clientid);
}

std::string ClientListener::getChaddr(const struct dhcpmsg &dm) const
{
    char mac[7];
    memcpy(mac, dm.chaddr, sizeof mac - 1);
    return std::string(mac, 6);
}

std::string ClientListener::getClientId(const struct dhcpmsg &dm) const
{
    char buf[MAX_DOPT_SIZE];
    auto len = get_option_clientid(&dm, buf, sizeof buf);
    if (len < 2)
        return std::string("");
    return std::string(buf, len);
}

uint8_t ClientListener::validate_dhcp(size_t len) const
{
    if (len < offsetof(struct dhcpmsg, options))
        return DHCPNULL;
    if (ntohl(dhcpmsg_.cookie) != DHCP_MAGIC)
        return DHCPNULL;
    return get_option_msgtype(&dhcpmsg_);
}

void ClientListener::start_receive()
{
    socket_.async_receive_from
        (ba::buffer(recv_buffer_), remote_endpoint_,
         [this](const boost::system::error_code &error,
                std::size_t bytes_xferred)
         {
             bool direct_request = false;
             size_t msglen = std::min(bytes_xferred, sizeof dhcpmsg_);
             memset(&dhcpmsg_, 0, sizeof dhcpmsg_);
             memcpy(&dhcpmsg_, recv_buffer_.data(), msglen);
             uint8_t msgtype = validate_dhcp(msglen);
             if (!msgtype) {
                 start_receive();
                 return;
             }
             ClientID clientid(getClientId(dhcpmsg_), getChaddr(dhcpmsg_));

             auto cs = client_states_v4->stateGet(dhcpmsg_.xid, clientid);
             if (cs == DHCPNULL) {
                 switch (msgtype) {
                 case DHCPREQUEST:
                     direct_request = true;
                 case DHCPDISCOVER:
                     cs = msgtype;
                     client_states_v4->stateAdd(dhcpmsg_.xid, clientid, cs);
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
             case DHCPDISCOVER: reply_discover(clientid); break;
             case DHCPREQUEST:  reply_request(clientid, direct_request); break;
             case DHCPINFORM:   reply_inform(clientid); break;
             case DHCPDECLINE:
                                fmt::print("Received a DHCPDECLINE.  Clients conflict?\n");
             case DHCPRELEASE:  do_release(clientid); break;
             }
             start_receive();
         });
}

