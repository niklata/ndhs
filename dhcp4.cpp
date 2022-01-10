/* dhcpclient.cpp - dhcp client request handling
 *
 * Copyright 2011-2020 Nicholas J. Kain <njkain at gmail dot com>
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
#include "rng.hpp"
#include "dhcp4.hpp"
#include "dhcp_state.hpp"
#include "nlsocket.hpp"
#include "dynlease.hpp"
#include "sbufs.h"
extern "C" {
#include "nk/log.h"
#include "nk/io.h"
#include "options.h"
}

// key is concatenation of xid|hwaddr.  Neither of these need to be
// stored in explicit fields in the state structure.
static std::string generateKey(uint32_t xid, uint8_t *hwaddr) {
    std::string ret;
    ret.resize(32);
    int splen = snprintf(ret.data(), ret.size(), "%u%2.x%2.x%2.x%2.x%2.x%2.x",
                         xid, hwaddr[0], hwaddr[1], hwaddr[2],
                         hwaddr[3], hwaddr[4], hwaddr[5]);
    if (splen < 0)
        suicide("%s: snprintf failed; return=%d", __func__, splen);
    if ((size_t)splen >= ret.size())
        suicide("%s: snprintf dest buffer too small %d >= %zu",
                __func__, splen, ret.size());
    ret.resize(splen);
    return ret;
}

ClientStates::ClientStates() : currentMap_(0), swapInterval_(60) /* 1m */
{
    expires_ = std::chrono::steady_clock::now() + std::chrono::seconds(swapInterval_);
}
bool ClientStates::stateExists(uint32_t xid, uint8_t *hwaddr) {
    maybe_swap();
    const auto key = generateKey(xid, hwaddr);
    return (map_[0].find(key) != map_[0].end()) ||
           (map_[1].find(key) != map_[1].end());
}
void ClientStates::stateAdd(uint32_t xid, uint8_t *hwaddr, uint8_t state)
{
    maybe_swap();
    const auto key = generateKey(xid, hwaddr);
    if (!state)
        return;
    stateKill(xid, hwaddr);
    map_[currentMap_][key] = state;
}
uint8_t ClientStates::stateGet(uint32_t xid, uint8_t *hwaddr)
{
    maybe_swap();
    const auto key = generateKey(xid, hwaddr);
    auto r = map_[currentMap_].find(key);
    if (r != map_[currentMap_].end())
        return r->second;
    r = map_[!currentMap_].find(key);
    if (r != map_[!currentMap_].end()) {
        map_[!currentMap_].erase(r);
        map_[currentMap_][key] = r->second;
        return r->second;
    }
    return DHCPNULL;
}
void ClientStates::stateKill(uint32_t xid, uint8_t *hwaddr)
{
    maybe_swap();
    const auto key = generateKey(xid, hwaddr);
    auto elt = map_[currentMap_].find(key);
    if (elt != map_[currentMap_].end()) {
        map_[currentMap_].erase(elt);
        return;
    }
    elt = map_[!currentMap_].find(key);
    if (elt != map_[!currentMap_].end())
        map_[!currentMap_].erase(elt);
}
void ClientStates::maybe_swap(void)
{
    const auto now = std::chrono::steady_clock::now();
    if (now < expires_) return;

    expires_ = now + std::chrono::seconds(swapInterval_);
    const int killMap = !currentMap_;
    map_[killMap].clear();
    currentMap_ = killMap;
}

extern std::unique_ptr<NLSocket> nl_socket;
extern int64_t get_current_ts();

static std::unique_ptr<ClientStates> client_states_v4;
static void init_client_states_v4()
{
    static bool was_initialized;
    if (was_initialized) return;
    client_states_v4 = std::make_unique<ClientStates>();
}

// Must be called after ifname_ is set.
bool D4Listener::create_dhcp4_socket()
{
    auto tfd = nk::sys::handle{ socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP) };
    if (!tfd) {
        log_line("Failed to create v4 UDP socket on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }
    const int iv = 1;
    if (setsockopt(tfd(), SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char *>(&iv), sizeof iv) == -1) {
        log_line("Failed to set broadcast flag on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }
    if (setsockopt(tfd(), SOL_SOCKET, SO_DONTROUTE, reinterpret_cast<const char *>(&iv), sizeof iv) == -1) {
        log_line("Failed to set do not route flag on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }
    if (setsockopt(tfd(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&iv), sizeof iv) == -1) {
        log_line("Failed to set reuse address flag on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }
    sockaddr_in sai;
    sai.sin_family = AF_INET;
    sai.sin_port = htons(67);
    sai.sin_addr.s_addr = 0; // any
    if (bind(tfd(), reinterpret_cast<const sockaddr *>(&sai), sizeof sai)) {
        log_line("Failed to bind to UDP 67 on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    if (ifname_.size() >= sizeof ifr.ifr_name) {
        log_line("Interface name '%s' is too long: %zu >= %zu",
                 ifname_.c_str(), ifname_.size(), sizeof ifr.ifr_name);
        return false;
    }
    memcpy(ifr.ifr_name, ifname_.c_str(), ifname_.size());
    if (setsockopt(tfd(), SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_line("failed to bind socket to device on %s: %s", ifname_.c_str(), strerror(errno));
        return false;
    }

    swap(fd_, tfd);
    return true;
}

bool D4Listener::init(const std::string &ifname)
{
    ifname_ = ifname;
    init_client_states_v4();
    if (!create_dhcp4_socket()) return false;

    {
        auto ifinfo = nl_socket->get_ifinfo(ifname);
        if (!ifinfo) {
            log_line("Failed to get interface index for %s", ifname.c_str());
            return false;
        }

        for (const auto &i: ifinfo->addrs) {
            if (i.address.is_v4()) {
                local_ip_ = i.address.to_v4();
                log_line("IP address for %s is %s.", ifname.c_str(), local_ip_.to_string().c_str());
            }
        }
    }
    if (!local_ip_.is_v4()) {
        log_line("Interface (%s) has no IP address", ifname.c_str());
        return false;
    }

    return true;
}

void D4Listener::process_input()
{
    char buf[8192];
    auto buflen = safe_recv(fd_(), buf, sizeof buf, MSG_DONTWAIT);
    if (buflen < 0) suicide("D4Listener: recv failed: %s", strerror(errno));
    process_receive(buf, buflen);
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
        log_line("inet_pton failed: %s", strerror(errno));
        return 0;
    }
    return ret;
}

bool D4Listener::send_to(const void *buf, size_t len, uint32_t addr, int port)
{
    sockaddr_in sai;
    memset(&sai, 0, sizeof sai);
    sai.sin_family = AF_INET;
    sai.sin_port = htons(port);
    sai.sin_addr.s_addr = addr;
    const auto r = safe_sendto(fd_(), (const char *)buf, len, 0, reinterpret_cast<const sockaddr *>(&sai), sizeof sai);
    if (r < 0) {
        log_line("D4Listener sendto failed: %s", strerror(errno));
        return false;
    }
    return true;
}

void D4Listener::send_reply_do(const dhcpmsg &dm, SendReplyType srt)
{
    ssize_t endloc = get_end_option_idx(&dm);
    if (endloc < 0)
        return;

    const auto dmlen = sizeof dm - (sizeof dm.options - 1 - endloc);

    switch (srt) {
    case SendReplyType::UnicastCi:
        send_to(&dm, dmlen, dhcpmsg_.ciaddr, 68);
        break;
    case SendReplyType::Broadcast: {
        const auto broadcast = query_broadcast(ifname_);
        if (!broadcast) suicide("dhcp4: misconfigured -- must have a broadcast address");
        send_to(&dm, dmlen, htonl(broadcast->to_ulong()), 68);
        break;
    }
    case SendReplyType::Relay:
        send_to(&dm, dmlen, dhcpmsg_.giaddr, 67);
        break;
    case SendReplyType::UnicastYiCh:
        send_to(&dm, dmlen, dhcpmsg_.yiaddr, 68);
        break;
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

    log_line("Checking dynamic IP.");

    const auto dr = query_dynamic_range(ifname_);
    if (!dr) {
        log_line("No dynamic range is associated.  Can't assign an IP.");
        return false;
    }
    const auto expire_time = get_current_ts() + dynamic_lifetime;

    auto v4a = dynlease_query_refresh(ifname_, hwaddr, expire_time);
    if (v4a != asio::ip::address_v4::any()) {
        reply.yiaddr = htonl(v4a.to_ulong());
        add_u32_option(&reply, DCODE_LEASET, htonl(dynamic_lifetime));
        log_line("Assigned existing dynamic IP: %s", v4a.to_string().c_str());
        return true;
    }
    log_line("Selecting an unused dynamic IP.");

    // IP is randomly selected from the dynamic range.
    const auto al = dr->first.to_ulong();
    const auto ah = dr->second.to_ulong();
    const uint64_t ar = ah > al ? ah - al : al - ah;
    std::uniform_int_distribution<uint64_t> dist(0, ar);
    random_u64_wrapper r64w;
    const auto rqs = dist(r64w);

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
    const auto subnet = query_subnet(ifname_);
    if (!subnet) return false;
    add_option_subnet_mask(&reply, htonl(subnet->to_ulong()));
    const auto broadcast = query_broadcast(ifname_);
    if (!broadcast) return false;
    add_option_broadcast(&reply, htonl(broadcast->to_ulong()));

    std::string iplist;
    const auto routers = query_gateway(ifname_);
    const auto dns4 = query_dns4_servers(ifname_);
    const auto ntp4 = query_ntp4_servers(ifname_);
    if (routers) iplist_option(reply, iplist, DCODE_ROUTER, *routers);
    if (dns4) iplist_option(reply, iplist, DCODE_DNS, *dns4);
    if (ntp4) iplist_option(reply, iplist, DCODE_NTPSVR, *ntp4);
    const auto dns_search = query_dns_search(ifname_);
    if (dns_search && dns_search->size()) {
        const auto &dn = dns_search->front();
        add_option_domain_name(&reply, dn.c_str(), dn.size());
    }
    return true;
}

void D4Listener::reply_discover()
{
    log_line("Got DHCP4 discover message");
    dhcpmsg reply;
    dhcpmsg_init(reply, DHCPOFFER, dhcpmsg_.xid);
    if (create_reply(reply, dhcpmsg_.chaddr, true))
        send_reply(reply);
}

void D4Listener::reply_request()
{
    log_line("Got DHCP4 request message");
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
    log_line("Got DHCP4 inform message");
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
        } else
            send_reply_do(reply, SendReplyType::Broadcast);
    }
}

void D4Listener::do_release() {
    using aia4 = asio::ip::address_v4;
    auto valid = dynlease_exists(ifname_, aia4(ntohl(dhcpmsg_.ciaddr)), dhcpmsg_.chaddr);
    if (!valid) {
        char buf[32] = "invalid ip";
        ip4_to_string(buf, sizeof buf, dhcpmsg_.ciaddr);
        log_line("do_release: ignoring spoofed release request for %s.", buf);
        return;
    }
    dynlease_del(ifname_, aia4(ntohl(dhcpmsg_.ciaddr)), dhcpmsg_.chaddr);
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

void D4Listener::process_receive(const char *buf, std::size_t buflen)
{
    auto msglen = std::min(static_cast<size_t>(buflen), sizeof dhcpmsg_);
    memset(&dhcpmsg_, 0, sizeof dhcpmsg_);
    memcpy(&dhcpmsg_, buf, msglen);
    uint8_t msgtype = validate_dhcp(msglen);
    if (!msgtype)
        return;

    auto cs = client_states_v4->stateGet(dhcpmsg_.xid, dhcpmsg_.chaddr);
    if (cs == DHCPNULL) {
        switch (msgtype) {
        case DHCPREQUEST:
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
        default: return;
        }
    } else {
        if (cs == DHCPDISCOVER && msgtype == DHCPREQUEST)
            cs = DHCPREQUEST;
    }

    switch (cs) {
    case DHCPDISCOVER: reply_discover(); break;
    case DHCPREQUEST:  reply_request(); break;
    case DHCPINFORM:   reply_inform(); break;
    case DHCPDECLINE:  log_line("Received a DHCPDECLINE.  Clients conflict?");
    case DHCPRELEASE:  do_release(); break;
    }
}

