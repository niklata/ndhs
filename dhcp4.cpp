// Copyright 2011-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <sys/types.h>
#include <net/if.h>
#include <pwd.h>
#include "dhcp4.hpp"
#include "dhcp_state.hpp"
#include "nlsocket.hpp"
#include "dynlease.hpp"
#include "sbufs.h"
#include "nk/netbits.h"
extern "C" {
#include "nk/log.h"
#include "nk/io.h"
#include "nk/random.h"
#include "options.h"
}

extern struct nk_random_state g_rngstate;

// hwaddr must be exactly 6 bytes
static uint64_t hwaddr_to_int64(uint8_t *hwaddr)
{
    return (uint64_t)hwaddr[0] |
           ((uint64_t)hwaddr[1] << 8) |
           ((uint64_t)hwaddr[2] << 16) |
           ((uint64_t)hwaddr[3] << 24) |
           ((uint64_t)hwaddr[4] << 32) |
           ((uint64_t)hwaddr[5] << 40);
}

namespace detail {

ClientStates::ClientStates()
{
    memset(map_, 0, sizeof map_);
}

struct ClientStates::StateItem *ClientStates::find(uint64_t h)
{
    for (size_t i = 0; i < D4_CLIENT_STATE_TABLESIZE; ++i) {
        if (map_[i].hwaddr_ == h) {
            struct timespec now;
            clock_gettime(CLOCK_BOOTTIME, &now);
            if (now.tv_sec > map_[i].ts_.tv_sec + D4_XID_LIFE_SECS) {
                memset(&map_[i], 0, sizeof map_[i]);
                break;
            }
            return &map_[i];
        }
    }
    return nullptr;
}

bool ClientStates::stateAdd(uint32_t xid, uint8_t *hwaddr, uint8_t state)
{
    if (!state) return false;
    uint64_t key = hwaddr_to_int64(hwaddr);
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    struct StateItem *m = nullptr, *e = nullptr;
    struct StateItem zi;
    memset(&zi, 0, sizeof zi);
    for (size_t i = 0; i < D4_CLIENT_STATE_TABLESIZE; ++i) {
        if (map_[i].ts_.tv_sec && now.tv_sec > map_[i].ts_.tv_sec + D4_XID_LIFE_SECS) {
            // Expire entries as we see them.
            memset(&map_[i], 0, sizeof map_[i]);
        } else {
            if (map_[i].hwaddr_ == key) {
                m = &map_[i];
                break;
            }
        }
        if (!e && !memcmp(&map_[i], &zi, sizeof zi)) e = &map_[i];
    }
    if (!m) {
        if (!e) return false; // Out of space.
        m = e;
    }
    *m = (struct StateItem){
        .ts_ = now,
        .hwaddr_ = key,
        .xid_ = xid,
        .state_ = state,
    };
    return true;
}

uint8_t ClientStates::stateGet(uint32_t xid, uint8_t *hwaddr)
{
    uint64_t key = hwaddr_to_int64(hwaddr);
    struct StateItem *m = find(key);
    if (!m || m->xid_ != xid) return DHCPNULL;
    return m->state_;
}

void ClientStates::stateKill(uint8_t *hwaddr)
{
    uint64_t key = hwaddr_to_int64(hwaddr);
    struct StateItem *m = find(key);
    if (m) memset(m, 0, sizeof *m);
}

} // detail

extern NLSocket nl_socket;
extern int64_t get_current_ts();

// Must be called after ifname_ is set and only should be called once.
bool D4Listener::create_dhcp4_socket()
{
    struct ifreq ifr;
    const int iv = 1;
    if (fd_ > 0) close(fd_);
    fd_ = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP);
    if (fd_ < 0) {
        log_line("dhcp4: Failed to create v4 UDP socket on %s: %s\n", ifname_, strerror(errno));
        goto err0;
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char *>(&iv), sizeof iv) == -1) {
        log_line("dhcp4: Failed to set broadcast flag on %s: %s\n", ifname_, strerror(errno));
        goto err1;
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_DONTROUTE, reinterpret_cast<const char *>(&iv), sizeof iv) == -1) {
        log_line("dhcp4: Failed to set do not route flag on %s: %s\n", ifname_, strerror(errno));
        goto err1;
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&iv), sizeof iv) == -1) {
        log_line("dhcp4: Failed to set reuse address flag on %s: %s\n", ifname_, strerror(errno));
        goto err1;
    }
    {
        sockaddr_in sai;
        sai.sin_family = AF_INET;
        sai.sin_port = htons(67);
        sai.sin_addr.s_addr = 0; // any
        if (bind(fd_, (const sockaddr *)&sai, sizeof sai)) {
            log_line("dhcp4: Failed to bind to UDP 67 on %s: %s\n", ifname_, strerror(errno));
            goto err1;
        }
    }

    {
        size_t ifname_len = strlen(ifname_);
        memset(&ifr, 0, sizeof ifr);
        if (ifname_len >= sizeof ifr.ifr_name) {
            log_line("dhcp4: Interface name '%s' is too long: %zu >= %zu\n",
                     ifname_, ifname_len, sizeof ifr.ifr_name);
            goto err1;
        }
        memcpy(ifr.ifr_name, ifname_, ifname_len);
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_line("dhcp4: Failed to bind socket to device on %s: %s\n", ifname_, strerror(errno));
        goto err1;
    }

    return true;
err1:
    close(fd_);
    fd_ = -1;
err0:
    return false;
}

// Only intended to be called once per listener.
bool D4Listener::init(const char *ifname)
{
    size_t ifname_src_size = strlen(ifname);
    if (ifname_src_size >= sizeof ifname_) {
        log_line("D4Listener: Interface name (%s) too long\n", ifname);
        return false;
    }
    *static_cast<char *>(mempcpy(ifname_, ifname, ifname_src_size)) = 0;

    if (!create_dhcp4_socket()) return false;

    ifindex_ = nl_socket.get_ifindex(ifname);
    if (ifindex_ == -1) {
        log_line("dhcp4: Failed to get interface index for %s\n", ifname);
        return false;
    }
    auto ifinfo = nl_socket.get_ifinfo(ifindex_);
    assert(ifinfo);

    if (!ifinfo->has_v4_address) {
        log_line("dhcp4: Interface (%s) has no IP address\n", ifname);
        return false;
    }
    local_ip_ = ifinfo->v4_address;
    char abuf[48];
    if (!ipaddr_to_string(abuf, sizeof abuf, &local_ip_)) abort();
    log_line("dhcp4: IP address for %s is %s\n", ifname, abuf);


    return true;
}

void D4Listener::process_input()
{
    char buf[8192];
    for (;;) {
        sockaddr_storage sai;
        socklen_t sailen = sizeof sai;
        auto buflen = recvfrom(fd_, buf, sizeof buf, MSG_DONTWAIT, (sockaddr *)&sai, &sailen);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("dhcp4: recvfrom failed on %s: %s\n", ifname_, strerror(err));
        }
        process_receive(buf, static_cast<size_t>(buflen));
    }
}

void D4Listener::dhcpmsg_init(dhcpmsg &dm, uint8_t type, uint32_t xid) const
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
    char abuf[48];
    uint32_t ret;
    if (!ipaddr_to_string(abuf, sizeof abuf, &local_ip_)) abort();
    if (inet_pton(AF_INET, abuf, &ret) != 1) {
        log_line("dhcp4: inet_pton failed: %s\n", strerror(errno));
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
    const auto r = safe_sendto(fd_, static_cast<const char *>(buf), len, 0, (const sockaddr *)&sai, sizeof sai);
    if (r < 0) {
        log_line("dhcp4: D4Listener sendto failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

void D4Listener::send_reply_do(const dhcpmsg &dm, SendReplyType srt)
{
    ssize_t endloc = get_end_option_idx(&dm);
    if (endloc < 0) return;
    const auto dmlen = sizeof dm - (sizeof dm.options - 1 - static_cast<size_t>(endloc));

    switch (srt) {
    case SendReplyType::UnicastCi:
        send_to(&dm, dmlen, dhcpmsg_.ciaddr, 68);
        break;
    case SendReplyType::Broadcast: {
        auto broadcast = query_broadcast(ifindex_);
        if (!broadcast) suicide("dhcp4: misconfigured -- must have a broadcast address\n");
        uint32_t bcaddr;
        memcpy(&bcaddr, ipaddr_v4_bytes(broadcast), sizeof bcaddr);
        send_to(&dm, dmlen, bcaddr, 68);
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

static bool iplist_option(dhcpmsg *reply, uint8_t code, const struct addrlist *ipl)
{
    char buf[256]; // max option size is 255 bytes
    size_t off = 0;
    for (size_t i = 0; i < ipl->n; ++i) {
        if (off + 4 >= sizeof buf) break; // silently drop if too many
        if (ipaddr_is_v4(&ipl->addrs[i])) {
            memcpy(buf + off, ipaddr_v4_bytes(&ipl->addrs[i]), 4);
            off += 4;
        }
    }
    buf[off] = 0;
    if (!off) return false;
    add_option_string(reply, code, buf, off);
    return true;
}

static in6_addr u32_ipaddr(uint32_t v)
{
    in6_addr ret;
    ipaddr_from_v4_bytes(&ret, &v);
    return ret;
}

bool D4Listener::allot_dynamic_ip(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign)
{
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v4(ifindex_, &dynamic_lifetime))
        return false;

    log_line("dhcp4: Checking dynamic IP.\n");

    in6_addr dr_lo, dr_hi;
    if (!query_dynamic_range(ifindex_, &dr_lo, &dr_hi)) {
        log_line("dhcp4: No dynamic range is associated.  Can't assign an IP.\n");
        return false;
    }
    const auto expire_time = get_current_ts() + dynamic_lifetime;

    auto v4a = dynlease4_query_refresh(ifname_, hwaddr, expire_time);
    if (memcmp(&v4a, &in6addr_any, 16)) {
        if (!ipaddr_is_v4(&v4a)) {
            log_line("dhcp4: allot_dynamic_ip - bad address\n");
            return false;
        }
        memcpy(&reply.yiaddr, ipaddr_v4_bytes(&v4a), sizeof reply.yiaddr);
        add_u32_option(&reply, DCODE_LEASET, htonl(dynamic_lifetime));
        char abuf[48];
        if (!ipaddr_to_string(abuf, sizeof abuf, &v4a)) abort();
        log_line("dhcp4: Assigned existing dynamic IP: %s\n", abuf);
        return true;
    }
    log_line("dhcp4: Selecting an unused dynamic IP.\n");

    // IP is randomly selected from the dynamic range.
    uint32_t al = decode32be(ipaddr_v4_bytes(&dr_lo));
    uint32_t ah = decode32be(ipaddr_v4_bytes(&dr_hi));
    const uint64_t ar = ah > al ? ah - al : al - ah;
    // The extremely small distribution skew does not matter here.
    const auto rqs = nk_random_u64(&g_rngstate) % (ar + 1);

    // OK, here we have bisected our range using rqs.
    // [al .. ah] => [al .. rqs .. ah]
    // So we scan from [rqs, ah], taking the first empty slot.
    // If no success, scan from [al, rqs), taking the first empty slot.
    // If no success, then all IPs are taken, so return false.
    for (uint32_t i = al + rqs; i <= ah; ++i) {
        auto iaddr = u32_ipaddr(htonl(i));
        const auto matched = do_assign ? dynlease4_add(ifname_, &iaddr, hwaddr, expire_time)
                                       : dynlease4_exists(ifname_, &iaddr, hwaddr);
        if (matched) {
            reply.yiaddr = htonl(i);
            add_u32_option(&reply, DCODE_LEASET, htonl(dynamic_lifetime));
            return true;
        }
    }
    for (uint32_t i = al; i < al + rqs; ++i) {
        auto iaddr = u32_ipaddr(htonl(i));
        const auto matched = do_assign ? dynlease4_add(ifname_, &iaddr, hwaddr, expire_time)
                                       : dynlease4_exists(ifname_, &iaddr, hwaddr);
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
    auto dv4s = query_dhcp4_state(ifindex_, hwaddr);
    if (!dv4s) {
        if (!allot_dynamic_ip(reply, hwaddr, do_assign))
            return false;
    } else {
        memcpy(&reply.yiaddr, ipaddr_v4_bytes(&dv4s->address), sizeof reply.yiaddr);
        add_u32_option(&reply, DCODE_LEASET, htonl(dv4s->lifetime));
    }
    auto subnet = query_subnet(ifindex_);
    if (!subnet) return false;
    uint32_t subnet_addr;
    memcpy(&subnet_addr, ipaddr_v4_bytes(subnet), sizeof subnet_addr);
    add_option_subnet_mask(&reply, subnet_addr);

    auto broadcast = query_broadcast(ifindex_);
    if (!broadcast) return false;
    uint32_t broadcast_addr;
    memcpy(&broadcast_addr, ipaddr_v4_bytes(broadcast), sizeof broadcast_addr);
    add_option_broadcast(&reply, broadcast_addr);

    auto router = query_gateway_v4(ifindex_);
    if (router) {
        uint32_t router_addr;
        memcpy(&router_addr, ipaddr_v4_bytes(router), sizeof router_addr);
        add_option_router(&reply, router_addr);
    }

    auto dns_servers = query_dns_servers(ifindex_);
    if (dns_servers.n) iplist_option(&reply, DCODE_DNS, &dns_servers);

    auto ntp_servers = query_ntp_servers(ifindex_);
    if (ntp_servers.n) iplist_option(&reply, DCODE_NTPSVR, &ntp_servers);

    struct blob d4b = query_dns4_search_blob(ifindex_);
    if (d4b.n && d4b.s) add_option_domain_name(&reply, d4b.s, d4b.n);

    log_line("dhcp4: Sending reply %u.%u.%u.%u\n", reply.yiaddr & 255,
             (reply.yiaddr >> 8) & 255, (reply.yiaddr >> 16) & 255, (reply.yiaddr >> 24) & 255);

    return true;
}

void D4Listener::reply_discover()
{
    log_line("dhcp4: Got DHCP4 discover message\n");
    dhcpmsg reply;
    dhcpmsg_init(reply, DHCPOFFER, dhcpmsg_.xid);
    if (create_reply(reply, dhcpmsg_.chaddr, true))
        send_reply(reply);
}

void D4Listener::reply_request()
{
    log_line("dhcp4: Got DHCP4 request message\n");
    dhcpmsg reply;
    dhcpmsg_init(reply, DHCPACK, dhcpmsg_.xid);
    if (create_reply(reply, dhcpmsg_.chaddr, true)) {
        send_reply(reply);
    }
    state_.stateKill(dhcpmsg_.chaddr);
}

void D4Listener::reply_inform()
{
    log_line("dhcp4: Got DHCP4 inform message\n");
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
    auto ciaddr = u32_ipaddr(dhcpmsg_.ciaddr);
    auto valid = dynlease4_exists(ifname_, &ciaddr, dhcpmsg_.chaddr);
    if (!valid) {
        char buf[32] = "invalid ip";
        ip4_to_string(buf, sizeof buf, dhcpmsg_.ciaddr);
        log_line("dhcp4: do_release: ignoring spoofed release request for %s.\n", buf);
        return;
    }
    dynlease4_del(ifname_, &ciaddr, dhcpmsg_.chaddr);
}

uint8_t D4Listener::validate_dhcp(size_t len) const
{
    if (len < offsetof(struct dhcpmsg, options))
        return DHCPNULL;
    if (ntohl(dhcpmsg_.cookie) != DHCP_MAGIC)
        return DHCPNULL;
    return get_option_msgtype(&dhcpmsg_);
}

void D4Listener::process_receive(const char *buf, size_t buflen)
{
    size_t msglen = buflen < sizeof dhcpmsg_ ? buflen : sizeof dhcpmsg_;
    memset(&dhcpmsg_, 0, sizeof dhcpmsg_);
    memcpy(&dhcpmsg_, buf, msglen);
    uint8_t msgtype = validate_dhcp(msglen);
    if (!msgtype)
        return;

    auto cs = state_.stateGet(dhcpmsg_.xid, dhcpmsg_.chaddr);
    if (cs == DHCPNULL) {
        switch (msgtype) {
        case DHCPREQUEST:
        case DHCPDISCOVER:
            cs = msgtype;
            if (!state_.stateAdd(dhcpmsg_.xid, dhcpmsg_.chaddr, cs))
                return; // Possible DoS; silently drop.
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
    case DHCPDECLINE:  log_line("dhcp4: Received a DHCPDECLINE.  Clients conflict?\n");
    case DHCPRELEASE:  do_release(); break;
    }
}

