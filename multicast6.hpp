#ifndef NK_NRAD6_MULTICAST6_HPP_
#define NK_NRAD6_MULTICAST6_HPP_

#include <string>
#include <asio.hpp>
#include "nlsocket.hpp"
extern "C" {
#include "nk/log.h"
}

extern std::unique_ptr<NLSocket> nl_socket;
static void attach_multicast(int fd, const std::string &ifname, asio::ip::address_v6 &mc6addr)
{
    auto ifidx = nl_socket->get_ifindex(ifname);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0)
        suicide("failed to bind socket to device: %s", strerror(errno));
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                   &ifidx, sizeof ifidx) < 0)
        suicide("failed to set multicast interface for socket: %s", strerror(errno));
    int loopback(0);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                   &loopback, sizeof loopback) < 0)
        suicide("failed to disable multicast loopback for socket: %s", strerror(errno));
    int hops(255);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                   &hops, sizeof hops) < 0)
        suicide("failed to disable multicast hops for socket: %s", strerror(errno));
    auto mrb = mc6addr.to_bytes();
    struct ipv6_mreq mr;
    memcpy(&mr.ipv6mr_multiaddr, mrb.data(), sizeof mrb);
    mr.ipv6mr_interface = ifidx;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                   &mr, sizeof mr) < 0)
        suicide("failed to join router multicast group for socket: %s", strerror(errno));

#if 0
    asio::ip::multicast::join_group mc_routers_group(mc6_allrouters);
    socket_.set_option(mc_routers_group);
#endif

}

#endif

