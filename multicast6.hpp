#ifndef NK_NRAD6_MULTICAST6_HPP_
#define NK_NRAD6_MULTICAST6_HPP_

#include <string>
#include <asio.hpp>
#include "nlsocket.hpp"
extern "C" {
#include "nk/log.h"
}

extern std::unique_ptr<NLSocket> nl_socket;
[[nodiscard]] static inline bool attach_multicast(int fd, const std::string &ifname, const sockaddr_in6 &mc6addr)
{
    int ifidx;
    if (auto t = nl_socket->get_ifindex(ifname)) ifidx = *t;
    else {
        log_line("Failed to get interface index for %s", ifname.c_str());
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_line("failed to bind socket to device: %s", strerror(errno));
        return false;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof ifidx) < 0) {
        log_line("failed to set multicast interface for socket: %s", strerror(errno));
        return false;
    }
    int loopback(0);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopback, sizeof loopback) < 0) {
        log_line("failed to disable multicast loopback for socket: %s", strerror(errno));
        return false;
    }
    int hops(255);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof hops) < 0) {
        log_line("failed to disable multicast hops for socket: %s", strerror(errno));
        return false;
    }
    struct ipv6_mreq mr;
    memcpy(&mr.ipv6mr_multiaddr, &mc6addr.sin6_addr, sizeof mc6addr.sin6_addr);
    mr.ipv6mr_interface = ifidx;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mr, sizeof mr) < 0) {
        log_line("failed to join router multicast group for socket: %s", strerror(errno));
        return false;
    }
    return true;
}

[[nodiscard]] static inline bool attach_multicast(int fd, const std::string &ifname, asio::ip::address_v6 &mc6addr)
{
    sockaddr_in6 sai;
    memset(&sai, 0, sizeof sai);
    sai.sin6_family = AF_INET6;
    memcpy(&sai.sin6_addr, mc6addr.to_bytes().data(), sizeof sai.sin6_addr);
    return attach_multicast(fd, ifname, sai);
}
#endif

