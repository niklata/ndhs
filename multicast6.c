#include "multicast6.h"
#include "nlsocket.h"
#include "nk/log.h"

extern struct NLSocket nl_socket;

bool attach_multicast_sockaddr_in6(int fd, const char *ifname, const struct sockaddr_in6 *mc6addr)
{
    int ifidx = NLSocket_get_ifindex(&nl_socket, ifname);
    if (ifidx < 0) {
        log_line("Failed to get interface index for %s\n", ifname);
        return false;
    }
    struct ifreq ifr = {0};
    memcpy(ifr.ifr_name, ifname, strlen(ifname));
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_line("failed to bind socket to device: %s\n", strerror(errno));
        return false;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof ifidx) < 0) {
        log_line("failed to set multicast interface for socket: %s\n", strerror(errno));
        return false;
    }
    int loopback = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopback, sizeof loopback) < 0) {
        log_line("failed to disable multicast loopback for socket: %s\n", strerror(errno));
        return false;
    }
    int hops = 255;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof hops) < 0) {
        log_line("failed to disable multicast hops for socket: %s\n", strerror(errno));
        return false;
    }
    struct ipv6_mreq mr = {
        .ipv6mr_multiaddr = mc6addr->sin6_addr,
        .ipv6mr_interface = (unsigned)ifidx,
    };
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mr, sizeof mr) < 0) {
        log_line("failed to join router multicast group for socket: %s\n", strerror(errno));
        return false;
    }
    return true;
}

bool attach_multicast_in6_addr(int fd, const char *ifname, const struct in6_addr *mc6addr)
{
    struct sockaddr_in6 sai = {
        .sin6_family = AF_INET6,
        .sin6_addr = *mc6addr,
    };
    return attach_multicast_sockaddr_in6(fd, ifname, &sai);
}
