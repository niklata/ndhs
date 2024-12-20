// Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_NLSOCKET_HPP_
#define NDHS_NLSOCKET_HPP_
#include <stdint.h>
#include <vector>
extern "C" {
#include <ipaddr.h>
#include <net/if.h>
#include "nl.h"
}

struct netif_addr
{
    enum class Scope {
        Global = RT_SCOPE_UNIVERSE,
        Site = RT_SCOPE_SITE,
        Link = RT_SCOPE_LINK,
        Host = RT_SCOPE_HOST,
        None = RT_SCOPE_NOWHERE,
    };

    char if_name[IFNAMSIZ];
    int if_index;
    in6_addr address;
    in6_addr peer_address;
    in6_addr broadcast_address;
    in6_addr anycast_address;
    unsigned char addr_type;
    unsigned char prefixlen;
    unsigned char flags;
    Scope scope;
};

struct netif_info
{
    char name[IFNAMSIZ];
    unsigned char family;
    unsigned short device_type;
    int index;
    unsigned int flags;
    unsigned int change_mask;
    unsigned int mtu;
    int link_type;
    char macaddr[6];
    char macbc[6];
    bool is_active:1;

    std::vector<netif_addr> addrs;
};

struct NLSocket
{
    NLSocket() {}
    NLSocket(const NLSocket &) = delete;
    NLSocket &operator=(const NLSocket &) = delete;

    void init();
    [[nodiscard]] bool get_interface_addresses(int ifindex);

    void process_input();
    auto fd() const { return fd_; }
    [[nodiscard]] int get_ifindex(const char *name) const {
        for (auto &i: ifaces_) {
            if (!strcmp(name, i.name)) return i.index;
        }
        return -1;
    }

    // The pointer that is returned is stable because the function is only
    // called after NLSocket is constructed.
    [[nodiscard]] netif_info *get_ifinfo(int ifindex)
    {
        for (auto &i: ifaces_) {
            if (ifindex == i.index) return &i;
        }
        return nullptr;
    }
    [[nodiscard]] netif_info *get_ifinfo(const char *name)
    {
        for (auto &i: ifaces_) {
            if (!strcmp(name, i.name)) return &i;
        }
        return nullptr;
    }
private:
    void process_receive(const char *buf, size_t bytes_xferred,
                         unsigned seq, unsigned portid);
    void process_rt_link_msgs(const struct nlmsghdr *nlh);
    void process_rt_addr_msgs(const struct nlmsghdr *nlh);
    void process_nlmsg(const struct nlmsghdr *nlh);
    void request_links();
    void request_addrs(int ifidx);
    std::vector<netif_info> ifaces_;
    int query_ifindex_;
    int fd_;
    uint32_t nlseq_;
    bool got_newlink_:1;
};

#endif
