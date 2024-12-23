// Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_NLSOCKET_HPP_
#define NDHS_NLSOCKET_HPP_
#include <stdint.h>
extern "C" {
#include <ipaddr.h>
#include <net/if.h>
#include "nl.h"
}

struct netif_info
{
    char name[IFNAMSIZ];
    char macaddr[6];
    char macbc[6];
    in6_addr v4_address;
    in6_addr v6_address_global;
    in6_addr v6_address_link;
    int index;
    int link_type;
    unsigned int flags;
    unsigned int change_mask;
    unsigned int mtu;
    unsigned short device_type;
    unsigned char v6_prefixlen_global;
    unsigned char family;
    bool is_active:1;
    bool has_v4_address:1;
    bool has_v6_address_global:1;
    bool has_v6_address_link:1;
};

#define MAX_NL_INTERFACES 50

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
        for (int i = 0; i < MAX_NL_INTERFACES; ++i) {
            if (!strcmp(name, interfaces_[i].name)) return i;
        }
        return -1;
    }

    // The pointer that is returned is stable because the function is only
    // called after NLSocket is constructed.
    [[nodiscard]] netif_info *get_ifinfo(int ifindex)
    {
        if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return nullptr;
        return &interfaces_[ifindex];
    }
    [[nodiscard]] netif_info *get_ifinfo(const char *name)
    {
        for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
            if (!strcmp(name, interfaces_[i].name)) return &interfaces_[i];
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
    netif_info interfaces_[MAX_NL_INTERFACES];
    int query_ifindex_;
    int fd_;
    uint32_t nlseq_;
    bool got_newlink_:1;
};

#endif
