// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP6_HPP_
#define NDHS_DHCP6_HPP_

#include <stdint.h>
#include <net/if.h>
extern "C" {
#include <ipaddr.h>
}

struct D6Listener
{
    in6_addr local_ip_;
    in6_addr local_ip_prefix_;
    in6_addr link_local_ip_;
    char ifname_[IFNAMSIZ];
    int ifindex_;
    int fd_;
    unsigned char prefixlen_;
    uint8_t preference_;
    bool using_bpf_:1;
};

struct D6Listener *D6Listener_create(const char *ifname, uint8_t preference);
void D6Listener_process_input(struct D6Listener *self);
void D6Listener_destroy(struct D6Listener *self);

#endif
