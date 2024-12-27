// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_MULTICAST6_H_
#define NDHS_MULTICAST6_H_

#include <net/if.h>
#include <ipaddr.h>

bool attach_multicast_sockaddr_in6(int fd, const char *ifname, const struct sockaddr_in6 *mc6addr);
bool attach_multicast_in6_addr(int fd, const char *ifname, const struct in6_addr *mc6addr);

#endif
