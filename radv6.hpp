// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_RADV6_H_
#define NDHS_RADV6_H_

#include <time.h>
#include <net/if.h>

struct RA6Listener
{
    struct timespec advert_ts_;
    char ifname_[IFNAMSIZ];
    int fd_;
    unsigned advi_s_max_;
    bool using_bpf_:1;
};

struct RA6Listener *RA6Listener_create(const char *ifname);
void RA6Listener_process_input(struct RA6Listener *self);
int RA6Listener_send_periodic_advert(struct RA6Listener *self);

#endif
