// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_RADV6_H_
#define NDHS_RADV6_H_

struct netif_info;
struct RA6Listener;
struct RA6Listener *RA6Listener_create(const char *ifname, const struct netif_info *ifinfo);
void RA6Listener_process_input(struct RA6Listener *self);
int RA6Listener_send_periodic_advert(struct RA6Listener *self);
int RA6Listener_fd(const struct RA6Listener *self);

#endif
