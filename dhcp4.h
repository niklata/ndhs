// Copyright 2011-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP4_H
#define NDHS_DHCP4_H

#ifdef __cplusplus
extern "C" {
#endif

struct netif_info;
struct D4Listener;
struct D4Listener *D4Listener_create(const char *ifname, const struct netif_info *ifinfo);
void D4Listener_process_input(struct D4Listener *self);
int D4Listener_fd(const struct D4Listener *self);

#ifdef __cplusplus
}
#endif

#endif
