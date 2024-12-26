// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP6_H_
#define NDHS_DHCP6_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct D6Listener;
struct D6Listener *D6Listener_create(const char *ifname, uint8_t preference);
void D6Listener_process_input(struct D6Listener *self);
void D6Listener_destroy(struct D6Listener *self);
int D6Listener_fd(const struct D6Listener *self);

#ifdef __cplusplus
}
#endif

#endif
