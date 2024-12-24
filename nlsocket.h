// Copyright 2014-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_NLSOCKET_H_
#define NDHS_NLSOCKET_H_

#include <stdint.h>
#include <ipaddr.h>
#include <net/if.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "nl.h"

#define MAX_NL_INTERFACES 50

struct netif_info
{
    char name[IFNAMSIZ];
    char macaddr[6];
    char macbc[6];
    struct in6_addr v4_address;
    struct in6_addr v6_address_global;
    struct in6_addr v6_address_link;
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

struct NLSocket
{
    struct netif_info interfaces_[MAX_NL_INTERFACES];
    int query_ifindex_;
    int fd_;
    uint32_t nlseq_;
    bool got_newlink_:1;
};

void NLSocket_init(struct NLSocket *self);
bool NLSocket_get_interface_addresses(struct NLSocket *self, int ifindex);

void NLSocket_process_input(struct NLSocket *self);

static inline int NLSocket_get_ifindex(const struct NLSocket *self, const char *name) {
    for (int i = 0; i < MAX_NL_INTERFACES; ++i) {
        if (!strcmp(name, self->interfaces_[i].name)) return i;
    }
    return -1;
}

// The pointer that is returned is stable because the function is only
// called after NLSocket is constructed.
static inline struct netif_info *NLSocket_get_ifinfo(struct NLSocket *self, int ifindex)
{
    if (ifindex < 0 || ifindex >= MAX_NL_INTERFACES) return NULL;
    return &self->interfaces_[ifindex];
}
static inline struct netif_info *NLSocket_get_ifinfo_by_name(struct NLSocket *self, const char *name)
{
    for (size_t i = 0; i < MAX_NL_INTERFACES; ++i) {
        if (!strcmp(name, self->interfaces_[i].name)) return &self->interfaces_[i];
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif
