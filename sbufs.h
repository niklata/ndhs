// Copyright 2020-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_SBUFS_H_
#define NDHS_SBUFS_H_

#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <arpa/inet.h>
extern "C" {
#include "nk/log.h"
}

struct sbufs {
    char *si;
    char *se;

    size_t brem() const {
        return se > si ? static_cast<size_t>(se - si) : 0;
    }
};

static inline bool ip4_to_string(char *buf, size_t buflen, uint32_t addr)
{
    return !!inet_ntop(AF_INET, &addr, buf, buflen);
}

static inline bool sa6_from_string(sockaddr_in6 *sin, const char *str)
{
    memset(sin, 0, sizeof(sockaddr_in6));
    sin->sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, str, &sin->sin6_addr) != 1) {
        log_line("inet_pton failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}
static inline bool sa6_to_string(char *buf, size_t buflen, const void *sin, socklen_t sinlen)
{
    if (sinlen < sizeof(sockaddr_in6)) return false;
    return !!inet_ntop(AF_INET6, &((const sockaddr_in6 *)sin)->sin6_addr, buf, buflen);
}

#endif
