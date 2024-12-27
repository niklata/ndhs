// Copyright 2020-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_SBUFS_H_
#define NDHS_SBUFS_H_

#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <arpa/inet.h>
#include "nk/log.h"

struct sbufs {
    char *si;
    char *se;
};

static inline size_t sbufs_brem(const struct sbufs *self)
{
    return self->se > self->si ? (size_t)(self->se - self->si) : 0;
}

static inline bool sa6_to_string(char *buf, size_t buflen, const void *sin, socklen_t sinlen)
{
    if (sinlen < sizeof(struct sockaddr_in6)) return false;
    return !!inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sin)->sin6_addr, buf, buflen);
}

#endif
