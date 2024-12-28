// Copyright 2020-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_SBUFS_H_
#define NDHS_SBUFS_H_

#include <stddef.h>

struct sbufs {
    char *si;
    char *se;
};

static inline size_t sbufs_brem(const struct sbufs *self)
{
    return self->se > self->si ? (size_t)(self->se - self->si) : 0;
}

#endif
