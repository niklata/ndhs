// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DUID_HPP_
#define NDHS_DUID_HPP_

#include <stdint.h>

constexpr auto g_server_duid_len{sizeof(uint16_t) + sizeof(uint64_t) * 2};
extern char g_server_duid[g_server_duid_len];

void duid_load_from_file();

#endif
