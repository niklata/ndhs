// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DUID_H_
#define NDHS_DUID_H_

#include <stdint.h>
#define SERVER_DUID_LEN (sizeof(uint16_t) + sizeof(uint64_t) * 2)

extern char g_server_duid[SERVER_DUID_LEN];
void duid_load_from_file(void);

#endif
