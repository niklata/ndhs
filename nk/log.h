// Copyright 2003-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_LOG_H_
#define NCM_LOG_H_

#include <stdlib.h>
#include "nk/daemon.h"

#define log_line(...) do { \
    nk_log(LOG_INFO, __VA_ARGS__); \
    } while (0)

#define suicide(...) do { \
    nk_log(LOG_CRIT, __VA_ARGS__); \
    exit(EXIT_FAILURE); } while (0)

#endif

