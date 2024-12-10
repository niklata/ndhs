// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <nk/scopeguard.hpp>
extern "C" {
#include "nk/io.h"
#include "nk/log.h"
}
#include "duid.hpp"
#include "rng.hpp"

#define DUID_PATH "/store/duid.txt"
char g_server_duid[g_server_duid_len];

static void print_duid()
{
    if (g_server_duid_len <= 0) return;
    log_line("DUID is '");
    char tbuf[16] = {0};
    snprintf(tbuf, sizeof tbuf, "%.2hhx", static_cast<uint8_t>(g_server_duid[0]));
    log_line("%s", tbuf);
    for (unsigned i = 1; i < g_server_duid_len; ++i) {
        snprintf(tbuf, sizeof tbuf, "-%.2hhx", static_cast<uint8_t>(g_server_duid[i]));
        log_line("%s", tbuf);
    }
    log_line("'\n");
}

// Use DUID-UUID (RFC6355)
static void generate_duid()
{
    size_t off{0};

    const uint16_t typefield = htons(4);
    memcpy(g_server_duid + off, &typefield, sizeof typefield);
    off += sizeof typefield;
    const auto r0 = nk_random_u64();
    const auto r1 = nk_random_u64();
    memcpy(g_server_duid + off, &r0, sizeof r0);
    off += sizeof r0;
    memcpy(g_server_duid + off, &r1, sizeof r1);
    off += sizeof r1;

    const auto fd = open(DUID_PATH, O_WRONLY|O_TRUNC|O_CREAT|O_CLOEXEC, 0644);
    if (fd < 0) suicide("%s: failed to open %s for write\n", __func__, DUID_PATH);
    SCOPE_EXIT { close(fd); };
    const auto r = safe_write(fd, g_server_duid, g_server_duid_len);
    if (r < 0 || r != g_server_duid_len)
        suicide("%s: failed to write duid to %s\n", __func__, DUID_PATH);
    print_duid();
}

void duid_load_from_file()
{
    const auto fd = open(DUID_PATH, O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0) {
        log_line("No DUID found.  Generating a DUID.\n");
        generate_duid();
        return;
    }
    SCOPE_EXIT { close(fd); };
    const auto r = safe_read(fd, g_server_duid, g_server_duid_len);
    if (r < 0) suicide("%s: failed to read duid from %s\n", __func__, DUID_PATH);
    if (r != g_server_duid_len) {
        log_line("DUID is too short to be valid.  Generating a new DUID.\n");
        generate_duid();
        return;
    }
    print_duid();
}

