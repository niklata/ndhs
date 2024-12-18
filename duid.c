// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "nk/io.h"
#include "nk/log.h"
#include "duid.h"
#include "rng.h"

#define DUID_PATH "/store/duid.txt"
char g_server_duid[SERVER_DUID_LEN];

static void print_duid(void)
{
    if (SERVER_DUID_LEN <= 0) return;
    log_line("DUID is '");
    char tbuf[16] = {0};
    for (unsigned i = 0; i < SERVER_DUID_LEN; ++i) {
        snprintf(tbuf, sizeof tbuf, "%.2hhx", (uint8_t)g_server_duid[i]);
        log_line("%s", tbuf);
    }
    log_line("'\n");
}

// Use DUID-UUID (RFC6355)
static void generate_duid(void)
{
    size_t off = 0;

    uint16_t typefield = htons(4);
    memcpy(g_server_duid + off, &typefield, sizeof typefield);
    off += sizeof typefield;
    uint64_t r0 = nk_random_u64();
    uint64_t r1 = nk_random_u64();
    memcpy(g_server_duid + off, &r0, sizeof r0);
    off += sizeof r0;
    memcpy(g_server_duid + off, &r1, sizeof r1);
    off += sizeof r1;

    int fd = open(DUID_PATH, O_WRONLY|O_TRUNC|O_CREAT|O_CLOEXEC, 0644);
    if (fd < 0) suicide("%s: failed to open %s for write\n", __func__, DUID_PATH);
    ssize_t r = safe_write(fd, g_server_duid, SERVER_DUID_LEN);
    if (r < 0 || r != SERVER_DUID_LEN)
        suicide("%s: failed to write duid to %s\n", __func__, DUID_PATH);
    print_duid();
    close(fd);
}

void duid_load_from_file(void)
{
    int fd = open(DUID_PATH, O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0) {
        log_line("No DUID found.  Generating a DUID.\n");
        generate_duid();
        return;
    }
    ssize_t r = safe_read(fd, g_server_duid, SERVER_DUID_LEN);
    if (r < 0) suicide("%s: failed to read duid from %s\n", __func__, DUID_PATH);
    if (r != SERVER_DUID_LEN) {
        log_line("DUID is too short to be valid.  Generating a new DUID.\n");
        generate_duid();
        goto out0;
    }
    print_duid();
out0:
    close(fd);
}

