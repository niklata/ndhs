#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <format.hpp>
#include <nk/xorshift.hpp>
#include <nk/scopeguard.hpp>
extern "C" {
#include "nk/io.h"
}
#include "duid.hpp"

extern nk::rng::xoroshiro128p g_random_prng;

#define DUID_PATH "/store/duid.txt"
char g_server_duid[g_server_duid_len];

static void print_duid()
{
    fmt::printf("DUID is '%02.x", static_cast<uint8_t>(g_server_duid[0]));
    for (unsigned i = 1; i < g_server_duid_len; ++i)
        fmt::printf("-%02.x", static_cast<uint8_t>(g_server_duid[i]));
    fmt::print("'\n");
}

// Use DUID-UUID (RFC6355)
static void generate_duid()
{
    size_t off{0};

    const uint16_t typefield = htons(4);
    memcpy(g_server_duid + off, &typefield, sizeof typefield);
    off += sizeof typefield;
    const uint64_t r0 = g_random_prng();
    const uint64_t r1 = g_random_prng();
    memcpy(g_server_duid + off, &r0, sizeof r0);
    off += sizeof r0;
    memcpy(g_server_duid + off, &r1, sizeof r1);
    off += sizeof r1;

    const auto fd = open(DUID_PATH, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0) throw std::runtime_error(fmt::format("{}: failed to open {} for write\n",
                                                     __func__, DUID_PATH));
    SCOPE_EXIT { close(fd); };
    const auto r = safe_write(fd, g_server_duid, g_server_duid_len);
    if (r < 0 || r != g_server_duid_len)
        throw std::runtime_error(fmt::format("{}: failed to write duid to {}\n",
                                             __func__, DUID_PATH));
    print_duid();
}

void duid_load_from_file()
{
    const auto fd = open(DUID_PATH, O_RDONLY, 0);
    if (fd < 0) {
        fmt::print("No DUID found.  Generating a DUID.\n");
        generate_duid();
        return;
    }
    SCOPE_EXIT { close(fd); };
    const auto r = safe_read(fd, g_server_duid, g_server_duid_len);
    if (r < 0) throw std::runtime_error(fmt::format("{}: failed to read duid from {}\n",
                                                    __func__, DUID_PATH));
    if (r != g_server_duid_len) {
        fmt::print("DUID is too short to be valid.  Generating a new DUID.\n");
        generate_duid();
        return;
    }
    print_duid();
}

