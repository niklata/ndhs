/* ndhs.c - DHCPv4/DHCPv6 and IPv6 router advertisement server
 *
 * Copyright 2014-2017 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define NDHS_VERSION "2.0"
#define LEASEFILE_PATH "/store/dynlease.txt"

#include <memory>
#include <string>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <asio.hpp>
#include <fmt/format.h>
#include <nk/optionarg.hpp>
#include <nk/from_string.hpp>
#include <nk/prng.hpp>
extern "C" {
#include "nk/log.h"
#include "nk/privilege.h"
}
#include "nlsocket.hpp"
#include "dhcp6.hpp"
#include "dhcp4.hpp"
#include "dhcp_state.hpp"
#include "dynlease.hpp"
#include "duid.hpp"

asio::io_service io_service;
static asio::signal_set asio_signal_set(io_service);
static std::string configfile{"/etc/ndhs.conf"};
static std::string chroot_path;
static uid_t ndhs_uid;
static gid_t ndhs_gid;

std::unique_ptr<NLSocket> nl_socket;

static std::vector<std::unique_ptr<D6Listener>> v6_listeners;
static std::vector<std::unique_ptr<D4Listener>> v4_listeners;

nk::rng::prng g_random_prng;

extern void parse_config(const std::string &path);

static void init_listeners()
{
    auto ios = &io_service;
    auto v6l = &v6_listeners;
    auto v4l = &v4_listeners;
    bound_interfaces_foreach([ios, v6l, v4l](const std::string &i, bool use_v4, bool use_v6,
                                             uint8_t preference) {
        if (use_v6) {
            v6l->emplace_back(std::make_unique<D6Listener>(*ios));
            if (!v6l->back()->init(i, preference)) {
                v6l->pop_back();
                fmt::print(stderr, "Can't bind to v6 interface: {}\n", i);
            }
        }
        if (use_v4) {
            v4l->emplace_back(std::make_unique<D4Listener>(*ios));
            if (!v4l->back()->init(i)) {
                v4l->pop_back();
                fmt::print(stderr, "Can't bind to v4 interface: {}\n", i);
            }
        }
    });
}

int64_t get_current_ts()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        suicide("clock_gettime failed");
    return ts.tv_sec;
}

void set_user_runas(size_t /* linenum */, std::string &&username)
{
    if (nk_uidgidbyname(username.c_str(), &ndhs_uid, &ndhs_gid)) {
        fmt::print(stderr, "invalid user '{}' specified\n", username);
        std::exit(EXIT_FAILURE);
    }
}
void set_chroot_path(size_t /* linenum */, std::string &&path)
{
    chroot_path = std::move(path);
}

static void process_signals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        fmt::print(stderr, "sigprocmask failed\n");
        std::exit(EXIT_FAILURE);
    }
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait([](const std::error_code &, int) { io_service.stop(); });
}

static void print_version(void)
{
    fmt::print(stderr, "ndhs " NDHS_VERSION ", ipv6 router advertisment and dhcp server.\n"
               "Copyright 2014-2017 Nicholas J. Kain\n"
               "All rights reserved.\n\n"
               "Redistribution and use in source and binary forms, with or without\n"
               "modification, are permitted provided that the following conditions are met:\n\n"
               "- Redistributions of source code must retain the above copyright notice,\n"
               "  this list of conditions and the following disclaimer.\n"
               "- Redistributions in binary form must reproduce the above copyright notice,\n"
               "  this list of conditions and the following disclaimer in the documentation\n"
               "  and/or other materials provided with the distribution.\n\n"
               "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
               "AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
               "IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
               "ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n"
               "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
               "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
               "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
               "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
               "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
               "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
               "POSSIBILITY OF SUCH DAMAGE.\n");
}

enum OpIdx {
    OPT_UNKNOWN, OPT_HELP, OPT_VERSION, OPT_CONFIG, OPT_QUIET
};
static const option::Descriptor usage[] = {
    { OPT_UNKNOWN,    0,  "",           "", Arg::Unknown,
        "ndhs " NDHS_VERSION ", DHCPv4/DHCPv6 and IPv6 Router Advertisement server.\n"
        "Copyright 2014-2017 Nicholas J. Kain\n"
        "ndhs [options] [configfile]...\n\nOptions:" },
    { OPT_HELP,       0, "h",            "help",    Arg::None, "\t-h, \t--help  \tPrint usage and exit." },
    { OPT_VERSION,    0, "v",         "version",    Arg::None, "\t-v, \t--version  \tPrint version and exit." },
    { OPT_CONFIG,     0, "c",          "config",  Arg::String, "\t-c, \t--config  \tPath to configuration file (default: /etc/ndhs.conf)."},
    { OPT_QUIET,      0, "q",           "quiet",    Arg::None, "\t-q, \t--quiet  \tDon't log to std(out|err) or syslog." },
    {0,0,0,0,0,0}
};
static void process_options(int ac, char *av[])
{
    ac-=ac>0; av+=ac>0;
    option::Stats stats(usage, ac, av);
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
    option::Option options[stats.options_max], buffer[stats.buffer_max];
#pragma GCC diagnostic pop
    option::Parser parse(usage, ac, av, options, buffer);
#else
    auto options = std::make_unique<option::Option[]>(stats.options_max);
    auto buffer = std::make_unique<option::Option[]>(stats.buffer_max);
    option::Parser parse(usage, ac, av, options.get(), buffer.get());
#endif
    if (parse.error())
        std::exit(EXIT_FAILURE);
    if (options[OPT_HELP]) {
        uint16_t col{80};
        if (const auto cols = getenv("COLUMNS")) {
            if (auto t = nk::from_string<uint16_t>(cols)) col = *t;
        }
        option::printUsage(fwrite, stdout, usage, col);
        std::exit(EXIT_FAILURE);
    }
    if (options[OPT_VERSION]) {
        print_version();
        std::exit(EXIT_FAILURE);
    }

    std::vector<std::string> addrlist;

    for (int i = 0; i < parse.optionsCount(); ++i) {
        option::Option &opt = buffer[i];
        switch (opt.index()) {
            case OPT_CONFIG: configfile = std::string(opt.arg); break;
            case OPT_QUIET: gflags_quiet = 1; break;
        }
    }

    if (configfile.size())
        parse_config(configfile);

    for (int i = 0; i < parse.nonOptionsCount(); ++i)
        parse_config(parse.nonOption(i));

    if (!bound_interfaces_count()) {
        fmt::print(stderr, "No interfaces have been bound\n");
        std::exit(EXIT_FAILURE);
    }
    if (!ndhs_uid || !ndhs_gid) {
        fmt::print(stderr, "No non-root user account is specified.\n");
        std::exit(EXIT_FAILURE);
    }
    if (chroot_path.empty()) {
        fmt::print(stderr, "No chroot path is specified.\n");
        std::exit(EXIT_FAILURE);
    }

    nl_socket = std::make_unique<NLSocket>(io_service);
    init_listeners();

    umask(077);
    process_signals();

    nk_set_chroot(chroot_path.c_str());
    duid_load_from_file();
    dynlease_deserialize(LEASEFILE_PATH);
    nk_set_uidgid(ndhs_uid, ndhs_gid, nullptr, 0);
}

int main(int ac, char *av[])
{
    gflags_log_name = const_cast<char *>("ndhs");

    process_options(ac, av);

    io_service.run();

    dynlease_serialize(LEASEFILE_PATH);

    std::exit(EXIT_SUCCESS);
}

