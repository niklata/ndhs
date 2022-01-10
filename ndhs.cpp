/* ndhs.c - DHCPv4/DHCPv6 and IPv6 router advertisement server
 *
 * Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
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
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <nk/from_string.hpp>
extern "C" {
#include "nk/log.h"
#include "nk/privs.h"
}
#include "nlsocket.hpp"
#include "dhcp6.hpp"
#include "dhcp4.hpp"
#include "dhcp_state.hpp"
#include "dynlease.hpp"
#include "duid.hpp"

enum class pfd_type
{
    netlink,
    dhcp6,
    dhcp4,
    radv6,
};

struct pfd_meta
{
    pfd_meta(pfd_type p, void *d) : pfdt(p), data(d) {}
    pfd_type pfdt;
    void *data;
};

static std::string configfile{"/etc/ndhs.conf"};
static std::string chroot_path;
static uid_t ndhs_uid;
static gid_t ndhs_gid;

std::unique_ptr<NLSocket> nl_socket;

static std::vector<std::unique_ptr<D6Listener>> v6_listeners;
static std::vector<std::unique_ptr<D4Listener>> v4_listeners;
static std::vector<std::unique_ptr<RA6Listener>> r6_listeners;

static std::vector<struct pollfd> poll_vector;
static std::vector<pfd_meta> poll_meta;

extern void parse_config(const std::string &path);

static void init_listeners()
{
    nl_socket = std::make_unique<NLSocket>(bound_interfaces_names());
    struct pollfd pt;
    pt.fd = nl_socket->fd();
    pt.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pt.revents = 0;
    poll_vector.push_back(pt);
    poll_meta.emplace_back(pfd_type::netlink, nl_socket.get());

    auto v6l = &v6_listeners;
    auto vr6l = &r6_listeners;
    auto v4l = &v4_listeners;
    bound_interfaces_foreach([v6l, vr6l, v4l](const std::string &i, bool use_v4, bool use_v6,
                                              uint8_t preference) {
        if (use_v6) {
            v6l->emplace_back(std::make_unique<D6Listener>());
            if (!v6l->back()->init(i, preference)) {
                v6l->pop_back();
                log_line("Can't bind to dhcpv6 interface: %s", i.c_str());
            } else {
                vr6l->emplace_back(std::make_unique<RA6Listener>());
                if (!vr6l->back()->init(i)) {
                    v6l->pop_back();
                    vr6l->pop_back();
                    log_line("Can't bind to rav6 interface: %s", i.c_str());
                } else {
                    struct pollfd pt;
                    pt.fd = v6l->back()->fd();
                    pt.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
                    pt.revents = 0;
                    poll_vector.push_back(pt);
                    poll_meta.emplace_back(pfd_type::dhcp6, v6l->back().get());
                    pt.fd = vr6l->back()->fd();
                    pt.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
                    pt.revents = 0;
                    poll_vector.push_back(pt);
                    poll_meta.emplace_back(pfd_type::radv6, vr6l->back().get());
                }
            }
        }
        if (use_v4) {
            v4l->emplace_back(std::make_unique<D4Listener>());
            if (!v4l->back()->init(i)) {
                v4l->pop_back();
                log_line("Can't bind to dhcpv4 interface: %s", i.c_str());
            } else {
                struct pollfd pt;
                pt.fd = v4l->back()->fd();
                pt.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
                pt.revents = 0;
                poll_vector.push_back(pt);
                poll_meta.emplace_back(pfd_type::dhcp4, v4l->back().get());
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
    if (nk_uidgidbyname(username.c_str(), &ndhs_uid, &ndhs_gid))
        suicide("invalid user '%s' specified", username.c_str());
}
void set_chroot_path(size_t /* linenum */, std::string &&path)
{
    chroot_path = std::move(path);
}

static volatile sig_atomic_t l_signal_exit;
static void signal_handler(int signo)
{
    switch (signo) {
    case SIGCHLD: {
        while (waitpid(-1, nullptr, WNOHANG) > -1);
        break;
    }
    case SIGINT:
    case SIGTERM: l_signal_exit = 1; break;
    default: break;
    }
}

static void setup_signals_ndhs()
{
    static const int ss[] = {
        SIGCHLD, SIGINT, SIGTERM, SIGKILL
    };
    sigset_t mask;
    if (sigprocmask(0, 0, &mask) < 0)
        suicide("sigprocmask failed");
    for (int i = 0; ss[i] != SIGKILL; ++i)
        if (sigdelset(&mask, ss[i]))
            suicide("sigdelset failed");
    if (sigaddset(&mask, SIGPIPE))
        suicide("sigaddset failed");
    if (sigprocmask(SIG_SETMASK, &mask, static_cast<sigset_t *>(nullptr)) < 0)
        suicide("sigprocmask failed");

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    if (sigemptyset(&sa.sa_mask))
        suicide("sigemptyset failed");
    for (int i = 0; ss[i] != SIGKILL; ++i)
        if (sigaction(ss[i], &sa, NULL))
            suicide("sigaction failed");
}

static void usage()
{
    printf("ndhs " NDHS_VERSION ", DHCPv4/DHCPv6 and IPv6 Router Advertisement server.\n");
    printf("Copyright 2014-2020 Nicholas J. Kain\n");
    printf("ndhs [options] [configfile]...\n\nOptions:");
    printf("--config          -c []  Path to configuration file.\n");
    printf("--version         -v     Print version and exit.\n");
    printf("--help            -h     Print this help and exit.\n");
}

static void print_version()
{
    log_line("ndhs " NDHS_VERSION ", ipv6 router advertisment and dhcp server.\n"
             "Copyright 2014-2020 Nicholas J. Kain\n"
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

static void process_options(int ac, char *av[])
{
    static struct option long_options[] = {
        {"config", 1, (int *)0, 'c'},
        {"version", 0, (int *)0, 'v'},
        {"help", 0, (int *)0, 'h'},
        {(const char *)0, 0, (int *)0, 0 }
    };
    for (;;) {
        auto c = getopt_long(ac, av, "qc:vh", long_options, (int *)0);
        if (c == -1) break;
        switch (c) {
            case 'c': configfile = optarg; break;
            case 'v': print_version(); std::exit(EXIT_SUCCESS); break;
            case 'h': usage(); std::exit(EXIT_SUCCESS); break;
            default: break;
        }
    }

    if (configfile.size())
        parse_config(configfile);

    if (!bound_interfaces_count())
        suicide("No interfaces have been bound");
    if (!ndhs_uid || !ndhs_gid)
        suicide("No non-root user account is specified.");
    if (chroot_path.empty())
        suicide("No chroot path is specified.");

    init_listeners();

    umask(077);
    setup_signals_ndhs();

    nk_set_chroot(chroot_path.c_str());
    duid_load_from_file();
    dynlease_deserialize(LEASEFILE_PATH);
    nk_set_uidgid(ndhs_uid, ndhs_gid, nullptr, 0);
}

int main(int ac, char *av[])
{
    process_options(ac, av);

    for (;;) {
        int timeout = INT_MAX;
        for (auto &i: r6_listeners) {
            auto t = i->send_periodic_advert();
            timeout = std::min(timeout, t);
        }
        if (poll(poll_vector.data(), poll_vector.size(), timeout > 0 ? timeout : 0) < 0) {
            if (errno != EINTR) suicide("poll failed");
        }
        if (l_signal_exit) break;
        for (size_t i = 0, iend = poll_vector.size(); i < iend; ++i) {
            switch (poll_meta[i].pfdt) {
            case pfd_type::netlink: {
                auto nl = static_cast<NLSocket *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("nlfd closed unexpectedly");
                }
                if (poll_vector[i].revents & POLLIN) {
                    nl->process_input();
                }
            } break;
            case pfd_type::dhcp6: {
                auto d6 = static_cast<D6Listener *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: dhcp6 socket closed unexpectedly", d6->ifname().c_str());
                }
                if (poll_vector[i].revents & POLLIN) {
                    d6->process_input();
                }
            } break;
            case pfd_type::dhcp4: {
                auto d4 = static_cast<D4Listener *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: dhcp4 socket closed unexpectedly", d4->ifname().c_str());
                }
                if (poll_vector[i].revents & POLLIN) {
                    d4->process_input();
                }
            } break;
            case pfd_type::radv6: {
                auto r6 = static_cast<RA6Listener *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: ra6 socket closed unexpectedly", r6->ifname().c_str());
                }
                if (poll_vector[i].revents & POLLIN) {
                    r6->process_input();
                }
            } break;
            }
        }
    }

    dynlease_serialize(LEASEFILE_PATH);

    std::exit(EXIT_SUCCESS);
}

