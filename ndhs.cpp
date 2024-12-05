// Copyright 2014-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#define NDHS_VERSION "2.0"
#define LEASEFILE_PATH "/store/dynlease.txt"

#include <memory>
#include <string>
#include <vector>
#include <climits>
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
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <nk/from_string.hpp>
extern "C" {
#include "nk/log.h"
#include "nk/privs.h"
#include "nk/io.h"
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
static std::optional<int> s6_notify_fd;

NLSocket nl_socket;

static std::vector<std::unique_ptr<D6Listener>> v6_listeners;
static std::vector<std::unique_ptr<D4Listener>> v4_listeners;
static std::vector<std::unique_ptr<RA6Listener>> r6_listeners;

static std::vector<struct pollfd> poll_vector;
static std::vector<pfd_meta> poll_meta;

extern void parse_config(const std::string &path);

static void init_listeners()
{
    {
        nl_socket.init();
        {
            auto bn = bound_interfaces_names();
            for (auto &i: bn) {
                if (!nl_socket.add_interface(i.c_str())) {
                    // XXX: Maybe this should be a fatal error?  It indicates
                    //      the kernel changed the list of interfaces between
                    //      bound_interfaces_names() and now.
                    log_line("Interface %s does not exist!\n", i.c_str());
                }
            }
        }
        struct pollfd pt;
        pt.fd = nl_socket.fd();
        pt.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
        pt.revents = 0;
        poll_vector.push_back(pt);
        poll_meta.emplace_back(pfd_type::netlink, &nl_socket);
    }

    {
        auto bin = bound_interfaces_names();
        for (const auto &i: bin)
            log_line("Detected %s broadcast: %s subnet: %s\n", i.c_str(), query_broadcast(i)->to_string().c_str(),
                     query_subnet(i)->to_string().c_str());
    }

    auto v6l = &v6_listeners;
    auto vr6l = &r6_listeners;
    auto v4l = &v4_listeners;
    bound_interfaces_foreach([v6l, vr6l, v4l](const std::string &i, bool use_v4, bool use_v6,
                                              uint8_t preference) {
        if (use_v6) {
            v6l->emplace_back(std::make_unique<D6Listener>());
            if (!v6l->back()->init(i.c_str(), preference)) {
                v6l->pop_back();
                log_line("Can't bind to dhcpv6 interface: %s\n", i.c_str());
            } else {
                vr6l->emplace_back(std::make_unique<RA6Listener>());
                if (!vr6l->back()->init(i.c_str())) {
                    v6l->pop_back();
                    vr6l->pop_back();
                    log_line("Can't bind to rav6 interface: %s\n", i.c_str());
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
            if (!v4l->back()->init(i.c_str())) {
                v4l->pop_back();
                log_line("Can't bind to dhcpv4 interface: %s\n", i.c_str());
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
        suicide("clock_gettime failed\n");
    return ts.tv_sec;
}

void set_user_runas(size_t /* linenum */, std::string &&username)
{
    if (nk_uidgidbyname(username.c_str(), &ndhs_uid, &ndhs_gid))
        suicide("invalid user '%s' specified\n", username.c_str());
}
void set_chroot_path(size_t /* linenum */, std::string &&path)
{
    chroot_path = std::move(path);
}
void set_s6_notify_fd(size_t /* linenum */, int fd)
{
    s6_notify_fd = fd;
}

static volatile sig_atomic_t l_signal_exit;
static void signal_handler(int signo)
{
    int serrno = errno;
    if (signo == SIGINT || signo == SIGTERM) {
        l_signal_exit = 1;
    }
    errno = serrno;
}

static void setup_signals_ndhs()
{
    static const int ss[] = {
        SIGINT, SIGTERM, SIGKILL
    };
    sigset_t mask;
    if (sigprocmask(0, 0, &mask) < 0)
        suicide("sigprocmask failed\n");
    for (int i = 0; ss[i] != SIGKILL; ++i)
        if (sigdelset(&mask, ss[i]))
            suicide("sigdelset failed\n");
    if (sigaddset(&mask, SIGPIPE))
        suicide("sigaddset failed\n");
    if (sigprocmask(SIG_SETMASK, &mask, nullptr) < 0)
        suicide("sigprocmask failed\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    if (sigemptyset(&sa.sa_mask))
        suicide("sigemptyset failed\n");
    for (int i = 0; ss[i] != SIGKILL; ++i)
        if (sigaction(ss[i], &sa, NULL))
            suicide("sigaction failed\n");
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &sa, NULL))
        suicide("sigaction failed\n");
}

static void usage()
{
    printf("ndhs " NDHS_VERSION ", DHCPv4/DHCPv6 and IPv6 Router Advertisement server.\n");
    printf("Copyright 2014-2022 Nicholas J. Kain\n");
    printf("ndhs [options] [configfile]...\n\nOptions:\n");
    printf("--config          -c []  Path to configuration file.\n");
    printf("--version         -v     Print version and exit.\n");
    printf("--help            -h     Print this help and exit.\n");
}

static void print_version()
{
    log_line("ndhs " NDHS_VERSION ", ipv6 router advertisment and dhcp server.\n"
             "Copyright 2014-2022 Nicholas J. Kain\n\n"
"Permission is hereby granted, free of charge, to any person obtaining\n"
"a copy of this software and associated documentation files (the\n"
"\"Software\"), to deal in the Software without restriction, including\n"
"without limitation the rights to use, copy, modify, merge, publish,\n"
"distribute, sublicense, and/or sell copies of the Software, and to\n"
"permit persons to whom the Software is furnished to do so, subject to\n"
"the following conditions:\n\n"
"The above copyright notice and this permission notice shall be\n"
"included in all copies or substantial portions of the Software.\n\n"
"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n"
"EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n"
"MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND\n"
"NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE\n"
"LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION\n"
"OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION\n"
"WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n"
    );
}

static void process_options(int ac, char *av[])
{
    static struct option long_options[] = {
        {"config", 1, nullptr, 'c'},
        {"version", 0, nullptr, 'v'},
        {"help", 0, nullptr, 'h'},
        {nullptr, 0, nullptr, 0 }
    };
    for (;;) {
        auto c = getopt_long(ac, av, "c:vh", long_options, nullptr);
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
        suicide("No interfaces have been bound\n");
    if (!ndhs_uid || !ndhs_gid)
        suicide("No non-root user account is specified.\n");
    if (chroot_path.empty())
        suicide("No chroot path is specified.\n");

    init_listeners();

    umask(077);
    setup_signals_ndhs();

    nk_set_chroot(chroot_path.c_str());
    duid_load_from_file();
    dynlease_deserialize(LEASEFILE_PATH);
    nk_set_uidgid(ndhs_uid, ndhs_gid, nullptr, 0);

    if (s6_notify_fd) {
        char buf[] = "\n";
        safe_write(*s6_notify_fd, buf, 1);
        close(*s6_notify_fd);
    }
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
        dynlease_gc();
        if (poll(poll_vector.data(), poll_vector.size(), timeout > 0 ? timeout : 0) < 0) {
            if (errno != EINTR) suicide("poll failed\n");
        }
        if (l_signal_exit) break;
        for (size_t i = 0, iend = poll_vector.size(); i < iend; ++i) {
            switch (poll_meta[i].pfdt) {
            case pfd_type::netlink: {
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("nlfd closed unexpectedly\n");
                }
                if (poll_vector[i].revents & POLLIN) {
                    nl_socket.process_input();
                }
            } break;
            case pfd_type::dhcp6: {
                auto d6 = static_cast<D6Listener *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: dhcp6 socket closed unexpectedly\n", d6->ifname());
                }
                if (poll_vector[i].revents & POLLIN) {
                    d6->process_input();
                }
            } break;
            case pfd_type::dhcp4: {
                auto d4 = static_cast<D4Listener *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: dhcp4 socket closed unexpectedly\n", d4->ifname());
                }
                if (poll_vector[i].revents & POLLIN) {
                    d4->process_input();
                }
            } break;
            case pfd_type::radv6: {
                auto r6 = static_cast<RA6Listener *>(poll_meta[i].data);
                if (poll_vector[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: ra6 socket closed unexpectedly\n", r6->ifname());
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

