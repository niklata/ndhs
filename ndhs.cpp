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
    pfd_type pfdt;
    void *data;
};

static const char *configfile = "/etc/ndhs.conf";
static char *chroot_path;
static uid_t ndhs_uid;
static gid_t ndhs_gid;
static int s6_notify_fd = -1;

NLSocket nl_socket;

static std::vector<std::unique_ptr<D6Listener>> v6_listeners;
static std::vector<std::unique_ptr<D4Listener>> v4_listeners;
static std::vector<std::unique_ptr<RA6Listener>> r6_listeners;

static struct pollfd *poll_array;
static struct pfd_meta *poll_meta;
static size_t poll_size;

extern bool parse_config(const char *path);

static void get_interface_addresses(const struct netif_info *ifinfo, bool, bool, uint8_t, void *)
{
    if (!nl_socket.get_interface_addresses(ifinfo->index)) {
        // XXX: Maybe this should be a fatal error?  It indicates
        //      the kernel changed the list of interfaces between
        //      bound_interfaces_names() and now.
        log_line("Interface %s does not exist!\n", ifinfo->name);
    }
}

static void create_interface_listener(const struct netif_info *ifinfo,
                                      bool use_v4, bool use_v6,
                                      uint8_t preference, void *)
{
    if (use_v6) {
        auto d6l = std::make_unique<D6Listener>();
        if (d6l->init(ifinfo->name, preference)) {
            auto r6l = std::make_unique<RA6Listener>();
            if (r6l->init(ifinfo->name)) {
                v6_listeners.emplace_back(std::move(d6l));
                r6_listeners.emplace_back(std::move(r6l));
            } else log_line("Can't bind to rav6 interface: %s\n", ifinfo->name);
        } else log_line("Can't bind to dhcpv6 interface: %s\n", ifinfo->name);
    }
    if (use_v4) {
        auto d4l = std::make_unique<D4Listener>();
        if (d4l->init(ifinfo->name)) {
            v4_listeners.emplace_back(std::move(d4l));
        } else log_line("Can't bind to dhcpv4 interface: %s\n", ifinfo->name);
    }
}

static void init_listeners()
{
    nl_socket.init();
    bound_interfaces_foreach(get_interface_addresses, nullptr);
    bound_interfaces_foreach(create_interface_listener, nullptr);

    struct pollfd pt;
    pt.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pt.revents = 0;

    poll_size = 1 + v4_listeners.size() + v6_listeners.size() + r6_listeners.size();
    poll_array = static_cast<struct pollfd *>(malloc(poll_size * sizeof *poll_array));
    poll_meta = static_cast<struct pfd_meta *>(malloc(poll_size * sizeof *poll_meta));
    if (!poll_array || !poll_meta) abort();

    pt.fd = nl_socket.fd();
    poll_array[0] = pt;
    poll_meta[0] = (struct pfd_meta){ .pfdt = pfd_type::netlink, .data = &nl_socket };

    size_t pfdc = 1;
    for (auto &i: v4_listeners) {
        pt.fd = i->fd();
        poll_array[pfdc] = pt;
        poll_meta[pfdc++] = (struct pfd_meta){ .pfdt = pfd_type::dhcp4, .data = i.get() };
    }
    for (auto &i: v6_listeners) {
        pt.fd = i->fd();
        poll_array[pfdc] = pt;
        poll_meta[pfdc++] = (struct pfd_meta){ .pfdt = pfd_type::dhcp6, .data = i.get() };
    }
    for (auto &i: r6_listeners) {
        pt.fd = i->fd();
        poll_array[pfdc] = pt;
        poll_meta[pfdc++] = (struct pfd_meta){ .pfdt = pfd_type::radv6, .data = i.get() };
    }
}

int64_t get_current_ts()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        suicide("clock_gettime failed\n");
    return ts.tv_sec;
}

void set_user_runas(const char *username, size_t len)
{
    char buf[256];
    if (len >= sizeof buf)
        suicide("user %.*s is too long: %zu\n", (int)len, username, len);
    memcpy(buf, username, len);
    buf[len] = 0;
    if (nk_uidgidbyname(buf, &ndhs_uid, &ndhs_gid))
        suicide("invalid user '%s' specified\n", buf);
}
void set_chroot_path(const char *path, size_t len)
{
    chroot_path = strndup(path, len);
}
void set_s6_notify_fd(int fd)
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
            case 'c': configfile = strdup(optarg); break;
            case 'v': print_version(); exit(EXIT_SUCCESS); break;
            case 'h': usage(); exit(EXIT_SUCCESS); break;
            default: break;
        }
    }

    if (!parse_config(configfile))
        suicide("Failed to load configuration file.\n");

    if (!bound_interfaces_count())
        suicide("No interfaces have been bound\n");
    if (!ndhs_uid || !ndhs_gid)
        suicide("No non-root user account is specified.\n");
    if (!chroot_path)
        suicide("No chroot path is specified.\n");

    init_listeners();

    umask(077);
    setup_signals_ndhs();

    nk_set_chroot(chroot_path);
    duid_load_from_file();
    dynlease_deserialize(LEASEFILE_PATH);
    nk_set_uidgid(ndhs_uid, ndhs_gid, nullptr, 0);

    if (s6_notify_fd >= 0) {
        char buf[] = "\n";
        safe_write(s6_notify_fd, buf, 1);
        close(s6_notify_fd);
    }
}

int main(int ac, char *av[])
{
    process_options(ac, av);

    for (;;) {
        int timeout = INT_MAX;
        for (auto &i: r6_listeners) {
            auto t = i->send_periodic_advert();
            timeout = timeout < t ? timeout : t;
        }
        dynlease_gc();
        if (poll(poll_array, poll_size, timeout > 0 ? timeout : 0) < 0) {
            if (errno != EINTR) suicide("poll failed\n");
        }
        if (l_signal_exit) break;
        for (size_t i = 0, iend = poll_size; i < iend; ++i) {
            switch (poll_meta[i].pfdt) {
            case pfd_type::netlink: {
                if (poll_array[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("nlfd closed unexpectedly\n");
                }
                if (poll_array[i].revents & POLLIN) {
                    nl_socket.process_input();
                }
            } break;
            case pfd_type::dhcp6: {
                auto d6 = static_cast<D6Listener *>(poll_meta[i].data);
                if (poll_array[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: dhcp6 socket closed unexpectedly\n", d6->ifname());
                }
                if (poll_array[i].revents & POLLIN) {
                    d6->process_input();
                }
            } break;
            case pfd_type::dhcp4: {
                auto d4 = static_cast<D4Listener *>(poll_meta[i].data);
                if (poll_array[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: dhcp4 socket closed unexpectedly\n", d4->ifname());
                }
                if (poll_array[i].revents & POLLIN) {
                    d4->process_input();
                }
            } break;
            case pfd_type::radv6: {
                auto r6 = static_cast<RA6Listener *>(poll_meta[i].data);
                if (poll_array[i].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                    suicide("%s: ra6 socket closed unexpectedly\n", r6->ifname());
                }
                if (poll_array[i].revents & POLLIN) {
                    r6->process_input();
                }
            } break;
            }
        }
    }

    dynlease_serialize(LEASEFILE_PATH);

    exit(EXIT_SUCCESS);
}

