/* ndhs.c - dhcp server
 *
 * (c) 2011-2016 Nicholas J. Kain <njkain at gmail dot com>
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

#define NDHS_VERSION "1.0"

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
#include <boost/asio.hpp>
#include <format.hpp>
#include <nk/optionarg.hpp>
extern "C" {
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/exec.h"
#include "nk/seccomp-bpf.h"
}
#include "dhcpclient.hpp"
#include "dhcplua.hpp"
#include "leasestore.hpp"

boost::asio::io_service io_service;
static boost::asio::signal_set asio_signal_set(io_service);
static std::vector<std::unique_ptr<ClientListener>> listeners;
static uid_t ndhs_uid;
static gid_t ndhs_gid;
extern int gflags_detach;
extern int gflags_quiet;
static bool use_seccomp(false);

std::unique_ptr<LeaseStore> gLeaseStore;
std::unique_ptr<DhcpLua> gLua;

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
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        fmt::print(stderr, "sigprocmask failed\n");
        std::quick_exit(EXIT_FAILURE);
    }
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait(
        [](const boost::system::error_code &, int signum) {
            io_service.stop();
        });
}

static int enforce_seccomp(bool changed_uidgid)
{
    if (!use_seccomp)
        return 0;
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,

#if defined(__x86_64__) || (defined(__arm__) && defined(__ARM_EABI__))
        ALLOW_SYSCALL(sendmsg),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(getpeername),
        ALLOW_SYSCALL(setsockopt),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(recvfrom),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(shutdown),
#elif defined(__i386__)
        ALLOW_SYSCALL(socketcall),
        ALLOW_SYSCALL(fcntl64),
#else
#error Target platform does not support seccomp-filter.
#endif

        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(timerfd_settime),
        ALLOW_SYSCALL(access),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(umask),
        ALLOW_SYSCALL(geteuid),
        ALLOW_SYSCALL(fsync),
        ALLOW_SYSCALL(unlink),
        ALLOW_SYSCALL(rt_sigreturn),
        ALLOW_SYSCALL(rt_sigaction),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
#ifdef __NR_sigaction
        ALLOW_SYSCALL(sigaction),
#endif
        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        // operator new
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(mremap),

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog;
    memset(&prog, 0, sizeof prog);
    prog.len = (unsigned short)(sizeof filter / sizeof filter[0]);
    prog.filter = filter;
    if (!changed_uidgid && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    fmt::print("seccomp filter installed.  Please disable seccomp if you encounter problems.\n");
    std::fflush(stdout);
    return 0;
}

static void print_version(void)
{
    fmt::print("ndhs " NDHS_VERSION ", dhcp server.\n"
               "Copyright (c) 2011-2016 Nicholas J. Kain\n"
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
    OPT_UNKNOWN, OPT_HELP, OPT_VERSION, OPT_BACKGROUND, OPT_PIDFILE,
    OPT_CHROOT, OPT_USER, OPT_SCRIPTFILE, OPT_LEASEFILE, OPT_SECCOMP,
    OPT_QUIET
};
static const option::Descriptor usage[] = {
    { OPT_UNKNOWN,    0,  "",           "", Arg::Unknown,
        "ndhs " NDHS_VERSION ", dhcp server.\n"
        "Copyright (c) 2011-2016 Nicholas J. Kain\n"
        "ndhs [options] interface...\n\nOptions:" },
    { OPT_HELP,       0, "h",            "help",    Arg::None, "\t-h, \t--help  \tPrint usage and exit." },
    { OPT_VERSION,    0, "v",         "version",    Arg::None, "\t-v, \t--version  \tPrint version and exit." },
    { OPT_BACKGROUND, 0, "b",      "background",    Arg::None, "\t-b, \t--background  \tRun as a background daemon." },
    { OPT_PIDFILE,    0, "f",         "pidfile",  Arg::String, "\t-f, \t--pidfile  \tPath to process id file." },
    { OPT_CHROOT,     0, "C",          "chroot",  Arg::String, "\t-C, \t--chroot  \tPath in which nident should chroot itself." },
    { OPT_USER,       0, "u",            "user",  Arg::String, "\t-u, \t--user  \tUser name that nrad6 should run as." },
    { OPT_SCRIPTFILE, 0, "s",          "script",  Arg::String, "\t-s, \t--script  \tPath to response script file." },
    { OPT_LEASEFILE,  0, "l",       "leasefile",  Arg::String, "\t-l, \t--leasefile  \tPath to lease database file." },
    { OPT_SECCOMP,    0, "S", "seccomp-enforce",    Arg::None, "\t-S  \t--seccomp-enforce  \tEnforce seccomp syscall restrictions." },
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
        int col = getenv("COLUMNS") ? atoi(getenv("COLUMNS")) : 80;
        option::printUsage(fwrite, stdout, usage, col);
        std::exit(EXIT_FAILURE);
    }
    if (options[OPT_VERSION]) {
        print_version();
        std::exit(EXIT_FAILURE);
    }

    std::vector<std::string> iflist;
    std::string pidfile, chroot_path, leasefile_path, scriptfile_path;

    for (int i = 0; i < parse.optionsCount(); ++i) {
        option::Option &opt = buffer[i];
        switch (opt.index()) {
            case OPT_BACKGROUND: gflags_detach = 1; break;
            case OPT_PIDFILE: pidfile = std::string(opt.arg); break;
            case OPT_CHROOT: chroot_path = std::string(opt.arg); break;
            case OPT_USER: {
                if (nk_uidgidbyname(opt.arg, &ndhs_uid, &ndhs_gid)) {
                    fmt::print(stderr, "invalid user '{}' specified\n", opt.arg);
                    std::exit(EXIT_FAILURE);
                }
                break;
            }
            case OPT_SCRIPTFILE: scriptfile_path = std::string(opt.arg); break;
            case OPT_LEASEFILE: leasefile_path = std::string(opt.arg); break;
            case OPT_SECCOMP: use_seccomp = true; break;
            case OPT_QUIET: gflags_quiet = 1; break;
        }
    }
    for (int i = 0; i < parse.nonOptionsCount(); ++i) {
        iflist.emplace_back(parse.nonOption(i));
    }

    for (const auto &i: iflist) {
        try {
            auto addy = boost::asio::ip::address_v4::any();
            auto ep = boost::asio::ip::udp::endpoint(addy, 67);
            listeners.emplace_back(std::make_unique<ClientListener>
                                   (io_service, ep, i));
        } catch (boost::system::error_code &ec) {
            fmt::print(stderr, "bad interface: {}\n", i);
        }
    }
    if (!iflist.size()) {
        fmt::print(stderr, "At least one listening interface must be specified\n");
        std::exit(EXIT_FAILURE);
    }
    if (gflags_detach && daemon(0,0)) {
        fmt::print(stderr, "detaching fork failed\n");
        std::exit(EXIT_FAILURE);
    }
    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    process_signals();
    nk_fix_env(ndhs_uid, 0);

    gLua = std::make_unique<DhcpLua>(scriptfile_path);

    if (chroot_path.size())
        nk_set_chroot(chroot_path.c_str());
    if (ndhs_uid != 0 || ndhs_gid != 0)
        nk_set_uidgid(ndhs_uid, ndhs_gid, NULL, 0);

    init_client_states_v4(io_service);
    gLeaseStore = std::make_unique<LeaseStore>(leasefile_path);

    if (enforce_seccomp(ndhs_uid || ndhs_gid)) {
        fmt::print(stderr, "seccomp filter cannot be installed\n");
        std::exit(EXIT_FAILURE);
    }
}

int main(int ac, char *av[])
{
    process_options(ac, av);

    io_service.run();

    std::exit(EXIT_SUCCESS);
}

