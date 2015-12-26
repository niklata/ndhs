/* ndhs.c - dhcp server
 *
 * (c) 2011-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include <fstream>

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
#include <getopt.h>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <format.hpp>

#include "dhcpclient.hpp"
#include "dhcplua.hpp"
#include "leasestore.hpp"

extern "C" {
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/exec.h"
#include "nk/seccomp-bpf.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
static boost::asio::signal_set asio_signal_set(io_service);
static std::vector<std::unique_ptr<ClientListener>> listeners;
static uid_t ndhs_uid;
static gid_t ndhs_gid;
extern int gflags_detach;
extern int gflags_quiet;

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

static int enforce_seccomp(void)
{
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
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    fmt::print("seccomp filter installed.  Please disable seccomp if you encounter problems.\n");
    return 0;
}

static po::variables_map fetch_options(int ac, char *av[])
{
    std::string config_file;

    po::options_description cli_opts("Command-line-exclusive options");
    cli_opts.add_options()
        ("config,c", po::value<std::string>(&config_file),
         "path to configuration file")
        ("background", "run as a background daemon")
        ("quiet,q", "don't print to std(out|err) or log")
        ("help,h", "print help message")
        ("version,v", "print version information")
        ;

    po::options_description gopts("Options");
    gopts.add_options()
        ("script,s", po::value<std::string>(),
         "path to response script file")
        ("leasefile,l", po::value<std::string>(),
         "path to lease database file")
        ("pidfile,f", po::value<std::string>(),
         "path to process id file")
        ("chroot,C", po::value<std::string>(),
         "path in which ndhs should chroot itself")
        ("interface,i", po::value<std::vector<std::string> >(),
         "'interface' on which to listen (must specify at least one)")
        ("user,u", po::value<std::string>(),
         "user name that ndhs should run as")
        ("seccomp-enforce,S", "enforce seccomp syscall restrictions")
        ;

    po::options_description cmdline_options;
    cmdline_options.add(cli_opts).add(gopts);
    po::options_description cfgfile_options;
    cfgfile_options.add(gopts);

    po::positional_options_description p;
    p.add("interface", -1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(ac, av).
                  options(cmdline_options).positional(p).run(), vm);
    } catch (const std::exception& e) {
        fmt::print(stderr, "{}\n", e.what());
    }
    po::notify(vm);

    if (config_file.size()) {
        std::ifstream ifs(config_file.c_str());
        if (!ifs) {
            fmt::print(stderr, "Could not open config file: {}\n", config_file);
            std::exit(EXIT_FAILURE);
        }
        po::store(po::parse_config_file(ifs, cfgfile_options), vm);
        po::notify(vm);
    }

    if (vm.count("help")) {
        fmt::print("ndhs " NDHS_VERSION ", dhcp server.\n"
                  "Copyright (c) 2011-2014 Nicholas J. Kain\n"
                  "{} [options] interfaces...\n{}\n", av[0], gopts);
        std::exit(EXIT_FAILURE);
    }
    if (vm.count("version")) {
        fmt::print("ndhs " NDHS_VERSION ", dhcp server.\n"
            "Copyright (c) 2011-2014 Nicholas J. Kain\n"
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
        std::exit(EXIT_FAILURE);
    }
    return vm;
}

static void process_options(int ac, char *av[])
{
    std::vector<std::string> iflist;
    std::string pidfile, chroot_path, leasefile_path, scriptfile_path;
    bool use_seccomp(false);

    auto vm(fetch_options(ac, av));

    if (vm.count("background"))
        gflags_detach = 1;
    if (vm.count("quiet"))
        gflags_quiet = 1;
    if (vm.count("script"))
        scriptfile_path = vm["script"].as<std::string>();
    if (vm.count("leasefile"))
        leasefile_path = vm["leasefile"].as<std::string>();
    if (vm.count("pidfile"))
        pidfile = vm["pidfile"].as<std::string>();
    if (vm.count("chroot"))
        chroot_path = vm["chroot"].as<std::string>();
    if (vm.count("interface"))
        iflist = vm["interface"].as<std::vector<std::string> >();
    if (vm.count("user")) {
        auto t = vm["user"].as<std::string>();
        if (nk_uidgidbyname(t.c_str(), &ndhs_uid, &ndhs_gid)) {
            fmt::print(stderr, "invalid user '{}' specified\n", t);
            std::exit(EXIT_FAILURE);
        }
    }
    if (vm.count("seccomp-enforce"))
        use_seccomp = true;

    if (!iflist.size()) {
        fmt::print(stderr, "at least one listening interface must be specified\n");
        std::exit(EXIT_FAILURE);
    } else
        for (const auto &i: iflist) {
            try {
                auto addy = boost::asio::ip::address_v4::any();
                auto ep = boost::asio::ip::udp::endpoint(addy, 67);
                listeners.emplace_back(std::make_unique<ClientListener>
                                       (io_service, ep, i));
            } catch (boost::system::error_code &ec) {
                fmt::print("bad interface: {}\n", i);
            }
        }

    if (gflags_detach) {
        if (daemon(0,0)) {
            fmt::print(stderr, "detaching fork failed\n");
            std::exit(EXIT_FAILURE);
        }
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

    if (use_seccomp) {
        if (enforce_seccomp())
            fmt::print(stderr, "seccomp filter cannot be installed\n");
    }
}

int main(int ac, char *av[])
{
    process_options(ac, av);

    io_service.run();

    std::exit(EXIT_SUCCESS);
}

