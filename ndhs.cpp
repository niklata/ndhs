/* ndhs.c - dhcp server
 *
 * (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include <getopt.h>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include "dhcpclient.hpp"
#include "dhcplua.hpp"
#include "leasestore.hpp"

extern "C" {
#include "defines.h"
#include "malloc.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "strl.h"
#include "exec.h"
#include "network.h"
#include "strlist.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
bool gParanoid = false;
bool gChrooted = false;

LeaseStore *gLeaseStore;
DhcpLua *gLua;

static void sighandler(int sig)
{
    exit(EXIT_SUCCESS);
}

static void fix_signals(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");

    struct sigaction sa;
    memset(&sa, 0, sizeof (struct sigaction));
    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int main(int ac, char *av[]) {
    int uid = 0, gid = 0;
    std::string pidfile, chroot_path, leasefile_path, configfile_path;
    std::vector<ClientListener *> listeners;
    std::vector<std::string> iflist;

    gflags_log_name = const_cast<char *>("ndhs");

    po::options_description desc("Options");
    desc.add_options()
        ("paranoid,p",
         "return UNKNOWN-ERROR for all errors except INVALID-PORT (prevents inference of used ports)")
        ("detach,d", "run as a background daemon (default)")
        ("nodetach,n", "stay attached to TTY")
        ("quiet,q", "don't print to std(out|err) or log")
        ("config,c", po::value<std::string>(),
         "path to configuration file")
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
        ("group,g", po::value<std::string>(),
         "group name that ndhs should run as")
        ("help,h", "print help message")
        ("version,v", "print version information")
        ;
    po::positional_options_description p;
    p.add("address", -1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(ac, av).
                  options(desc).positional(p).run(), vm);
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << "ndhs " << NDHS_VERSION << ", dhcp server.\n"
                  << "Copyright (c) 2011 Nicholas J. Kain\n"
                  << av[0] << " [options] addresses...\n"
                  << desc << std::endl;
        return 1;
    }
    if (vm.count("version")) {
        std::cout << "ndhs " << NDHS_VERSION << ", dhcp server.\n" <<
            "Copyright (c) 2011 Nicholas J. Kain\n"
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
            "POSSIBILITY OF SUCH DAMAGE.\n";
        return 1;
    }
    if (vm.count("paranoid"))
        gParanoid = true;
    if (vm.count("detach"))
        gflags_detach = 1;
    if (vm.count("nodetach"))
        gflags_detach = 0;
    if (vm.count("quiet"))
        gflags_quiet = 1;
    if (vm.count("config"))
        configfile_path = vm["config"].as<std::string>();
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
        try {
            uid = boost::lexical_cast<unsigned int>(t);
        } catch (boost::bad_lexical_cast &) {
            auto pws = getpwnam(t.c_str());
            if (pws) {
                uid = (int)pws->pw_uid;
                if (!gid)
                    gid = (int)pws->pw_gid;
            } else suicide("invalid uid specified");
        }
    }
    if (vm.count("group")) {
        auto t = vm["group"].as<std::string>();
        try {
            gid = boost::lexical_cast<unsigned int>(t);
        } catch (boost::bad_lexical_cast &) {
            auto grp = getgrnam(t.c_str());
            if (grp) {
                gid = (int)grp->gr_gid;
            } else suicide("invalid gid specified");
        }
    }

    if (gflags_detach)
        if (daemon(0,0))
            suicide("detaching fork failed");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    fix_signals();
    ncm_fix_env(uid, 0);

    gLua = new DhcpLua(configfile_path);

    if (!iflist.size()) {
        suicide("at least one listening interface must be specified");
    } else
        for (auto i = iflist.cbegin(); i != iflist.cend(); ++i) {
            std::string iface = *i;
            try {
                auto addy = boost::asio::ip::address_v4::any();
                auto ep = boost::asio::ip::udp::endpoint(addy, 67);
                auto cl = new ClientListener(io_service, ep, iface);
                listeners.push_back(cl);
            } catch (boost::system::error_code &ec) {
                std::cout << "bad interface: " << iface << std::endl;
            }
        }
    iflist.clear();

    if (chroot_path.size()) {
        if (getuid())
            suicide("root required for chroot\n");
        if (chdir(chroot_path.c_str()))
            suicide("failed to chdir(%s)\n", chroot_path.c_str());
        if (chroot(chroot_path.c_str()))
            suicide("failed to chroot(%s)\n", chroot_path.c_str());
        gChrooted = true;
        chroot_path.clear();
    }
    if (uid != 0 || gid != 0)
        drop_root(uid, gid);

    /* Cover our tracks... */
    pidfile.clear();

    init_client_states(io_service);
    gLeaseStore = new LeaseStore(leasefile_path);
    io_service.run();

    exit(EXIT_SUCCESS);
}

