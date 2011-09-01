/* dhcpclient.cpp - dhcp client request handling
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

#include <sstream>
#include <iostream>
#include <unordered_map>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <net/if.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

#include "dhcpclient.hpp"
#include "leasestore.hpp"
#include "dhcplua.hpp"

extern "C" {
#include "log.h"
#include "options.h"
}

#define DHCP_MAGIC              0x63825363

namespace ba = boost::asio;

extern bool gParanoid;
extern bool gChrooted;
extern LeaseStore *gLeaseStore;
extern DhcpLua *gLua;

// XXX: still need to implement the timers

// There are two hashtables, a 'new' and a 'marked for death' table.  If these
// tables are not empty, a timer with period t will wake up and delete all
// entries on the 'm4d' table and move the 'new' table to replace the 'm4d'
// table.  If an entry on the 'm4d' table is accessed, it will be moved to the
// 'new' table.  New entries will be added to the 'new' table.  If both tables
// are emptied, the timer can stop until a new entry is added.
//
// This scheme requires no timestamping and will bound the lifetime of any
// object to be p < lifetime < 2p.  A further refinement would be to scale
// p to be inversely proportional to the number of entries on the 'new'
// and 'm4d' tables.  This change would cause the deletion rate to increase
// smoothly under heavy load, providing resistance to OOM DoS at the cost of
// making it so that clients will need to complete their transactions quickly.
class ClientStates {
public:
    ClientStates() {
        currentMap_ = 0;
        swapInterval_ = 60; // 1m
        nextSwapTs_ = 0; // never
    }
    ~ClientStates() {
        for (auto elt = map_[0].begin(); elt != map_[0].end(); ++elt)
            delete elt->second;
        for (auto elt = map_[1].begin(); elt != map_[1].end(); ++elt)
            delete elt->second;
    }
    void doSwap(void) {
        int killMap = !currentMap_;
        for (auto elt = map_[killMap].begin(); elt != map_[killMap].end();
             ++elt)
            delete elt->second;
        map_[killMap].clear();
        currentMap_ = killMap;
        nextSwapTs_ = getNowTs() + swapInterval_;
    }
    bool stateExists(uint32_t xid, const std::string &chaddr) const {
        std::string key(generateKey(xid, chaddr));
        return (map_[0].find(key) != map_[0].end()) ||
               (map_[1].find(key) != map_[1].end());
    }
    void stateAdd(uint32_t xid, const std::string &chaddr, ClientState *state)
    {
        std::string key(generateKey(xid, chaddr));
        if (!state)
            return;
        stateKill(xid, chaddr);
        map_[currentMap_][key] = state;
    }
    struct ClientState *stateGet(uint32_t xid, const std::string &chaddr) {
        std::string key(generateKey(xid, chaddr));
        auto r = map_[currentMap_].find(key);
        if (r != map_[currentMap_].end())
            return r->second;
        r = map_[!currentMap_].find(key);
        if (r != map_[!currentMap_].end()) {
            map_[!currentMap_].erase(r);
            map_[currentMap_][key] = r->second;
            return r->second;
        }
        return NULL;
    }
    void stateKill(uint32_t xid, const std::string &chaddr) {
        std::string key(generateKey(xid, chaddr));
        auto elt = map_[currentMap_].find(key);
        if (elt != map_[currentMap_].end()) {
            delete elt->second;
            map_[currentMap_].erase(elt);
            return;
        }
        elt = map_[!currentMap_].find(key);
        if (elt != map_[!currentMap_].end()) {
            delete elt->second;
            map_[!currentMap_].erase(elt);
        }
    }
private:
    std::string generateKey(uint32_t xid, const std::string &chaddr) const {
        std::string r;
        union {
            uint8_t c[4];
            uint32_t n;
        } xia;
        xia.n = xid;
        r.push_back(xia.c[0]);
        r.push_back(xia.c[1]);
        r.push_back(xia.c[2]);
        r.push_back(xia.c[3]);
        r.append(chaddr);
        return r;
    }
    uint64_t getNowTs(void) const {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec;
    }
    // Key is concatenation of xid|chaddr.  Neither of these need to be stored
    // in explicit fields in the state structure.
    int currentMap_; // Either 0 or 1.
    int swapInterval_;
    std::unordered_map<std::string, ClientState *> map_[2];
    uint64_t nextSwapTs_;
};

ClientStates client_states;

ClientListener::ClientListener(ba::io_service &io_service,
                               const ba::ip::udp::endpoint &endpoint,
                               const std::string &ifname)
 : socket_(io_service, endpoint)
{
    socket_.set_option(ba::ip::udp::socket::broadcast(true));
    socket_.set_option(ba::ip::udp::socket::do_not_route(true));
    socket_.set_option(ba::ip::udp::socket::reuse_address(true));
    int fd = socket_.native();

    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_error("failed to bind socket to device: %s", strerror(errno));
        exit(-1);
    }

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        log_error("failed to get list of interface ips: %s", strerror(errno));
        exit(-1);
    }
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (strcmp(ifa->ifa_name, ifname.c_str()))
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        char lipbuf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                       lipbuf, sizeof lipbuf)) {
            log_error("failed to parse IP for interface (%s): %s",
                       ifname.c_str(), strerror(errno));
            exit(-1);
        }
        local_ip_ = ba::ip::address::from_string(lipbuf);
        break;
    }
    freeifaddrs(ifaddr);
    if (!local_ip_.is_v4()) {
        log_error("interface (%s) has no IP address", ifname.c_str());
        exit(-1);
    }

    socket_.async_receive_from(ba::buffer(recv_buffer_), remote_endpoint_,
                               boost::bind(&ClientListener::start_receive,
                                           this, ba::placeholders::error,
                                           ba::placeholders::bytes_transferred));
}

void ClientListener::start_receive(const boost::system::error_code &error,
                                   std::size_t bytes_xferred)
{
    std::cout << "start_receive triggered" << std::endl;
    handle_receive(error, bytes_xferred);
    socket_.async_receive_from(ba::buffer(recv_buffer_), remote_endpoint_,
                               boost::bind(&ClientListener::start_receive,
                                           this, ba::placeholders::error,
                                           ba::placeholders::bytes_transferred));
}

void ClientListener::dhcpmsg_init(struct dhcpmsg *dm, char type) const
{
    memset(dm, 0, sizeof (struct dhcpmsg));
    dm->op = 2; // BOOTREPLY (server)
    dm->htype = 1;
    dm->hlen = 6;
    dm->xid = dhcpmsg_.xid;
    dm->cookie = htonl(DHCP_MAGIC);
    dm->options[0] = DCODE_END;
    add_option_msgtype(dm, type);
    add_option_serverid(dm, local_ip());
}

uint32_t ClientListener::local_ip() const
{
    uint32_t ret;
    if (inet_pton(AF_INET, local_ip_.to_string().c_str(), &ret) != 1) {
        log_warning("inet_pton failed: %s", strerror(errno));
        return 0;
    }
    return ret;
}

void ClientListener::send_reply(struct dhcpmsg *dm)
{
    ssize_t endloc = get_end_option_idx(dm);
    if (endloc < 0)
        return;
    std::string msgbuf((const char *)dm, sizeof (struct dhcpmsg) -
                       (sizeof (dm->options) - 1 - endloc));
    boost::system::error_code ignored_error;
    std::cout << "remote_endpoint is " << remote_endpoint_ << std::endl;
    #if 0
    socket_.send_to(boost::asio::buffer(msgbuf), remote_endpoint_,
                    0, ignored_error);
    #endif
    socket_.send_to(boost::asio::buffer(msgbuf),
     ba::ip::udp::endpoint(remote_endpoint_.address().to_v4().broadcast(), 68),
     0, ignored_error);
}

std::string ClientListener::ipStr(uint32_t ip) const
{
    char addrbuf[INET_ADDRSTRLEN];
    auto r = inet_ntop(AF_INET, &ip, addrbuf, sizeof addrbuf);
    if (!r)
        return std::string("");
    return std::string(addrbuf);
}

uint64_t ClientListener::getNowTs(void) const {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

void ClientListener::reply_discover(ClientState *cs, const std::string &chaddr)
{
    struct dhcpmsg reply;

    dhcpmsg_init(&reply, DHCPOFFER);
    gLua->reply_discover(&reply, local_ip_.to_string(),
                         remote_endpoint_.address().to_string(), chaddr);
    send_reply(&reply);
    std::cout << "Leaving CL::reply_discover()" << std::endl;
}

void ClientListener::reply_request(ClientState *cs, const std::string &chaddr,
                                   bool is_direct)
{
    struct dhcpmsg reply;
    std::string leaseip;
    
    dhcpmsg_init(&reply, DHCPACK);
    gLua->reply_request(&reply, local_ip_.to_string(),
                        remote_endpoint_.address().to_string(), chaddr);

    leaseip = ipStr(reply.yiaddr);
    if (!leaseip.size())
        goto out;
    gLeaseStore->addLease(local_ip_.to_string(), chaddr, leaseip,
                          getNowTs() + get_option_leasetime(&reply));
    send_reply(&reply);
out:
    client_states.stateKill(dhcpmsg_.xid, chaddr);
}

void ClientListener::reply_inform(ClientState *cs, const std::string &chaddr)
{
    // XXX: send a DHCPACK that just non-LEASET options.
}

void ClientListener::do_release(ClientState *cs, const std::string &chaddr) {
    std::string lip =
        gLeaseStore->getLease(socket_.local_endpoint().address().to_string(),
                              chaddr);
    if (lip != remote_endpoint_.address().to_string()) {
        log_line("do_release: ignoring spoofed release request.  %s != %s.", remote_endpoint_.address().to_string().c_str(), lip.c_str());
        return;
    }
    gLeaseStore->delLease(socket_.local_endpoint().address().to_string(),
                          chaddr);
}

std::string ClientListener::getChaddr(const struct dhcpmsg &dm) const
{
    std::string r;
    r.push_back(dm.chaddr[0]);
    r.push_back(dm.chaddr[1]);
    r.push_back(dm.chaddr[2]);
    r.push_back(dm.chaddr[3]);
    r.push_back(dm.chaddr[4]);
    r.push_back(dm.chaddr[5]);
    return r;
}

bool ClientListener::validate_dhcp(void) const
{
    // XXX: validate the packet
    return true;
}

void ClientListener::handle_receive(const boost::system::error_code &error,
                                    std::size_t bytes_xferred)
{
    bool direct_request = false;
    std::cout << "handle_receive triggered" << std::endl;
    memset(&dhcpmsg_, 0, sizeof dhcpmsg_);
    memcpy(&dhcpmsg_, recv_buffer_.c_array(),
           bytes_xferred <= sizeof dhcpmsg_ ? bytes_xferred : sizeof dhcpmsg_);
    if (!validate_dhcp())
        return;

    uint8_t msgtype = get_option_msgtype(&dhcpmsg_);
    std::string chaddr = getChaddr(dhcpmsg_);
    
    auto cs = client_states.stateGet(dhcpmsg_.xid, chaddr);
    if (!cs) {
        switch (msgtype) {
        case DHCPREQUEST:
            direct_request = true;
        case DHCPDISCOVER:
            cs = new ClientState;
            cs->state = msgtype;
            client_states.stateAdd(dhcpmsg_.xid, chaddr, cs);
            break;
        case DHCPINFORM:
        case DHCPRELEASE:
            // XXX: nyi
            return;
        }
    } else {
        if (cs->state == DHCPDISCOVER && msgtype == DHCPREQUEST)
            cs->state = DHCPREQUEST;
    }

    switch (cs->state) {
    case DHCPDISCOVER: reply_discover(cs, chaddr); break;
    case DHCPREQUEST:  reply_request(cs, chaddr, direct_request); break;
    case DHCPINFORM:   reply_inform(cs, chaddr); break;
    case DHCPRELEASE:  do_release(cs, chaddr); break;
    }
}

