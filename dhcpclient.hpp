/* dhcpclient.hpp - dhcp client request handling
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

#ifndef NK_DHCPCLIENT_H
#define NK_DHCPCLIENT_H

#include <string>
#include <unordered_map>
#include <netdb.h>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "dhcp.h"

// There are two hashtables, a 'new' and a 'marked for death' table.  If these
// tables are not empty, a timer with period t will wake up and delete all
// entries on the 'm4d' table and move the 'new' table to replace the 'm4d'
// table.  If an entry on the 'm4d' table is accessed, it will be moved to the
// 'new' table.  New entries will be added to the 'new' table.  If both tables
// are emptied, the timer can stop until a new entry is added.  We optimize
// the scheme by not actually performing moves: instead, we store an index
// to the 'new' table, and the 'marked for death' table is the unindexed table.
//
// This scheme requires no timestamping and will bound the lifetime of any
// object to be p < lifetime < 2p.  A further refinement would be to scale
// p to be inversely proportional to the number of entries on the 'new'
// and 'm4d' tables.  This change would cause the deletion rate to increase
// smoothly under heavy load, providing resistance to OOM DoS at the cost of
// making it so that clients will need to complete their transactions quickly.
class ClientStates {
public:
    ClientStates(boost::asio::io_service &io_service)
            : swapTimer_(io_service)
        {
        currentMap_ = 0;
        swapInterval_ = 60; // 1m
    }
    ~ClientStates() {}
    bool stateExists(uint32_t xid, const std::string &chaddr) const {
        std::string key(generateKey(xid, chaddr));
        return (map_[0].find(key) != map_[0].end()) ||
               (map_[1].find(key) != map_[1].end());
    }
    void stateAdd(uint32_t xid, const std::string &chaddr, uint8_t state)
    {
        std::string key(generateKey(xid, chaddr));
        if (!state)
            return;
        stateKill(xid, chaddr);
        map_[currentMap_][key] = state;
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer();
    }
    uint8_t stateGet(uint32_t xid, const std::string &chaddr) {
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
        return DHCPNULL;
    }
    void stateKill(uint32_t xid, const std::string &chaddr) {
        std::string key(generateKey(xid, chaddr));
        auto elt = map_[currentMap_].find(key);
        if (elt != map_[currentMap_].end()) {
            map_[currentMap_].erase(elt);
            return;
        }
        elt = map_[!currentMap_].find(key);
        if (elt != map_[!currentMap_].end())
            map_[!currentMap_].erase(elt);
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
    void doSwap(void) {
        int killMap = !currentMap_;
        map_[killMap].clear();
        currentMap_ = killMap;
    }
    void setTimer(void) {
        swapTimer_.expires_from_now(boost::posix_time::seconds(swapInterval_));
        swapTimer_.async_wait
            ([this](const boost::system::error_code& error)
            {
                doSwap();
                if (map_[0].size() || map_[1].size())
                    setTimer();

            });
    }
    // Key is concatenation of xid|chaddr.  Neither of these need to be stored
    // in explicit fields in the state structure.
    int currentMap_; // Either 0 or 1.
    int swapInterval_;
    boost::asio::deadline_timer swapTimer_;
    std::unordered_map<std::string, uint8_t> map_[2];
};

void init_client_states_v4(boost::asio::io_service &io_service);

class ClientListener
{
public:
    ClientListener(boost::asio::io_service &io_service,
                   const boost::asio::ip::udp::endpoint &endpoint,
                   const std::string &ifname);
private:
    void start_receive();
    uint64_t getNowTs(void) const;
    void dhcpmsg_init(struct dhcpmsg *dm, char type,
                      uint32_t xid, const std::string &chaddr) const;
    uint32_t local_ip() const;
    std::string ipStr(uint32_t ip) const;
    void send_reply(struct dhcpmsg *dm, bool broadcast);
    void reply_discover(const std::string &chaddr);
    void reply_request(const std::string &chaddr, bool is_direct);
    void reply_inform(const std::string &chaddr);
    void do_release(const std::string &chaddr);
    std::string getChaddr(const struct dhcpmsg &dm) const;
    bool validate_dhcp(void) const;
    void handle_receive(const boost::system::error_code &error,
                        std::size_t bytes_xferred);

    boost::asio::ip::udp::socket socket_;
    //boost::asio::ip::udp::socket broadcast_socket_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    boost::array<uint8_t, 1024> recv_buffer_;
    struct dhcpmsg dhcpmsg_;
    boost::asio::ip::address local_ip_;
};

#endif /* NK_DHCPCLIENT_H */
