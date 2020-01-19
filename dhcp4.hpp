/* dhcp4.hpp - dhcpv4 client request handling
 *
 * Copyright 2011-2017 Nicholas J. Kain <njkain at gmail dot com>
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
#include <memory>
#include <unordered_map>
#include <netdb.h>
#include <asio.hpp>
#include <fmt/printf.h>
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
class ClientStates
{
public:
    ClientStates(asio::io_service &io_service)
            : swapTimer_(io_service)
        {
        currentMap_ = 0;
        swapInterval_ = 60; // 1m
    }
    ClientStates(const ClientStates &) = delete;
    ClientStates &operator=(const ClientStates &) = delete;
    ~ClientStates() {}
    bool stateExists(uint32_t xid, uint8_t *hwaddr) {
        key_ = generateKey(xid, hwaddr);
        return (map_[0].find(key_) != map_[0].end()) ||
               (map_[1].find(key_) != map_[1].end());
    }
    void stateAdd(uint32_t xid, uint8_t *hwaddr, uint8_t state)
    {
        key_ = generateKey(xid, hwaddr);
        if (!state)
            return;
        stateKill(xid, hwaddr);
        map_[currentMap_][key_] = state;
        if (swapTimer_.expiry() <= std::chrono::steady_clock::now())
            setTimer();
    }
    uint8_t stateGet(uint32_t xid, uint8_t *hwaddr) {
        key_ = generateKey(xid, hwaddr);
        auto r = map_[currentMap_].find(key_);
        if (r != map_[currentMap_].end())
            return r->second;
        r = map_[!currentMap_].find(key_);
        if (r != map_[!currentMap_].end()) {
            map_[!currentMap_].erase(r);
            map_[currentMap_][key_] = r->second;
            return r->second;
        }
        return DHCPNULL;
    }
    void stateKill(uint32_t xid, uint8_t *hwaddr) {
        key_ = generateKey(xid, hwaddr);
        auto elt = map_[currentMap_].find(key_);
        if (elt != map_[currentMap_].end()) {
            map_[currentMap_].erase(elt);
            return;
        }
        elt = map_[!currentMap_].find(key_);
        if (elt != map_[!currentMap_].end())
            map_[!currentMap_].erase(elt);
    }
private:
    const std::string generateKey(uint32_t xid, uint8_t *hwaddr) const {
        return fmt::sprintf("{}%02.x%02.x%02.x%02.x%02.x%02.x", xid,
                            hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3],
                            hwaddr[4], hwaddr[5]);
    }
    void doSwap(void) {
        int killMap = !currentMap_;
        map_[killMap].clear();
        currentMap_ = killMap;
    }
    void setTimer(void) {
        swapTimer_.expires_after(std::chrono::seconds(swapInterval_));
        swapTimer_.async_wait
            ([this](const std::error_code& error)
             {
                 if (error) {
                     fmt::print(stderr, "dhcp4: Error during swap timer: {}\n", error);
                     exit(EXIT_FAILURE);
                     return;
                 }
                 doSwap();
                 if (map_[0].size() || map_[1].size())
                     setTimer();
             });
    }
    // key_ is concatenation of xid|hwaddr.  Neither of these need to be
    // stored in explicit fields in the state structure.
    asio::steady_timer swapTimer_;
    std::unordered_map<std::string, uint8_t> map_[2];
    std::string key_; // Stored here to reduce number of allocations.
    int currentMap_; // Either 0 or 1.
    int swapInterval_;
};

class D4Listener
{
public:
    D4Listener(asio::io_service &io_service) : socket_(io_service) {}
    D4Listener(const D4Listener &) = delete;
    D4Listener &operator=(const D4Listener &) = delete;

    [[nodiscard]] bool init(const std::string &ifname);
private:
    void start_receive();
    void dhcpmsg_init(dhcpmsg &dm, char type, uint32_t xid) const;
    uint32_t local_ip() const;
    std::string ipStr(uint32_t ip) const;

    enum class SendReplyType { UnicastCi, Broadcast, Relay, UnicastYiCh };
    void send_reply_do(const dhcpmsg &dm, SendReplyType srt);
    void send_reply(const dhcpmsg &dm);
    bool iplist_option(dhcpmsg &reply, std::string &iplist, uint8_t code,
                       const std::vector<asio::ip::address_v4> &addrs);
    bool allot_dynamic_ip(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign);
    bool create_reply(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign);
    void reply_discover();
    void reply_request(bool is_direct);
    void reply_inform();
    void do_release();
    std::string getChaddr(const struct dhcpmsg &dm) const;
    uint8_t validate_dhcp(size_t len) const;

    asio::ip::udp::socket socket_;
    //asio::ip::udp::socket broadcast_socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 1024> recv_buffer_;
    struct dhcpmsg dhcpmsg_;
    std::string ifname_;
    asio::ip::address local_ip_;
};

#endif /* NK_DHCPCLIENT_H */
