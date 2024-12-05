// Copyright 2011-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP4_HPP
#define NDHS_DHCP4_HPP

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <netdb.h>
#include <nk/net/ip_address.hpp>
#include <nk/sys/posix/handle.hpp>
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
// This scheme requires no per-item timestamping and will bound the lifetime of any
// object to be p < lifetime < 2p.  A further refinement would be to scale
// p to be inversely proportional to the number of entries on the 'new'
// and 'm4d' tables.  This change would cause the deletion rate to increase
// smoothly under heavy load, providing resistance to OOM DoS at the cost of
// making it so that clients will need to complete their transactions quickly.
class ClientStates
{
public:
    ClientStates();
    ClientStates(const ClientStates &) = delete;
    ClientStates &operator=(const ClientStates &) = delete;

    bool stateExists(uint32_t xid, uint8_t *hwaddr);
    void stateAdd(uint32_t xid, uint8_t *hwaddr, uint8_t state);
    uint8_t stateGet(uint32_t xid, uint8_t *hwaddr);
    void stateKill(uint32_t xid, uint8_t *hwaddr);
private:
    void maybe_swap(void);
    std::chrono::steady_clock::time_point expires_;
    std::unordered_map<std::string, uint8_t> map_[2];
    int currentMap_; // Either 0 or 1.
    int swapInterval_;
};

class D4Listener
{
public:
    D4Listener() {}
    D4Listener(const D4Listener &) = delete;
    D4Listener &operator=(const D4Listener &) = delete;

    [[nodiscard]] bool init(const std::string &ifname);
    void process_input();
    auto fd() const { return fd_(); }
    auto& ifname() const { return ifname_; }
private:
    bool create_dhcp4_socket();
    void dhcpmsg_init(dhcpmsg &dm, uint8_t type, uint32_t xid) const;
    uint32_t local_ip() const;
    std::string ipStr(uint32_t ip) const;

    enum class SendReplyType { UnicastCi, Broadcast, Relay, UnicastYiCh };
    bool send_to(const void *buf, size_t len, uint32_t addr, int port);
    void send_reply_do(const dhcpmsg &dm, SendReplyType srt);
    void send_reply(const dhcpmsg &dm);
    bool iplist_option(dhcpmsg &reply, std::string &iplist, uint8_t code,
                       const std::vector<nk::ip_address> &addrs);
    bool allot_dynamic_ip(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign);
    bool create_reply(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign);
    void reply_discover();
    void reply_request();
    void reply_inform();
    void do_release();
    std::string getChaddr(const struct dhcpmsg &dm) const;
    uint8_t validate_dhcp(size_t len) const;
    void process_receive(const char *buf, size_t bytes_xferred);

    nk::sys::handle fd_;
    struct dhcpmsg dhcpmsg_;
    std::string ifname_;
    nk::ip_address local_ip_;
};

#endif
