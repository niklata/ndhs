// Copyright 2011-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP4_HPP
#define NDHS_DHCP4_HPP

#include <time.h> // ClientStates
#include <nk/sys/posix/handle.hpp>
#include "dhcp.h"
extern "C" {
#include <ipaddr.h>
#include <net/if.h>
}

// Number of entries for one of the two tables.  Exists per interface.
#define D4_CLIENT_STATE_TABLESIZE 256
#define D4_XID_LIFE_SECS 60

namespace detail {

// Timestamps are cheap on modern hardware, so we can do
// things precisely.  We optimize for cache locality.
struct ClientStates
{
    ClientStates();
    ClientStates(const ClientStates &) = delete;
    ClientStates &operator=(const ClientStates &) = delete;

    bool stateAdd(uint32_t xid, uint8_t *hwaddr, uint8_t state);
    uint8_t stateGet(uint32_t xid, uint8_t *hwaddr);
    void stateKill(uint8_t *hwaddr);
private:
    struct StateItem
    {
        struct timespec ts_; // Set once at creation
        uint64_t hwaddr_;
        uint32_t xid_;
        uint32_t state_;
    };
    struct StateItem *find(uint64_t h);

    struct StateItem map_[D4_CLIENT_STATE_TABLESIZE];
};

}

class D4Listener
{
public:
    D4Listener() {}
    D4Listener(const D4Listener &) = delete;
    D4Listener &operator=(const D4Listener &) = delete;

    [[nodiscard]] bool init(const char *ifname);
    void process_input();
    auto fd() const { return fd_(); }
    const char *ifname() const { return ifname_; }
private:
    bool create_dhcp4_socket();
    void dhcpmsg_init(dhcpmsg &dm, uint8_t type, uint32_t xid) const;
    uint32_t local_ip() const;

    enum class SendReplyType { UnicastCi, Broadcast, Relay, UnicastYiCh };
    bool send_to(const void *buf, size_t len, uint32_t addr, int port);
    void send_reply_do(const dhcpmsg &dm, SendReplyType srt);
    void send_reply(const dhcpmsg &dm);
    bool allot_dynamic_ip(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign);
    bool create_reply(dhcpmsg &reply, const uint8_t *hwaddr, bool do_assign);
    void reply_discover();
    void reply_request();
    void reply_inform();
    void do_release();
    uint8_t validate_dhcp(size_t len) const;
    void process_receive(const char *buf, size_t bytes_xferred);

    nk::sys::handle fd_;
    struct dhcpmsg dhcpmsg_;
    char ifname_[IFNAMSIZ];
    int ifindex_;
    in6_addr local_ip_;
    detail::ClientStates state_;
};

#endif
