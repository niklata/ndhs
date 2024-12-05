// Copyright 2011-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP4_HPP
#define NDHS_DHCP4_HPP

#include <string>
#include <vector>
#include <nk/net/ip_address.hpp>
#include <nk/sys/posix/handle.hpp>
#include "dhcp.h"
extern "C" {
#include <net/if.h>
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
    bool iplist_option(dhcpmsg &reply, std::string &iplist, uint8_t code,
                       const std::vector<nk::ip_address> &addrs);
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
    nk::ip_address local_ip_;
};

#endif
