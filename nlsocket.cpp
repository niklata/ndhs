/* nlsocket.cpp - ipv6 netlink ifinfo gathering
 *
 * (c) 2014-2016 Nicholas J. Kain <njkain at gmail dot com>
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

#include <format.hpp>
#include <nk/xorshift.hpp>
#include "nlsocket.hpp"
extern "C" {
#include "nl.h"
}
extern nk::rng::xorshift64m g_random_prng;

NLSocket::NLSocket(asio::io_service &io_service)
: socket_(io_service), nlseq_(g_random_prng())
{
    initialized_ = false;
    socket_.open(nl_protocol(NETLINK_ROUTE));
    socket_.bind(nl_endpoint<nl_protocol>(RTMGRP_LINK));
    socket_.non_blocking(true);

    request_links();
    request_addrs();
    initialized_ = true;

    // Begin the main asynchronous receive loop.
    start_receive();
}

void NLSocket::request_links()
{
    int fd = socket_.native();
    auto link_seq = nlseq_++;
    if (nl_sendgetlinks(fd, link_seq) < 0) {
        fmt::print(stderr, "nlsocket: failed to get initial rtlink state\n");
        std::exit(EXIT_FAILURE);
    }
    std::size_t bytes_xferred;
    std::error_code ec;
    while ((bytes_xferred = socket_.receive(asio::buffer(recv_buffer_), 0, ec)))
        process_receive(bytes_xferred, link_seq, 0);
}

void NLSocket::request_addrs()
{
    int fd = socket_.native();
    auto addr_seq = nlseq_++;
    if (nl_sendgetaddrs(fd, addr_seq) < 0) {
        fmt::print(stderr, "nlsocket: failed to get initial rtaddr state\n");
        std::exit(EXIT_FAILURE);
    }
    std::size_t bytes_xferred;
    std::error_code ec;
    while ((bytes_xferred = socket_.receive(asio::buffer(recv_buffer_), 0, ec)))
        process_receive(bytes_xferred, addr_seq, 0);
}

void NLSocket::request_addrs(int ifidx)
{
    int fd = socket_.native();
    auto addr_seq = nlseq_++;
    if (nl_sendgetaddr(fd, addr_seq, ifidx) < 0) {
        fmt::print(stderr, "nlsocket: failed to get initial rtaddr state\n");
        std::exit(EXIT_FAILURE);
    }
}

static void parse_raw_address6(asio::ip::address &addr, struct rtattr *tb[], size_t type, int index)
{
    asio::ip::address_v6::bytes_type bytes;
    memcpy(&bytes, RTA_DATA(tb[type]), sizeof bytes);
    addr = asio::ip::address_v6(bytes, index);
}
static void parse_raw_address4(asio::ip::address &addr, struct rtattr *tb[], size_t type)
{
    asio::ip::address_v4::bytes_type bytes;
    memcpy(&bytes, RTA_DATA(tb[type]), sizeof bytes);
    addr = asio::ip::address_v4(bytes);
}

void NLSocket::process_rt_addr_msgs(const struct nlmsghdr *nlh)
{
    auto ifa = reinterpret_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh));
    struct rtattr *tb[IFA_MAX];
    memset(tb, 0, sizeof tb);
    nl_rtattr_parse(nlh, sizeof *ifa, rtattr_assign, tb);

    netif_addr nia;
    nia.addr_type = ifa->ifa_family;
    if (nia.addr_type != AF_INET6 && nia.addr_type != AF_INET)
        return;
    nia.prefixlen = ifa->ifa_prefixlen;
    nia.flags = ifa->ifa_flags;
    nia.if_index = ifa->ifa_index;
    switch (ifa->ifa_scope) {
    case RT_SCOPE_UNIVERSE: nia.scope = netif_addr::Scope::Global; break;
    case RT_SCOPE_SITE: nia.scope = netif_addr::Scope::Site; break;
    case RT_SCOPE_LINK: nia.scope = netif_addr::Scope::Link; break;
    case RT_SCOPE_HOST: nia.scope = netif_addr::Scope::Host; break;
    case RT_SCOPE_NOWHERE: nia.scope = netif_addr::Scope::None; break;
    default: fmt::print(stderr, "nlsocket: Unknown scope: {}\n", ifa->ifa_scope); return;
    }
    if (tb[IFA_ADDRESS]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(nia.address, tb, IFA_ADDRESS, ifa->ifa_index);
        else
            parse_raw_address4(nia.address, tb, IFA_ADDRESS);
    }
    if (tb[IFA_LOCAL]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(nia.peer_address, tb, IFA_LOCAL, ifa->ifa_index);
        else
            parse_raw_address4(nia.peer_address, tb, IFA_LOCAL);
    }
    if (tb[IFA_LABEL]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFA_LABEL]));
        nia.if_name = std::string(v, strlen(v));
    }
    if (tb[IFA_BROADCAST]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(nia.broadcast_address, tb, IFA_BROADCAST, ifa->ifa_index);
        else
            parse_raw_address4(nia.broadcast_address, tb, IFA_BROADCAST);
    }
    if (tb[IFA_ANYCAST]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(nia.anycast_address, tb, IFA_ANYCAST, ifa->ifa_index);
        else
            parse_raw_address4(nia.anycast_address, tb, IFA_ANYCAST);
    }

    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR: {
        auto ifelt = interfaces.find(nia.if_index);
        if (ifelt == interfaces.end()) {
            fmt::print(stderr, "nlsocket: Address for unknown interface {}\n",
                       nia.if_name.c_str());
            return;
        }
        const auto iend = ifelt->second.addrs.end();
        for (auto i = ifelt->second.addrs.begin(); i != iend; ++i) {
            if (i->address == nia.address) {
                *i = std::move(nia);
                return;
            }
        }
        ifelt->second.addrs.emplace_back(std::move(nia));
        return;
    }
    case RTM_DELADDR: {
        auto ifelt = interfaces.find(nia.if_index);
        if (ifelt == interfaces.end())
            return;
        const auto iend = ifelt->second.addrs.end();
        for (auto i = ifelt->second.addrs.begin(); i != iend; ++i) {
            if (i->address == nia.address) {
                ifelt->second.addrs.erase(i);
                break;
            }
        }
        return;
    }
    default:
        fmt::print(stderr, "nlsocket: Unhandled address message type: {}\n", nlh->nlmsg_type);
        return;
    }
}

void NLSocket::process_rt_link_msgs(const struct nlmsghdr *nlh)
{
    auto ifm = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nlh));
    struct rtattr *tb[IFLA_MAX];
    memset(tb, 0, sizeof tb);
    nl_rtattr_parse(nlh, sizeof *ifm, rtattr_assign, tb);

    netif_info nii;
    nii.family = ifm->ifi_family;
    nii.device_type = ifm->ifi_type;
    nii.index = ifm->ifi_index;
    nii.flags = ifm->ifi_flags;
    nii.change_mask = ifm->ifi_change;
    nii.is_active = ifm->ifi_flags & IFF_UP;
    if (tb[IFLA_ADDRESS]) {
        auto mac = reinterpret_cast<const uint8_t *>
            (RTA_DATA(tb[IFLA_ADDRESS]));
        memcpy(nii.macaddr, mac, sizeof nii.macaddr);
    }
    if (tb[IFLA_BROADCAST]) {
        auto mac = reinterpret_cast<const uint8_t *>
            (RTA_DATA(tb[IFLA_ADDRESS]));
        memcpy(nii.macbc, mac, sizeof nii.macbc);
    }
    if (tb[IFLA_IFNAME]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFLA_IFNAME]));
        nii.name = std::string(v, strlen(v));
    }
    if (tb[IFLA_QDISC]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFLA_QDISC]));
        nii.qdisc = std::string(v, strlen(v));
    }
    if (tb[IFLA_MTU])
        nii.mtu = *reinterpret_cast<uint32_t *>(RTA_DATA(tb[IFLA_MTU]));
    if (tb[IFLA_LINK])
        nii.link_type = *reinterpret_cast<int32_t *>(RTA_DATA(tb[IFLA_LINK]));

    switch (nlh->nlmsg_type) {
    case RTM_NEWLINK: {
        name_to_ifindex_.emplace(std::make_pair(nii.name, nii.index));
        auto elt = interfaces.find(nii.index);
        // Preserve the addresses if we're just modifying fields.
        if (elt != interfaces.end())
            std::swap(nii.addrs, elt->second.addrs);
        fmt::print(stderr, "nlsocket: Adding link info: {}\n", nii.name);
        interfaces.emplace(std::make_pair(nii.index, nii));
        if (initialized_)
            request_addrs(nii.index);
        break;
    }
    case RTM_DELLINK:
        name_to_ifindex_.erase(nii.name);
        interfaces.erase(nii.index);
        break;
    default:
        fmt::print(stderr, "nlsocket: Unhandled link message type: {}\n", nlh->nlmsg_type);
        break;
    }
}

void NLSocket::process_nlmsg(const struct nlmsghdr *nlh)
{
    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            process_rt_link_msgs(nlh);
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            process_rt_addr_msgs(nlh);
            break;
        default:
            fmt::print(stderr, "nlsocket: Unhandled RTNETLINK msg type: {}\n", nlh->nlmsg_type);
            break;
    }
}

void NLSocket::process_receive(std::size_t bytes_xferred,
                               unsigned int seq, unsigned int portid)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)recv_buffer_.data();
    for (;NLMSG_OK(nlh, bytes_xferred); nlh = NLMSG_NEXT(nlh, bytes_xferred)) {
        // Should be 0 for messages from the kernel.
        if (nlh->nlmsg_pid && portid && nlh->nlmsg_pid != portid)
            continue;
        if (seq && nlh->nlmsg_seq != seq)
            continue;

        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
            process_nlmsg(nlh);
        } else {
            switch (nlh->nlmsg_type) {
            case NLMSG_ERROR: {
                fmt::print(stderr, "nlsocket: Received a NLMSG_ERROR: {}\n",
                           strerror(nlmsg_get_error(nlh)));
                auto nle = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                fmt::print(stderr, "error={} len={} type={} flags={} seq={} pid={}\n",
                         nle->error, nle->msg.nlmsg_len, nle->msg.nlmsg_type,
                         nle->msg.nlmsg_flags, nle->msg.nlmsg_seq,
                         nle->msg.nlmsg_pid);
                break;
            }
            case NLMSG_OVERRUN:
                fmt::print(stderr, "nlsocket: Received a NLMSG_OVERRUN.\n");
            case NLMSG_NOOP:
            case NLMSG_DONE:
            default:
                break;
            }
        }
    }
}

void NLSocket::start_receive()
{
    socket_.async_receive_from
        (asio::buffer(recv_buffer_), remote_endpoint_,
         [this](const std::error_code &error, std::size_t bytes_xferred)
         {
             process_receive(bytes_xferred, 0, 0);
             start_receive();
         });
}


