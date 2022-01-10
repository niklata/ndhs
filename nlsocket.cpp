/* nlsocket.cpp - ipv6 netlink ifinfo gathering
 *
 * Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
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

#include "rng.hpp"
#include "nlsocket.hpp"
extern "C" {
#include "nk/log.h"
#include "nl.h"
}

NLSocket::NLSocket(std::vector<std::string> &&ifnames)
    : ifnames_(std::move(ifnames)), nlseq_(random_u64()), got_newlink_(false)
{
    auto tfd = nk::sys::handle{ nl_open(NETLINK_ROUTE, RTMGRP_LINK, 0) };
    if (!tfd) suicide("NLSocket: failed to create netlink socket");
    swap(fd_, tfd);

    request_links();

    struct pollfd pfd;
    pfd.fd = fd_();
    pfd.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pfd.revents = 0;
    for (;(got_newlink_ == false);) {
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            suicide("poll failed");
        }
        if (pfd.revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            suicide("nlfd closed unexpectedly");
        }
        if (pfd.revents & POLLIN) {
            process_input();
        }
    }

    for (auto &i: ifnames_) {
        const auto ifindex = name_to_ifindex_[i];
        query_ifindex_ = ifindex;
        request_addrs(ifindex);
        for (;query_ifindex_.has_value();) {
            if (poll(&pfd, 1, -1) < 0) {
                if (errno == EINTR) continue;
                suicide("poll failed");
            }
            if (pfd.revents & (POLLHUP|POLLERR|POLLRDHUP)) {
                suicide("nlfd closed unexpectedly");
            }
            if (pfd.revents & POLLIN) {
                process_input();
            }
        }
    }
}

void NLSocket::process_input()
{
    char buf[8192];
    for (;;) {
        auto buflen = recv(fd_(), buf, sizeof buf, MSG_DONTWAIT);
        if (buflen == -1) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("nlsocket: recv failed: %s", strerror(err));
        }
        process_receive(buf, buflen, 0, 0);
    }
}

void NLSocket::request_links()
{
    auto link_seq = nlseq_++;
    if (nl_sendgetlinks(fd_(), link_seq) < 0)
        suicide("nlsocket: failed to get initial rtlink state");
}

void NLSocket::request_addrs(int ifidx)
{
    auto addr_seq = nlseq_++;
    if (nl_sendgetaddr(fd_(), addr_seq, ifidx) < 0)
        suicide("nlsocket: failed to get initial rtaddr state");
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
    default: log_line("nlsocket: Unknown scope: %u", ifa->ifa_scope); return;
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
        if (query_ifindex_.has_value() && *query_ifindex_ == nia.if_index) query_ifindex_.reset();
        auto ifelt = interfaces_.find(nia.if_index);
        if (ifelt == interfaces_.end()) {
            log_line("nlsocket: Address for unknown interface %s", nia.if_name.c_str());
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
        auto ifelt = interfaces_.find(nia.if_index);
        if (ifelt == interfaces_.end())
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
        log_line("nlsocket: Unhandled address message type: %u", nlh->nlmsg_type);
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
        auto elt = interfaces_.find(nii.index);
        // Preserve the addresses if we're just modifying fields.
        if (elt != interfaces_.end())
            std::swap(nii.addrs, elt->second.addrs);
        log_line("nlsocket: Adding link info: %s", nii.name.c_str());
        interfaces_.emplace(std::make_pair(nii.index, nii));
        break;
    }
    case RTM_DELLINK: {
        name_to_ifindex_.erase(nii.name);
        interfaces_.erase(nii.index);
        break;
    }
    default:
        log_line("nlsocket: Unhandled link message type: %u", nlh->nlmsg_type);
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
            log_line("nlsocket: Unhandled RTNETLINK msg type: %u", nlh->nlmsg_type);
            break;
    }
}

void NLSocket::process_receive(const char *buf, std::size_t bytes_xferred,
                               unsigned seq, unsigned portid)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
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
                log_line("nlsocket: Received a NLMSG_ERROR: %s",
                         strerror(nlmsg_get_error(nlh)));
                auto nle = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                log_line("error=%u len=%u type=%u flags=%u seq=%u pid=%u",
                         nle->error, nle->msg.nlmsg_len, nle->msg.nlmsg_type,
                         nle->msg.nlmsg_flags, nle->msg.nlmsg_seq,
                         nle->msg.nlmsg_pid);
                break;
            }
            case NLMSG_OVERRUN: log_line("nlsocket: Received a NLMSG_OVERRUN.");
            case NLMSG_NOOP: break;
            case NLMSG_DONE: got_newlink_ = true; break;
            default: break;
            }
        }
    }
}

