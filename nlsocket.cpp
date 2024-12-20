// Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <poll.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "rng.h"
#include "nlsocket.hpp"
#include "dhcp_state.hpp"
extern "C" {
#include "nk/log.h"
#include "nl.h"
}

// The NLMSG_* macros include c-style casts.
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

void NLSocket::init()
{
    nlseq_ = nk_random_u64();
    got_newlink_ = false;
    query_ifindex_ = -1;

    fd_ = nl_open(NETLINK_ROUTE, RTMGRP_LINK, 0);
    if (fd_ < 0) suicide("NLSocket: failed to create netlink socket\n");

    request_links();

    struct pollfd pfd;
    pfd.fd = fd_;
    pfd.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pfd.revents = 0;
    for (;(got_newlink_ == false);) {
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            suicide("poll failed\n");
        }
        if (pfd.revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            suicide("nlfd closed unexpectedly\n");
        }
        if (pfd.revents & POLLIN) {
            process_input();
        }
    }
}

bool NLSocket::get_interface_addresses(int ifindex)
{
    query_ifindex_ = ifindex;
    if (query_ifindex_ < 0) return false;
    request_addrs(query_ifindex_);

    struct pollfd pfd;
    pfd.fd = fd_;
    pfd.events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pfd.revents = 0;
    while (query_ifindex_ >= 0) {
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            suicide("poll failed\n");
        }
        if (pfd.revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            suicide("nlfd closed unexpectedly\n");
        }
        if (pfd.revents & POLLIN) {
            process_input();
        }
    }
    return true;
}

void NLSocket::process_input()
{
    char buf[8192];
    for (;;) {
        auto buflen = recv(fd_, buf, sizeof buf, MSG_DONTWAIT);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("nlsocket: recv failed: %s\n", strerror(err));
        }
        process_receive(buf, static_cast<size_t>(buflen), 0, 0);
    }
}

void NLSocket::request_links()
{
    auto link_seq = nlseq_++;
    if (nl_sendgetlinks(fd_, link_seq) < 0)
        suicide("nlsocket: failed to get initial rtlink state\n");
}

void NLSocket::request_addrs(int ifidx)
{
    auto addr_seq = nlseq_++;
    if (nl_sendgetaddr(fd_, addr_seq, static_cast<uint32_t>(ifidx)) < 0)
        suicide("nlsocket: failed to get initial rtaddr state\n");
}

static void parse_raw_address6(in6_addr *addr, struct rtattr *tb[], size_t type)
{
    memcpy(addr, RTA_DATA(tb[type]), sizeof *addr);
}
static void parse_raw_address4(in6_addr *addr, struct rtattr *tb[], size_t type)
{
    ipaddr_from_v4_bytes(addr, RTA_DATA(tb[type]));
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
    nia.if_index = static_cast<int>(ifa->ifa_index);
    switch (ifa->ifa_scope) {
    case RT_SCOPE_UNIVERSE: nia.scope = netif_addr::Scope::Global; break;
    case RT_SCOPE_SITE: nia.scope = netif_addr::Scope::Site; break;
    case RT_SCOPE_LINK: nia.scope = netif_addr::Scope::Link; break;
    case RT_SCOPE_HOST: nia.scope = netif_addr::Scope::Host; break;
    case RT_SCOPE_NOWHERE: nia.scope = netif_addr::Scope::None; break;
    default: log_line("nlsocket: Unknown scope: %u\n", ifa->ifa_scope); return;
    }
    if (tb[IFA_ADDRESS]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(&nia.address, tb, IFA_ADDRESS);
        else
            parse_raw_address4(&nia.address, tb, IFA_ADDRESS);
    }
    if (tb[IFA_LOCAL]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(&nia.peer_address, tb, IFA_LOCAL);
        else
            parse_raw_address4(&nia.peer_address, tb, IFA_LOCAL);
    }
    if (tb[IFA_LABEL]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFA_LABEL]));
        size_t src_size = strlen(v);
        if (src_size >= sizeof nia.if_name) {
            log_line("nlsocket: Interface name (%s) too long\n", v);
            return;
        }
        *((char *)mempcpy(nia.if_name, v, src_size)) = 0;
    }
    if (tb[IFA_BROADCAST]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(&nia.broadcast_address, tb, IFA_BROADCAST);
        else
            parse_raw_address4(&nia.broadcast_address, tb, IFA_BROADCAST);
    }
    if (tb[IFA_ANYCAST]) {
        if (nia.addr_type == AF_INET6)
            parse_raw_address6(&nia.anycast_address, tb, IFA_ANYCAST);
        else
            parse_raw_address4(&nia.anycast_address, tb, IFA_ANYCAST);
    }

    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR: {
        if (query_ifindex_ == nia.if_index) query_ifindex_ = -1;
        for (auto &i: ifaces_) {
            if (i.index == nia.if_index) {
                // Update if the address already exists
                for (auto j = i.addrs.begin(), jend = i.addrs.end(); j != jend; ++j) {
                    if (!memcmp(&j->address, &nia.address, sizeof nia.address)) {
                        *j = nia;
                        return;
                    }
                }
                // Otherwise add it.
                if (nia.addr_type == AF_INET) {
                    emplace_broadcast(nia.if_index, &nia.broadcast_address);

                    uint32_t subnet = 0xffffffffu;
                    for (unsigned j = 0, jend = 32 - nia.prefixlen; j < jend; ++j) subnet <<= 1;
                    subnet = htonl(subnet);
                    char sbuf[INET_ADDRSTRLEN+1];
                    if (inet_ntop(AF_INET, &subnet, sbuf, sizeof sbuf)) {
                        in6_addr taddr;
                        if (!ipaddr_from_string(&taddr, sbuf)) abort();
                        emplace_subnet(nia.if_index, &taddr);
                    }
                }
                i.addrs.emplace_back(nia);
                return;
            }
        }
        log_line("nlsocket: Address for unknown interface %s\n", nia.if_name);
    }
    case RTM_DELADDR: {
        for (auto &i: ifaces_) {
            if (i.index == nia.if_index) {
                for (auto j = i.addrs.begin(), jend = i.addrs.end(); j != jend; ++j) {
                    if (!memcmp(&j->address, &nia.address, sizeof nia.address)) {
                        i.addrs.erase(j);
                        return;
                    }
                }
            }
        }
    }
    default:
        log_line("nlsocket: Unhandled address message type: %u\n", nlh->nlmsg_type);
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
        size_t src_size = strlen(v);
        if (src_size >= sizeof nii.name) {
            log_line("nlsocket: Interface name (%s) in link message is too long\n", v);
            return;
        }
        *((char *)mempcpy(nii.name, v, src_size)) = 0;
    }
    if (tb[IFLA_MTU])
        nii.mtu = *reinterpret_cast<uint32_t *>(RTA_DATA(tb[IFLA_MTU]));
    if (tb[IFLA_LINK])
        nii.link_type = *reinterpret_cast<int32_t *>(RTA_DATA(tb[IFLA_LINK]));

    switch (nlh->nlmsg_type) {
    case RTM_NEWLINK: {
        bool update = false;
        for (auto &i: ifaces_) {
            if (!strcmp(i.name, nii.name)) {
                // Preserve the addresses if we're just modifying fields.
                std::swap(nii.addrs, i.addrs);
                i = std::move(nii);
                update = true;
                break;
            }
        }
        if (!update) ifaces_.emplace_back(std::move(nii));
        log_line("nlsocket: Adding link info: %s\n", nii.name);
        break;
    }
    case RTM_DELLINK: {
        for (auto i = ifaces_.begin(), iend = ifaces_.end(); i != iend; ++i) {
            if (!strcmp(i->name, nii.name)) {
                ifaces_.erase(i);
                break;
            }
        }
        break;
    }
    default:
        log_line("nlsocket: Unhandled link message type: %u\n", nlh->nlmsg_type);
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
            log_line("nlsocket: Unhandled RTNETLINK msg type: %u\n", nlh->nlmsg_type);
            break;
    }
}

void NLSocket::process_receive(const char *buf, size_t bytes_xferred,
                               unsigned seq, unsigned portid)
{
    auto nlh = reinterpret_cast<const struct nlmsghdr *>(buf);
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
                log_line("nlsocket: Received a NLMSG_ERROR: %s\n",
                         strerror(nlmsg_get_error(nlh)));
                auto nle = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                log_line("error=%u len=%u type=%u flags=%u seq=%u pid=%u\n",
                         nle->error, nle->msg.nlmsg_len, nle->msg.nlmsg_type,
                         nle->msg.nlmsg_flags, nle->msg.nlmsg_seq,
                         nle->msg.nlmsg_pid);
                break;
            }
            case NLMSG_OVERRUN: log_line("nlsocket: Received a NLMSG_OVERRUN.\n");
            case NLMSG_NOOP: break;
            case NLMSG_DONE: got_newlink_ = true; break;
            default: break;
            }
        }
    }
}

