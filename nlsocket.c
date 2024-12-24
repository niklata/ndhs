// Copyright 2014-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <poll.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "nlsocket.h"
#include "dhcp_state.h"
#include "nk/log.h"
#include "nk/random.h"
#include "nl.h"

extern struct nk_random_state g_rngstate;

struct netif_addrinfo
{
    char if_name[IFNAMSIZ];
    int if_index;
    struct in6_addr address;
    struct in6_addr peer_address;
    struct in6_addr broadcast_address;
    struct in6_addr anycast_address;
    unsigned char addr_type;
    unsigned char prefixlen;
    unsigned char flags;
    unsigned char scope;
};

static void request_links(struct NLSocket *self);
static void request_addrs(struct NLSocket *self, int ifidx);
static void process_receive(struct NLSocket *self, const char *buf, size_t bytes_xferred,
                            unsigned seq, unsigned portid);

void NLSocket_init(struct NLSocket *self)
{
    self->nlseq_ = nk_random_u64(&g_rngstate);
    self->got_newlink_ = false;
    self->query_ifindex_ = -1;

    self->fd_ = nl_open(NETLINK_ROUTE, RTMGRP_LINK, 0);
    if (self->fd_ < 0) suicide("NLSocket: failed to create netlink socket\n");

    request_links(self);

    struct pollfd pfd;
    pfd.fd = self->fd_;
    pfd.events = POLLIN|POLLHUP|POLLERR;
    pfd.revents = 0;
    for (;(self->got_newlink_ == false);) {
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            suicide("poll failed\n");
        }
        if (pfd.revents & (POLLHUP|POLLERR)) {
            suicide("nlfd closed unexpectedly\n");
        }
        if (pfd.revents & POLLIN) {
            NLSocket_process_input(self);
        }
    }
}

bool NLSocket_get_interface_addresses(struct NLSocket *self, int ifindex)
{
    self->query_ifindex_ = ifindex;
    if (self->query_ifindex_ < 0) return false;
    request_addrs(self, self->query_ifindex_);

    struct pollfd pfd;
    pfd.fd = self->fd_;
    pfd.events = POLLIN|POLLHUP|POLLERR;
    pfd.revents = 0;
    while (self->query_ifindex_ >= 0) {
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            suicide("poll failed\n");
        }
        if (pfd.revents & (POLLHUP|POLLERR)) {
            suicide("nlfd closed unexpectedly\n");
        }
        if (pfd.revents & POLLIN) {
            NLSocket_process_input(self);
        }
    }
    return true;
}

void NLSocket_process_input(struct NLSocket *self)
{
    char buf[8192];
    for (;;) {
        ssize_t buflen = recv(self->fd_, buf, sizeof buf, MSG_DONTWAIT);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("nlsocket: recv failed: %s\n", strerror(err));
        }
        process_receive(self, buf, (size_t)buflen, 0, 0);
    }
}

static void request_links(struct NLSocket *self)
{
    uint32_t link_seq = self->nlseq_++;
    if (nl_sendgetlinks(self->fd_, link_seq) < 0)
        suicide("nlsocket: failed to get initial rtlink state\n");
}

static void request_addrs(struct NLSocket *self, int ifidx)
{
    uint32_t addr_seq = self->nlseq_++;
    if (nl_sendgetaddr(self->fd_, addr_seq, (uint32_t)ifidx) < 0)
        suicide("nlsocket: failed to get initial rtaddr state\n");
}

static void parse_raw_address6(struct in6_addr *addr, struct rtattr *tb[], size_t type)
{
    memcpy(addr, RTA_DATA(tb[type]), sizeof *addr);
}
static void parse_raw_address4(struct in6_addr *addr, struct rtattr *tb[], size_t type)
{
    ipaddr_from_v4_bytes(addr, RTA_DATA(tb[type]));
}

static void process_rt_addr_msgs(struct NLSocket *self, const struct nlmsghdr *nlh)
{
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    struct rtattr *tb[IFA_MAX];
    memset(tb, 0, sizeof tb);
    nl_rtattr_parse(nlh, sizeof *ifa, rtattr_assign, tb);

    struct netif_addrinfo nia;
    nia.addr_type = ifa->ifa_family;
    if (nia.addr_type != AF_INET6 && nia.addr_type != AF_INET)
        return;
    nia.prefixlen = ifa->ifa_prefixlen;
    nia.flags = ifa->ifa_flags;
    nia.if_index = (int)ifa->ifa_index;
    nia.scope = ifa->ifa_scope;
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
        const char *v = RTA_DATA(tb[IFA_LABEL]);
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
        if (self->query_ifindex_ == nia.if_index) self->query_ifindex_ = -1;
        if (nia.if_index >= 0 && nia.if_index < MAX_NL_INTERFACES) {
            struct netif_info *n = &self->interfaces_[nia.if_index];
            if (nia.addr_type == AF_INET || ipaddr_is_v4(&nia.address)) {
                n->has_v4_address = true;
                n->v4_address = nia.address;
                emplace_broadcast(nia.if_index, &nia.broadcast_address);

                uint32_t subnet = 0xffffffffu;
                for (unsigned j = 0, jend = 32 - nia.prefixlen; j < jend; ++j) subnet <<= 1;
                subnet = htonl(subnet);
                char sbuf[INET_ADDRSTRLEN+1];
                if (inet_ntop(AF_INET, &subnet, sbuf, sizeof sbuf)) {
                    struct in6_addr taddr;
                    if (!ipaddr_from_string(&taddr, sbuf)) abort();
                    emplace_subnet(nia.if_index, &taddr);
                }
                return;
            } else if (nia.addr_type == AF_INET6) {
                if (nia.scope == RT_SCOPE_UNIVERSE) {
                    n->has_v6_address_global = true;
                    n->v6_address_global = nia.address;
                    n->v6_prefixlen_global = nia.prefixlen;
                } else if (nia.scope == RT_SCOPE_LINK) {
                    n->has_v6_address_link = true;
                    n->v6_address_link = nia.address;
                }
            }
            return;
        }
        log_line("nlsocket: Address for unknown interface %s\n", nia.if_name);
    }
    case RTM_DELADDR: {
        if (nia.if_index >= 0 && nia.if_index < MAX_NL_INTERFACES) {
            struct netif_info *n = &self->interfaces_[nia.if_index];
            if (n->has_v4_address && (nia.addr_type == AF_INET || ipaddr_is_v4(&nia.address))) {
                if (!memcmp(&n->v4_address, &nia.address, sizeof nia.address)) {
                    memset(&n->v4_address, 0, sizeof n->v4_address);
                    n->has_v4_address = false;
                }
            } else if ((n->has_v6_address_global || n->has_v6_address_link) && nia.addr_type == AF_INET6) {
                if (nia.scope == RT_SCOPE_UNIVERSE) {
                    if (!memcmp(&n->v6_address_global, &nia.address, sizeof nia.address)) {
                        memset(&n->v6_address_global, 0, sizeof n->v6_address_global);
                        n->has_v6_address_global = false;
                    }
                } else if (nia.scope == RT_SCOPE_LINK) {
                    if (!memcmp(&n->v6_address_link, &nia.address, sizeof nia.address)) {
                        memset(&n->v6_address_link, 0, sizeof n->v6_address_link);
                        n->has_v6_address_link = false;
                    }
                }
            }
            return;
        }
    }
    default:
        log_line("nlsocket: Unhandled address message type: %u\n", nlh->nlmsg_type);
        return;
    }
}

static void process_rt_link_msgs(struct NLSocket *self, const struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifm = NLMSG_DATA(nlh);
    struct rtattr *tb[IFLA_MAX];
    memset(tb, 0, sizeof tb);
    nl_rtattr_parse(nlh, sizeof *ifm, rtattr_assign, tb);

    struct netif_info nii;
    nii.family = ifm->ifi_family;
    nii.device_type = ifm->ifi_type;
    nii.index = ifm->ifi_index;
    nii.flags = ifm->ifi_flags;
    nii.change_mask = ifm->ifi_change;
    nii.is_active = ifm->ifi_flags & IFF_UP;
    if (tb[IFLA_ADDRESS]) {
        const uint8_t *mac = RTA_DATA(tb[IFLA_ADDRESS]);
        memcpy(nii.macaddr, mac, sizeof nii.macaddr);
    }
    if (tb[IFLA_BROADCAST]) {
        const uint8_t *mac = RTA_DATA(tb[IFLA_ADDRESS]);
        memcpy(nii.macbc, mac, sizeof nii.macbc);
    }
    if (tb[IFLA_IFNAME]) {
        const char *v = RTA_DATA(tb[IFLA_IFNAME]);
        size_t src_size = strlen(v);
        if (src_size >= sizeof nii.name) {
            log_line("nlsocket: Interface name (%s) in link message is too long\n", v);
            return;
        }
        *((char *)mempcpy(nii.name, v, src_size)) = 0;
    }
    if (tb[IFLA_MTU])
        nii.mtu = *(uint32_t *)(RTA_DATA(tb[IFLA_MTU]));
    if (tb[IFLA_LINK])
        nii.link_type = *(int32_t *)(RTA_DATA(tb[IFLA_LINK]));

    switch (nlh->nlmsg_type) {
    case RTM_NEWLINK: {
        if (ifm->ifi_index >= MAX_NL_INTERFACES) {
            log_line("nlsocket: Attempt to add interface with out-of-range index (%d)\n", ifm->ifi_index);
            break;
        }
        bool update = false;
        if (!strcmp(self->interfaces_[ifm->ifi_index].name, nii.name)) {
            // We don't alter name or index, and addresses are not
            // sent in this message, so don't alter those.
            struct netif_info *n = &self->interfaces_[ifm->ifi_index];
            n->family = nii.family;
            n->device_type = nii.device_type;
            n->flags = nii.flags;
            n->change_mask = nii.change_mask;
            n->mtu = nii.mtu;
            n->link_type = nii.link_type;
            memcpy(&n->macaddr, &nii.macaddr, sizeof n->macaddr);
            memcpy(&n->macbc, &nii.macbc, sizeof n->macbc);
            n->is_active = nii.is_active;
            update = true;
        }
        if (!update) memcpy(&self->interfaces_[ifm->ifi_index], &nii, sizeof self->interfaces_[0]);
        log_line("nlsocket: Adding link info: %s\n", nii.name);
        break;
    }
    case RTM_DELLINK: {
        if (ifm->ifi_index >= MAX_NL_INTERFACES) {
            log_line("nlsocket: Attempt to delete interface with out-of-range index (%d)\n", ifm->ifi_index);
            break;
        }
        memset(&self->interfaces_[ifm->ifi_index], 0, sizeof self->interfaces_[0]);
        break;
    }
    default:
        log_line("nlsocket: Unhandled link message type: %u\n", nlh->nlmsg_type);
        break;
    }
}

static void process_nlmsg(struct NLSocket *self, const struct nlmsghdr *nlh)
{
    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            process_rt_link_msgs(self, nlh);
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            process_rt_addr_msgs(self, nlh);
            break;
        default:
            log_line("nlsocket: Unhandled RTNETLINK msg type: %u\n", nlh->nlmsg_type);
            break;
    }
}

static void process_receive(struct NLSocket *self, const char *buf, size_t bytes_xferred,
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
            process_nlmsg(self, nlh);
        } else {
            switch (nlh->nlmsg_type) {
            case NLMSG_ERROR: {
                log_line("nlsocket: Received a NLMSG_ERROR: %s\n",
                         strerror(nlmsg_get_error(nlh)));
                struct nlmsgerr *nle = NLMSG_DATA(nlh);
                log_line("error=%u len=%u type=%u flags=%u seq=%u pid=%u\n",
                         nle->error, nle->msg.nlmsg_len, nle->msg.nlmsg_type,
                         nle->msg.nlmsg_flags, nle->msg.nlmsg_seq,
                         nle->msg.nlmsg_pid);
                break;
            }
            case NLMSG_OVERRUN: log_line("nlsocket: Received a NLMSG_OVERRUN.\n");
            case NLMSG_NOOP: break;
            case NLMSG_DONE: self->got_newlink_ = true; break;
            default: break;
            }
        }
    }
}

