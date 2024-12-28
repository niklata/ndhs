// Copyright 2011-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <sys/types.h>
#include <net/if.h>
#include <pwd.h>
#include "dhcp4.h"
#include "dhcp_state.h"
#include "nlsocket.h"
#include "dynlease.h"
#include "sbufs.h"
#include "nk/netbits.h"
#include "nk/log.h"
#include "nk/io.h"
#include "nk/random.h"
#include "ipaddr.h"
#include "options.h"
#include "get_current_ts.h"
#include "dhcp.h"

// Number of entries.  Exists per interface.
#define D4_CLIENT_STATE_TABLESIZE 256
#define D4_XID_LIFE_SECS 60

extern struct nk_random_state g_rngstate;
extern struct NLSocket nl_socket;

enum SendReplyType {
    SRT_UnicastCi,
    SRT_Broadcast,
    SRT_Relay,
    SRT_UnicastYiCh
};

// Timestamps are cheap on modern hardware, so we can do
// things precisely.  We optimize for cache locality.
struct D4State
{
    struct timespec ts; // Set once at creation
    uint64_t hwaddr;
    uint32_t xid;
    uint32_t state;
};

struct D4Listener
{
    int fd;
    int ifindex;
    struct dhcpmsg dhcpmsg;
    struct in6_addr local_ip;
    char ifname[IFNAMSIZ];
    struct D4State map[D4_CLIENT_STATE_TABLESIZE];
};

// hwaddr must be exactly 6 bytes
static uint64_t hwaddr_to_int64(uint8_t *hwaddr)
{
    return (uint64_t)hwaddr[0] |
           ((uint64_t)hwaddr[1] << 8) |
           ((uint64_t)hwaddr[2] << 16) |
           ((uint64_t)hwaddr[3] << 24) |
           ((uint64_t)hwaddr[4] << 32) |
           ((uint64_t)hwaddr[5] << 40);
}

static inline bool ip4_to_string(char *buf, size_t buflen, uint32_t addr)
{
    return !!inet_ntop(AF_INET, &addr, buf, buflen);
}

static struct D4State *find(struct D4State *self, uint64_t h)
{
    for (size_t i = 0; i < D4_CLIENT_STATE_TABLESIZE; ++i) {
        if (self[i].hwaddr == h) {
            struct timespec now;
            clock_gettime(CLOCK_BOOTTIME, &now);
            if (now.tv_sec > self[i].ts.tv_sec + D4_XID_LIFE_SECS) {
                self[i] = (struct D4State){0};
                break;
            }
            return &self[i];
        }
    }
    return NULL;
}

static bool D4State_add(struct D4State *self, uint32_t xid, uint8_t *hwaddr, uint8_t state)
{
    if (!state) return false;
    uint64_t key = hwaddr_to_int64(hwaddr);
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    struct D4State *m = NULL, *e = NULL;
    struct D4State zi = {0};
    for (size_t i = 0; i < D4_CLIENT_STATE_TABLESIZE; ++i) {
        if (self[i].ts.tv_sec && now.tv_sec > self[i].ts.tv_sec + D4_XID_LIFE_SECS) {
            // Expire entries as we see them.
            self[i] = (struct D4State){0};
        } else {
            if (self[i].hwaddr == key) {
                m = &self[i];
                break;
            }
        }
        if (!e && !memcmp(&self[i], &zi, sizeof zi)) e = &self[i];
    }
    if (!m) {
        if (!e) return false; // Out of space.
        m = e;
    }
    *m = (struct D4State){
        .ts = now,
        .hwaddr = key,
        .xid = xid,
        .state = state,
    };
    return true;
}

static uint8_t D4State_get(struct D4State *self, uint32_t xid, uint8_t *hwaddr)
{
    uint64_t key = hwaddr_to_int64(hwaddr);
    struct D4State *m = find(self, key);
    if (!m || m->xid != xid) return DHCPNULL;
    return m->state;
}

static void D4State_kill(struct D4State *self, uint8_t *hwaddr)
{
    uint64_t key = hwaddr_to_int64(hwaddr);
    struct D4State *m = find(self, key);
    if (m) *m = (struct D4State){0};
}

// Must be called after ifname is set and only should be called once.
static bool create_dhcp4_socket(struct D4Listener *self)
{
    struct ifreq ifr = {0};
    const int iv = 1;
    size_t ifname_len = strlen(self->ifname);
    struct sockaddr_in sai = {
        .sin_family = AF_INET,
        .sin_port = htons(67),
    };
    self->fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP);
    if (self->fd < 0) {
        log_line("dhcp4: Failed to create v4 UDP socket on %s: %s\n", self->ifname, strerror(errno));
        goto err0;
    }
    if (setsockopt(self->fd, SOL_SOCKET, SO_BROADCAST, &iv, sizeof iv) == -1) {
        log_line("dhcp4: Failed to set broadcast flag on %s: %s\n", self->ifname, strerror(errno));
        goto err1;
    }
    if (setsockopt(self->fd, SOL_SOCKET, SO_DONTROUTE, &iv, sizeof iv) == -1) {
        log_line("dhcp4: Failed to set do not route flag on %s: %s\n", self->ifname, strerror(errno));
        goto err1;
    }
    if (setsockopt(self->fd, SOL_SOCKET, SO_REUSEADDR, &iv, sizeof iv) == -1) {
        log_line("dhcp4: Failed to set reuse address flag on %s: %s\n", self->ifname, strerror(errno));
        goto err1;
    }
    if (bind(self->fd, (const struct sockaddr *)&sai, sizeof sai)) {
        log_line("dhcp4: Failed to bind to UDP 67 on %s: %s\n", self->ifname, strerror(errno));
        goto err1;
    }
    if (ifname_len >= sizeof ifr.ifr_name) {
        log_line("dhcp4: Interface name '%s' is too long: %zu >= %zu\n",
                 self->ifname, ifname_len, sizeof ifr.ifr_name);
        goto err1;
    }
    memcpy(ifr.ifr_name, self->ifname, ifname_len);
    if (setsockopt(self->fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_line("dhcp4: Failed to bind socket to device on %s: %s\n", self->ifname, strerror(errno));
        goto err1;
    }
    return true;
err1:
    close(self->fd);
    self->fd = -1;
err0:
    return false;
}

// Only intended to be called once per listener.
struct D4Listener *D4Listener_create(const char *ifname, const struct netif_info *ifinfo)
{
    struct D4Listener *self;
    size_t ifname_src_size = strlen(ifname);
    if (ifname_src_size >= sizeof self->ifname) {
        log_line("D4Listener: Interface name (%s) too long\n", ifname);
        return NULL;
    }
    if (!ifinfo->has_v4_address) {
        log_line("dhcp4: Interface (%s) has no IP address\n", ifname);
        return NULL;
    }
    self = calloc(1, sizeof(struct D4Listener));
    if (!self) return NULL;

    self->ifindex = ifinfo->index;
    *(char *)(mempcpy(self->ifname, ifname, ifname_src_size)) = 0;
    self->local_ip = ifinfo->v4_address;

    char abuf[48];
    if (!create_dhcp4_socket(self)) goto err;
    if (!ipaddr_to_string(abuf, sizeof abuf, &self->local_ip)) goto err;
    log_line("dhcp4: IP address for %s is %s\n", ifname, abuf);

    return self;
err:
    free(self);
    return NULL;
}

static void process_receive(struct D4Listener *self, const char *buf, size_t buflen,
                            const struct sockaddr_in *sai);

void D4Listener_process_input(struct D4Listener *self)
{
    char buf[8192];
    for (;;) {
        struct sockaddr_in sai;
        socklen_t sailen = sizeof sai;
        ssize_t buflen = recvfrom(self->fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&sai, &sailen);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("dhcp4: recvfrom failed on %s: %s\n", self->ifname, strerror(err));
        }
        process_receive(self, buf, (size_t)buflen, &sai);
    }
}

int D4Listener_fd(const struct D4Listener *self)
{
    return self->fd;
}

static uint32_t local_ip(const struct D4Listener *self)
{
    uint32_t ret;
    memcpy(&ret, ipaddr_v4_bytes(&self->local_ip), sizeof ret);
    return ret;
}

static void dhcpmsg_init(const struct D4Listener *self, struct dhcpmsg *dm, uint8_t type, uint32_t xid)
{
    *dm = (struct dhcpmsg){
        .op = 2, // BOOTREPLY (server)
        .htype = 1,
        .hlen = 6,
        .xid = xid,
        .cookie = htonl(DHCP_MAGIC),
        .options[0] = DCODE_END,
    };
    memcpy(dm->chaddr, &self->dhcpmsg.chaddr, sizeof self->dhcpmsg.chaddr);
    add_option_msgtype(dm, type);
    add_option_serverid(dm, local_ip(self));
}

static void send_to(int fd, const void *buf, size_t len, uint32_t addr, int port)
{
    struct sockaddr_in sai = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = addr,
    };
    ssize_t r = safe_sendto(fd, buf, len, 0, (const struct sockaddr *)&sai, sizeof sai);
    if (r < 0) log_line("dhcp4: D4Listener sendto failed: %s\n", strerror(errno));
}

static void send_reply_do(struct D4Listener *self, const struct dhcpmsg *dm, enum SendReplyType srt)
{
    ssize_t endloc = get_end_option_idx(dm);
    if (endloc < 0) return;
    size_t dmlen = sizeof *dm - (sizeof dm->options - 1 - (size_t)endloc);

    switch (srt) {
    case SRT_UnicastCi:   send_to(self->fd, dm, dmlen, self->dhcpmsg.ciaddr, 68); break;
    case SRT_Broadcast: {
        const struct in6_addr *broadcast = query_broadcast(self->ifindex);
        if (!broadcast) suicide("dhcp4: misconfigured -- must have a broadcast address\n");
        uint32_t bcaddr;
        memcpy(&bcaddr, ipaddr_v4_bytes(broadcast), sizeof bcaddr);
        send_to(self->fd, dm, dmlen, bcaddr, 68);
        break;
    }
    case SRT_Relay:       send_to(self->fd, dm, dmlen, self->dhcpmsg.giaddr, 67); break;
    case SRT_UnicastYiCh: send_to(self->fd, dm, dmlen, self->dhcpmsg.yiaddr, 68); break;
    }
}

static void send_reply(struct D4Listener *self, const struct dhcpmsg *reply)
{
    if      (self->dhcpmsg.giaddr)                 send_reply_do(self, reply, SRT_Relay);
    else if (self->dhcpmsg.ciaddr)                 send_reply_do(self, reply, SRT_UnicastCi);
    else if (ntohs(self->dhcpmsg.flags) & 0x8000u) send_reply_do(self, reply, SRT_Broadcast);
    else if (self->dhcpmsg.yiaddr)                 send_reply_do(self, reply, SRT_UnicastYiCh);
    else                                           send_reply_do(self, reply, SRT_Broadcast);
}

static bool iplist_option(struct dhcpmsg *reply, uint8_t code, const struct addrlist *ipl)
{
    char buf[256]; // max option size is 255 bytes
    size_t off = 0;
    for (size_t i = 0; i < ipl->n; ++i) {
        if (off + 4 >= sizeof buf) break; // silently drop if too many
        if (ipaddr_is_v4(&ipl->addrs[i])) {
            memcpy(buf + off, ipaddr_v4_bytes(&ipl->addrs[i]), 4);
            off += 4;
        }
    }
    buf[off] = 0;
    if (!off) return false;
    add_option_string(reply, code, buf, off);
    return true;
}

static struct in6_addr u32_ipaddr(uint32_t v)
{
    struct in6_addr ret;
    ipaddr_from_v4_bytes(&ret, &v);
    return ret;
}

static bool allot_dynamic_ip(struct D4Listener *self, struct dhcpmsg *reply, const uint8_t *hwaddr, bool do_assign)
{
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v4(self->ifindex, &dynamic_lifetime))
        return false;

    log_line("dhcp4: Checking dynamic IP.\n");

    struct in6_addr dr_lo, dr_hi;
    if (!query_dynamic_range(self->ifindex, &dr_lo, &dr_hi)) {
        log_line("dhcp4: No dynamic range is associated.  Can't assign an IP.\n");
        return false;
    }
    int64_t expire_time = get_current_ts() + dynamic_lifetime;

    struct in6_addr v4a = dynlease4_query_refresh(self->ifindex, hwaddr, expire_time);
    if (memcmp(&v4a, &in6addr_any, 16)) {
        if (!ipaddr_is_v4(&v4a)) {
            log_line("dhcp4: allot_dynamic_ip - bad address\n");
            return false;
        }
        memcpy(&reply->yiaddr, ipaddr_v4_bytes(&v4a), sizeof reply->yiaddr);
        add_u32_option(reply, DCODE_LEASET, htonl(dynamic_lifetime));
        char abuf[48] = "oom";
        ipaddr_to_string(abuf, sizeof abuf, &v4a);
        log_line("dhcp4: Assigned existing dynamic IP: %s\n", abuf);
        return true;
    }
    log_line("dhcp4: Selecting an unused dynamic IP.\n");

    // IP is randomly selected from the dynamic range.
    uint32_t al = decode32be(ipaddr_v4_bytes(&dr_lo));
    uint32_t ah = decode32be(ipaddr_v4_bytes(&dr_hi));
    uint64_t ar = ah > al ? ah - al : al - ah;
    // The extremely small distribution skew does not matter here.
    uint64_t rqs = nk_random_u64(&g_rngstate) % (ar + 1);

    // OK, here we have bisected our range using rqs.
    // [al .. ah] => [al .. rqs .. ah]
    // So we scan from [rqs, ah], taking the first empty slot.
    // If no success, scan from [al, rqs), taking the first empty slot.
    // If no success, then all IPs are taken, so return false.
    for (uint32_t i = al + rqs; i <= ah; ++i) {
        struct in6_addr iaddr = u32_ipaddr(htonl(i));
        bool matched = do_assign ? dynlease4_add(self->ifindex, &iaddr, hwaddr, expire_time)
                                 : dynlease4_exists(self->ifindex, &iaddr, hwaddr);
        if (matched) {
            reply->yiaddr = htonl(i);
            add_u32_option(reply, DCODE_LEASET, htonl(dynamic_lifetime));
            return true;
        }
    }
    for (uint32_t i = al; i < al + rqs; ++i) {
        struct in6_addr iaddr = u32_ipaddr(htonl(i));
        bool matched = do_assign ? dynlease4_add(self->ifindex, &iaddr, hwaddr, expire_time)
                                 : dynlease4_exists(self->ifindex, &iaddr, hwaddr);
        if (matched) {
            reply->yiaddr = htonl(i);
            add_u32_option(reply, DCODE_LEASET, htonl(dynamic_lifetime));
            return true;
        }
    }
    return false;
}

static bool create_reply(struct D4Listener *self, struct dhcpmsg *reply, const uint8_t *hwaddr, bool do_assign)
{
    const struct dhcpv4_entry *dv4s = query_dhcp4_state(self->ifindex, hwaddr);
    if (!dv4s) {
        if (!allot_dynamic_ip(self, reply, hwaddr, do_assign))
            return false;
    } else {
        memcpy(&reply->yiaddr, ipaddr_v4_bytes(&dv4s->address), sizeof reply->yiaddr);
        add_u32_option(reply, DCODE_LEASET, htonl(dv4s->lifetime));
    }
    const struct in6_addr *subnet = query_subnet(self->ifindex);
    if (!subnet) return false;
    uint32_t subnet_addr;
    memcpy(&subnet_addr, ipaddr_v4_bytes(subnet), sizeof subnet_addr);
    add_option_subnet_mask(reply, subnet_addr);

    const struct in6_addr *broadcast = query_broadcast(self->ifindex);
    if (!broadcast) return false;
    uint32_t broadcast_addr;
    memcpy(&broadcast_addr, ipaddr_v4_bytes(broadcast), sizeof broadcast_addr);
    add_option_broadcast(reply, broadcast_addr);

    const struct in6_addr *router = query_gateway_v4(self->ifindex);
    if (router) {
        uint32_t router_addr;
        memcpy(&router_addr, ipaddr_v4_bytes(router), sizeof router_addr);
        add_option_router(reply, router_addr);
    }

    struct addrlist dns_servers = query_dns_servers(self->ifindex);
    if (dns_servers.n) iplist_option(reply, DCODE_DNS, &dns_servers);

    struct addrlist ntp_servers = query_ntp_servers(self->ifindex);
    if (ntp_servers.n) iplist_option(reply, DCODE_NTPSVR, &ntp_servers);

    struct blob d4b = query_dns4_search_blob(self->ifindex);
    if (d4b.n && d4b.s) add_option_domain_name(reply, d4b.s, d4b.n);

    log_line("dhcp4: Sending reply %u.%u.%u.%u\n", reply->yiaddr & 255,
             (reply->yiaddr >> 8) & 255, (reply->yiaddr >> 16) & 255, (reply->yiaddr >> 24) & 255);

    return true;
}

static void reply_discover(struct D4Listener *self)
{
    struct dhcpmsg reply;
    dhcpmsg_init(self, &reply, DHCPOFFER, self->dhcpmsg.xid);
    if (create_reply(self, &reply, self->dhcpmsg.chaddr, true))
        send_reply(self, &reply);
}

static void reply_request(struct D4Listener *self)
{
    struct dhcpmsg reply;
    dhcpmsg_init(self, &reply, DHCPACK, self->dhcpmsg.xid);
    if (create_reply(self, &reply, self->dhcpmsg.chaddr, true)) {
        send_reply(self, &reply);
    }
    D4State_kill(self->map, self->dhcpmsg.chaddr);
}

static void reply_inform(struct D4Listener *self)
{
    struct dhcpmsg reply;
    dhcpmsg_init(self, &reply, DHCPACK, self->dhcpmsg.xid);
    if (create_reply(self, &reply, self->dhcpmsg.chaddr, false)) {
        // http://tools.ietf.org/html/draft-ietf-dhc-dhcpinform-clarify-06
        reply.htype = self->dhcpmsg.htype;
        reply.hlen = self->dhcpmsg.hlen;
        memcpy(&reply.chaddr, &self->dhcpmsg.chaddr, sizeof reply.chaddr);
        reply.ciaddr = self->dhcpmsg.ciaddr;
        // xid was already set equal
        reply.flags = self->dhcpmsg.flags;
        reply.hops = 0;
        reply.secs = 0;
        reply.yiaddr = 0;
        reply.siaddr = 0;
        if (self->dhcpmsg.ciaddr)
            send_reply_do(self, &reply, SRT_UnicastCi);
        else if (self->dhcpmsg.giaddr) {
            uint16_t fl = ntohs(reply.flags);
            reply.flags = htons(fl | 0x8000u);
            send_reply_do(self, &reply, SRT_Relay);
        } else
            send_reply_do(self, &reply, SRT_Broadcast);
    }
}

static void do_release(struct D4Listener *self)
{
    struct in6_addr ciaddr = u32_ipaddr(self->dhcpmsg.ciaddr);
    if (!dynlease4_exists(self->ifindex, &ciaddr, self->dhcpmsg.chaddr)) {
        char buf[32] = "invalid ip";
        ip4_to_string(buf, sizeof buf, self->dhcpmsg.ciaddr);
        log_line("dhcp4: do_release: ignoring spoofed release request for %s.\n", buf);
        return;
    }
    dynlease4_del(self->ifindex, &ciaddr, self->dhcpmsg.chaddr);
}

static uint8_t validate_dhcp(const struct D4Listener *self, size_t len)
{
    if (len < offsetof(struct dhcpmsg, options))
        return DHCPNULL;
    if (ntohl(self->dhcpmsg.cookie) != DHCP_MAGIC)
        return DHCPNULL;
    return get_option_msgtype(&self->dhcpmsg);
}

static void process_receive(struct D4Listener *self, const char *buf, size_t buflen,
                            const struct sockaddr_in *sai)
{
    if (sai->sin_family != AF_INET) return;
    size_t msglen = buflen < sizeof self->dhcpmsg ? buflen : sizeof self->dhcpmsg;
    self->dhcpmsg = (struct dhcpmsg){0};
    memcpy(&self->dhcpmsg, buf, msglen);
    uint8_t msgtype = validate_dhcp(self, msglen);
    if (!msgtype)
        return;

    uint8_t cs = D4State_get(self->map, self->dhcpmsg.xid, self->dhcpmsg.chaddr);
    if (cs == DHCPNULL) {
        switch (msgtype) {
        case DHCPREQUEST:
        case DHCPDISCOVER:
            cs = msgtype;
            if (!D4State_add(self->map, self->dhcpmsg.xid, self->dhcpmsg.chaddr, cs))
                return; // Possible DoS; silently drop.
            break;
        case DHCPINFORM:
            // No need to track state since we just INFORM => ACK
        case DHCPDECLINE:
        case DHCPRELEASE:
            cs = msgtype;
            break;
        default: return;
        }
    } else {
        if (cs == DHCPDISCOVER && msgtype == DHCPREQUEST)
            cs = DHCPREQUEST;
    }

    switch (cs) {
    case DHCPDISCOVER: reply_discover(self); break;
    case DHCPREQUEST:  reply_request(self); break;
    case DHCPINFORM:   reply_inform(self); break;
    case DHCPDECLINE:  log_line("dhcp4: Received a DHCPDECLINE.  Clients conflict?\n");
    case DHCPRELEASE:  do_release(self); break;
    }
}

