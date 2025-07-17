// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdbool.h>
#include <stdlib.h>
#include <net/if.h>
#include <ipaddr.h>
#include "nlsocket.h"
#include "multicast6.h"
#include "dhcp6.h"
#include "dynlease.h"
#include "attach_bpf.h"
#include "duid.h"
#include "sbufs.h"
#include <nk/netbits.h>
#include "dhcp_state.h"
#include "nk/log.h"
#include "nk/io.h"
#include "nk/random.h"
#include "get_current_ts.h"

#define MAX_DYN_LEASES 1000u
#define MAX_DYN_ATTEMPTS 100u
#define D6_MAX_IAS 4
#define D6_MAX_IA_ADDRS 4
#define D6_MAX_ENCAP_DEPTH 4

#define DHCP6_HEADER_SIZE 4
#define DHCP6_OPT_SIZE 4
#define DHCP6_IA_ADDR_SIZE 24
#define DHCP6_IA_NA_SIZE 12
#define OPT_STATUSCODE_SIZE 4

extern struct nk_random_state g_rngstate;
extern struct NLSocket nl_socket;

struct D6Listener
{
    struct in6_addr local_ip;
    struct in6_addr local_ip_prefix;
    struct in6_addr link_local_ip;
    char ifname[IFNAMSIZ];
    int ifindex;
    int fd;
    unsigned char prefixlen;
    uint8_t preference;
    bool using_bpf:1;
};

enum dhcp6_msgtype {
    D6_MSGTYPE_UNKNOWN = 0,
    D6_MSGTYPE_SOLICIT = 1,
    D6_MSGTYPE_ADVERTISE = 2,
    D6_MSGTYPE_REQUEST = 3,
    D6_MSGTYPE_CONFIRM = 4,
    D6_MSGTYPE_RENEW = 5,
    D6_MSGTYPE_REBIND = 6,
    D6_MSGTYPE_REPLY = 7,
    D6_MSGTYPE_RELEASE = 8,
    D6_MSGTYPE_DECLINE = 9,
    D6_MSGTYPE_RECONFIGURE = 10,
    D6_MSGTYPE_INFORMATION_REQUEST = 11,
    D6_MSGTYPE_RELAY_FORWARD = 12,
    D6_MSGTYPE_RELAY_REPLY = 13,
    D6_MSGTYPE_END = 14,
};
enum dhcp6_code {
    D6_CODE_SUCCESS = 0,
    D6_CODE_UNSPECFAIL = 1,
    D6_CODE_NOADDRSAVAIL = 2,
    D6_CODE_NOBINDING = 3,
    D6_CODE_NOTONLINK = 4,
    D6_CODE_USEMULTICAST = 5,
};

struct dhcp6_header
{
    uint8_t type;
    char xid[3];
};
struct dhcp6_ia_addr {
    struct in6_addr addr;
    uint32_t prefer_lifetime;
    uint32_t valid_lifetime;
};
struct dhcp6_ia_na {
    uint32_t iaid;
    uint32_t t1_seconds;
    uint32_t t2_seconds;
    size_t ia_na_addrs_n;
    struct dhcp6_ia_addr ia_na_addrs[D6_MAX_IA_ADDRS];
};

static enum dhcp6_msgtype dhcp6_header_msgtype(const struct dhcp6_header *self)
{
    return self->type >= 1 && self->type <= 13 ? (enum dhcp6_msgtype)self->type : D6_MSGTYPE_UNKNOWN;
}
static bool dhcp6_header_read(struct dhcp6_header *self, struct sbufs *rbuf)
{
    if (sbufs_brem(rbuf) < DHCP6_HEADER_SIZE) return false;
    memcpy(&self->type, rbuf->si, sizeof self->type);
    memcpy(&self->xid, rbuf->si + 1, sizeof self->xid);
    rbuf->si += DHCP6_HEADER_SIZE;
    return true;
}
static bool dhcp6_header_write(const struct dhcp6_header *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < DHCP6_HEADER_SIZE) return false;
    memcpy(sbuf->si, &self->type, sizeof self->type);
    memcpy(sbuf->si + 1, &self->xid, sizeof self->xid);
    sbuf->si += DHCP6_HEADER_SIZE;
    return true;
}

// Option header.
struct dhcp6_opt { uint8_t data_[4]; };
static uint16_t dhcp6_opt_type(const struct dhcp6_opt *self) { return decode16be(self->data_); }
static uint16_t dhcp6_opt_length(const struct dhcp6_opt *self) { return decode16be(self->data_ + 2); }
static struct dhcp6_opt dhcp6_opt_create(uint16_t type, uint16_t length) {
    struct dhcp6_opt ret;
    encode16be(ret.data_, type);
    encode16be(ret.data_ + 2, length);
    return ret;
}
static bool dhcp6_opt_read(struct dhcp6_opt *self, struct sbufs *rbuf)
{
    if (sbufs_brem(rbuf) < sizeof self->data_) return false;
    memcpy(&self->data_, rbuf->si, sizeof self->data_);
    rbuf->si += sizeof self->data_;
    return true;
}
static bool dhcp6_opt_write(const struct dhcp6_opt *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < sizeof self->data_) return false;
    memcpy(sbuf->si, self->data_, sizeof self->data_);
    sbuf->si += sizeof self->data_;
    return true;
}

// Server Identifier Option
struct dhcp6_opt_serverid
{
    const char *duid_string;
    size_t duid_len;
};
static struct dhcp6_opt_serverid dhcp6_opt_serverid_create(const char *s, size_t slen)
{
    return (struct dhcp6_opt_serverid){ .duid_string = s, .duid_len = slen };
}
static bool dhcp6_opt_serverid_write(const struct dhcp6_opt_serverid *self, struct sbufs *sbuf)
{
    const size_t size = DHCP6_OPT_SIZE + self->duid_len;
    if (sbufs_brem(sbuf) < size) return false;
    struct dhcp6_opt header = dhcp6_opt_create(2, self->duid_len);
    if (!dhcp6_opt_write(&header, sbuf)) return false;
    memcpy(sbuf->si, self->duid_string, self->duid_len);
    sbuf->si += self->duid_len;
    return true;
}

static bool dhcp6_ia_addr_read(struct dhcp6_ia_addr *self, struct sbufs *rbuf)
{
    if (sbufs_brem(rbuf) < DHCP6_IA_ADDR_SIZE) return false;
    memcpy(&self->addr, rbuf->si, sizeof self->addr);
    self->prefer_lifetime = 0; // RFC8415 S25
    self->valid_lifetime = 0; // RFC8415 S25
    rbuf->si += DHCP6_IA_ADDR_SIZE;
    return true;
}
static bool dhcp6_ia_addr_write(const struct dhcp6_ia_addr *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < DHCP6_IA_ADDR_SIZE) return false;
    memcpy(sbuf->si, &self->addr, sizeof self->addr);
    encode32be(sbuf->si + 16, self->prefer_lifetime);
    encode32be(sbuf->si + 20, self->valid_lifetime);
    sbuf->si += DHCP6_IA_ADDR_SIZE;
    return true;
}

static bool dhcp6_ia_na_read(struct dhcp6_ia_na *self, struct sbufs *rbuf)
{
    if (sbufs_brem(rbuf) < DHCP6_IA_NA_SIZE) return false;
    self->iaid = decode32be(rbuf->si);
    self->t1_seconds = 0; // RFC8415 S25
    self->t2_seconds = 0; // RFC8415 S25
    rbuf->si += DHCP6_IA_NA_SIZE;
    return true;
}
static bool dhcp6_ia_na_write(const struct dhcp6_ia_na *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < DHCP6_IA_NA_SIZE) return false;
    encode32be(sbuf->si, self->iaid);
    encode32be(sbuf->si + 4, self->t1_seconds);
    encode32be(sbuf->si + 8, self->t2_seconds);
    sbuf->si += DHCP6_IA_NA_SIZE;
    return true;
}

static struct in6_addr mask_v6_addr(const struct in6_addr *addr, uint8_t mask)
{
    struct in6_addr ret;
    uint8_t b[16];
    memcpy(b, addr, sizeof b);
    unsigned keep_bytes = mask / 8u;
    unsigned keep_r_bits = mask % 8u;
    b[keep_bytes] &= ~(0xffu >> keep_r_bits);
    for (unsigned i = keep_bytes + 1; i < 16; ++i) b[i] = 0u;
    memcpy(&ret, b, sizeof ret);
    return ret;
}
static struct in6_addr v6_addr_random(const struct in6_addr *prefix, uint8_t prefixlen)
{
    struct in6_addr ret;
    uint8_t b[16];
    memcpy(b, prefix, sizeof b);
    unsigned keep_bytes = prefixlen / 8u;
    unsigned keep_r_bits = prefixlen % 8u;
    unsigned i = 15;
    for (; i > keep_bytes; --i) b[i] = nk_random_u64(&g_rngstate);
    uint8_t c = nk_random_u64(&g_rngstate);
    b[i] |= c & (0xff >> keep_r_bits);
    memcpy(&ret, b, sizeof ret);
    return ret;
}

struct d6msg_state
{
    struct dhcp6_header header;
    char client_duid_str[320];
    char client_duid_blob[128];
    char server_duid_blob[128];
    struct dhcp6_ia_na ias[D6_MAX_IAS];
    uint8_t prev_opt_code[D6_MAX_ENCAP_DEPTH];
    uint16_t prev_opt_remlen[D6_MAX_ENCAP_DEPTH];
    size_t ias_n;
    size_t prev_opt_n;
    size_t client_duid_str_size;
    size_t client_duid_blob_size;
    size_t server_duid_blob_size;
    uint16_t elapsed_time;

    bool optreq_exists:1;
    bool optreq_dns:1;
    bool optreq_dns_search:1;
    bool optreq_sntp:1;
    bool optreq_info_refresh_time:1;
    bool optreq_ntp:1;

    bool use_rapid_commit:1;
};

static bool create_dhcp6_socket(struct D6Listener *self)
{
    struct in6_addr mc6_alldhcp_ras;
    struct sockaddr_in6 sai = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(547),
    };
    self->fd = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP);
    if (self->fd < 0) {
        log_line("dhcp6: Failed to create v6 UDP socket on %s: %s\n", self->ifname, strerror(errno));
        goto err0;
    }
    if (!ipaddr_from_string(&mc6_alldhcp_ras, "ff02::1:2")) goto err1;
    if (!attach_multicast_in6_addr(self->fd, self->ifname, &mc6_alldhcp_ras)) goto err1;
    self->using_bpf = attach_bpf_dhcp6_info(self->fd, self->ifname);

    if (bind(self->fd, (const struct sockaddr *)&sai, sizeof sai)) {
        log_line("dhcp6: Failed to bind to UDP 547 on %s: %s\n", self->ifname, strerror(errno));
        goto err1;
    }

    return true;
err1:
    close(self->fd);
    self->fd = -1;
err0:
    return false;
}

struct D6Listener *D6Listener_create(const char *ifname, const struct netif_info *ifinfo, uint8_t preference)
{
    struct D6Listener *self;
    size_t ifname_src_size = strlen(ifname);
    if (ifname_src_size >= sizeof self->ifname) {
        log_line("D6Listener: Interface name (%s) too long\n", ifname);
        return NULL;
    }
    if (!ifinfo->has_v6_address_global || !ifinfo->has_v6_address_link) {
        log_line("dhcp6: Failed to get ip address for %s\n", ifname);
        return NULL;
    }
    self = calloc(1, sizeof(struct D6Listener));
    if (!self) return NULL;

    self->ifindex = ifinfo->index;
    self->using_bpf = false;
    self->preference = preference;
    *(char *)(mempcpy(self->ifname, ifname, ifname_src_size)) = 0;
    self->local_ip = ifinfo->v6_address_global;
    self->prefixlen = ifinfo->v6_prefixlen_global;
    self->link_local_ip = ifinfo->v6_address_link;
    self->local_ip_prefix = mask_v6_addr(&self->local_ip, self->prefixlen);

    if (!create_dhcp6_socket(self)) goto err;

    char abuf[48];
    char abufp[48];
    if (!ipaddr_to_string(abuf, sizeof abuf, &self->local_ip)) abort();
    if (!ipaddr_to_string(abufp, sizeof abufp, &self->local_ip_prefix)) abort();
    log_line("dhcp6: IP address for %s is %s/%u.  Prefix is %s.\n",
             ifname, abuf, +self->prefixlen, abufp);
    if (!ipaddr_to_string(abuf, sizeof abuf, &self->link_local_ip)) abort();
    log_line("dhcp6: Link-local IP address for %s is %s.\n", ifname, abuf);
    log_line("dhcp6: DHCPv6 Preference is %u on %s\n", self->preference, self->ifname);

    return self;
err:
    free(self);
    return NULL;
}

void D6Listener_destroy(struct D6Listener *self)
{
    close(self->fd);
    free(self);
}

static const char *dhcp6_msgtype_to_string(enum dhcp6_msgtype m)
{
    static const char *pp[] = {
        "unknown",
        "solicit",
        "advertise",
        "request",
        "confirm",
        "renew",
        "rebind",
        "reply",
        "release",
        "decline",
        "reconfigure",
        "information_request",
        "relay_forward",
        "relay_reply",
    };
    return pp[m < D6_MSGTYPE_END && m >= 0 ? m : 0];
}

static bool dhcp6_statuscode_write(struct sbufs *ss, enum dhcp6_code status_code)
{
    if (sbufs_brem(ss) < sizeof(uint16_t)) return false;
    encode16be(ss->si, (uint16_t)status_code);
    ss->si += sizeof(uint16_t);
    return true;
}

static bool attach_status_code(struct sbufs *ss, enum dhcp6_code scode)
{
    static const char ok_str[] = "OK";
    static const char nak_str[] = "NO";
    struct dhcp6_opt header = dhcp6_opt_create(13, OPT_STATUSCODE_SIZE);
    if (!dhcp6_opt_write(&header, ss)) return false;
    if (!dhcp6_statuscode_write(ss, scode)) return false;
    const char *rstr = scode == D6_CODE_SUCCESS ? ok_str : nak_str;
    for (int i = 0; rstr[i]; ++i) {
        if (ss->si == ss->se) return false;
        *ss->si++ = rstr[i];
    }
    return true;
}

static bool emit_IA_code(struct sbufs *ss, uint32_t iaid, enum dhcp6_code scode)
{
    struct dhcp6_opt header = dhcp6_opt_create(3, DHCP6_IA_NA_SIZE + DHCP6_OPT_SIZE + OPT_STATUSCODE_SIZE);
    if (!dhcp6_opt_write(&header, ss)) return false;
    struct dhcp6_ia_na ia_na = {
        .iaid = iaid,
        .t1_seconds = 0,
        .t2_seconds = 0,
    };
    if (!dhcp6_ia_na_write(&ia_na, ss)) return false;
    if (!attach_status_code(ss, scode)) return false;
    return true;
}

// We control what IAs are valid, and we never assign multiple address to a single
// IA.  Thus there's no reason to care about that case.
static bool emit_IA_addr(struct sbufs *ss, struct in6_addr ipa, uint32_t iaid, uint32_t lifetime)
{
    struct dhcp6_opt header = dhcp6_opt_create(3, DHCP6_IA_NA_SIZE + DHCP6_OPT_SIZE + DHCP6_IA_ADDR_SIZE);
    if (!dhcp6_opt_write(&header, ss)) return false;
    struct dhcp6_ia_na ia_na = {
        .iaid = iaid,
        .t1_seconds = (uint32_t)(lifetime / 2),
        .t2_seconds = (uint32_t)(lifetime - lifetime / 5),
    };
    if (!dhcp6_ia_na_write(&ia_na, ss)) return false;
    header = dhcp6_opt_create(5, DHCP6_IA_ADDR_SIZE);
    if (!dhcp6_opt_write(&header, ss)) return false;
    struct dhcp6_ia_addr addr = {
        .addr = ipa,
        .prefer_lifetime = lifetime,
        .valid_lifetime = lifetime,
    };
    if (!dhcp6_ia_addr_write(&addr, ss)) return false;
    return true;
}

static bool allot_dynamic_ip(struct D6Listener *self, const char *client_duid, size_t client_duid_size,
                             struct sbufs *ss, uint32_t iaid,
                             enum dhcp6_code failcode, bool *use_dynamic)
{
    uint32_t dynamic_lifetime;
    if (!query_use_dynamic_v6(self->ifindex, &dynamic_lifetime)) {
        if (!emit_IA_code(ss, iaid, failcode)) return false;
        *use_dynamic = false;
        return true;
    }

    log_line("dhcp6: Checking dynamic IP on %s...\n", self->ifname);

    int64_t expire_time = get_current_ts() + dynamic_lifetime;

    struct in6_addr v6a = dynlease6_query_refresh(self->ifindex, client_duid, client_duid_size, iaid, expire_time);
    if (memcmp(&v6a, &in6addr_any, sizeof v6a)) {
        if (!emit_IA_addr(ss, v6a, iaid, dynamic_lifetime)) return false;
        char abuf[48];
        if (!ipaddr_to_string(abuf, sizeof abuf, &v6a)) abort();
        log_line("dhcp6: Assigned existing dynamic IP (%s) on %s\n", abuf, self->ifname);
        *use_dynamic = true;
        return true;
    }
    // This check guards against OOM via DoS.
    if (dynlease6_count(self->ifindex) >= MAX_DYN_LEASES) {
        log_line("dhcp6: Maximum number of dynamic leases (%u) reached on %s\n",
                 MAX_DYN_LEASES, self->ifname);
        if (!emit_IA_code(ss, iaid, failcode)) return false;
        *use_dynamic = false;
        return true;
    }
    log_line("dhcp6: Selecting an unused dynamic IP on %s\n", self->ifname);

    // Given a prefix, choose a random address.  Then check it against our
    // existing static and dynamic leases.  If no collision, assign a
    // dynamic lease to the random address and return it.
    for (unsigned attempt = 0; attempt < MAX_DYN_ATTEMPTS; ++attempt) {
        v6a = v6_addr_random(&self->local_ip_prefix, self->prefixlen);
        if (!query_unused_addr_v6(self->ifindex, &v6a)) continue;
        bool assigned = dynlease6_add(self->ifindex, &v6a, client_duid,
                                      client_duid_size, iaid, expire_time);
        if (assigned) {
            if (!emit_IA_addr(ss, v6a, iaid, dynamic_lifetime)) return false;
            *use_dynamic = true;
            return true;
        }
    }
    log_line("dhcp6: Unable to select an unused dynamic IP after %u attempts on %s\n",
             MAX_DYN_ATTEMPTS, self->ifname);
    if (!emit_IA_code(ss, iaid, failcode)) return false;
    *use_dynamic = false;
    return true;
}

static bool write_response_header(struct D6Listener *self, const struct d6msg_state *d6s, struct sbufs *ss,
                                  enum dhcp6_msgtype mtype)
{
    struct dhcp6_header send_d6hdr = d6s->header; // to copy the xid
    send_d6hdr.type = mtype;
    if (!dhcp6_header_write(&send_d6hdr, ss)) return false;

    struct dhcp6_opt_serverid send_serverid = dhcp6_opt_serverid_create(g_server_duid, sizeof g_server_duid);
    if (!dhcp6_opt_serverid_write(&send_serverid, ss)) return false;

    if (d6s->client_duid_blob_size == 0 ||
        (ptrdiff_t)d6s->client_duid_blob_size > ss->se - ss->si) return false;
    struct dhcp6_opt send_clientid = dhcp6_opt_create(1, d6s->client_duid_blob_size);
    if (!dhcp6_opt_write(&send_clientid, ss)) return false;
    memcpy(ss->si, d6s->client_duid_blob, d6s->client_duid_blob_size);
    ss->si += d6s->client_duid_blob_size;

    if (self->preference > 0) {
        struct dhcp6_opt send_pref = dhcp6_opt_create(7, 1);
        if (!dhcp6_opt_write(&send_pref, ss)) return false;
        if (ss->si == ss->se) return false;
        *ss->si++ = (char)self->preference;
    }
    return true;
}

// Returns false if no addresses would be assigned.
static bool attach_address_info(struct D6Listener *self, const struct d6msg_state *d6s, struct sbufs *ss,
                                enum dhcp6_code failcode, bool *has_addrs)
{
    bool ha = false;
    // Look through IAs and send IA with assigned address as an option.
    for (size_t i = 0; i < d6s->ias_n; ++i) {
        log_line("dhcp6: Querying duid='%s' iaid=%u...\n", d6s->client_duid_str, d6s->ias[i].iaid);
        const struct dhcpv6_entry *x = query_dhcp6_state(self->ifindex, d6s->client_duid_str,
                                                         d6s->client_duid_str_size, d6s->ias[i].iaid);
        if (x) {
            ha = true;
            char abuf[48];
            if (!ipaddr_to_string(abuf, sizeof abuf, &x->address)) abort();
            log_line("dhcp6: Found static address %s on %s\n", abuf, self->ifname);
            if (!emit_IA_addr(ss, x->address, x->iaid, x->lifetime)) return false;
            continue;
        }
        bool use_dynamic;
        if (!allot_dynamic_ip(self, d6s->client_duid_str, d6s->client_duid_str_size,
                              ss, d6s->ias[i].iaid, failcode, &use_dynamic)) return false;
        if (use_dynamic) ha = true;
    }
    if (!ha) log_line("dhcp6: Unable to assign any IPs on %s!\n", self->ifname);
    if (has_addrs) *has_addrs = ha;
    return true;
}

// If opt_req.size() == 0 then send DnsServers, DomainList,
// and NtpServer.  Otherwise, for each of these types,
// see if it is in the opt_req before adding it to the reply.
static bool attach_dns_ntp_info(struct D6Listener *self, const struct d6msg_state *d6s, struct sbufs *ss)
{
    struct addrlist dns_servers = query_dns_servers(self->ifindex);
    if (!dns_servers.n) return true;

    if (d6s->optreq_dns && dns_servers.n) {
        size_t siz = dns_servers.n * 16;
        if (ss->se - ss->si < (ptrdiff_t)(siz + 4)) return false;
        struct dhcp6_opt send_dns = dhcp6_opt_create(23, siz);
        if (!dhcp6_opt_write(&send_dns, ss)) abort();
        memcpy(ss->si, dns_servers.addrs, siz);
        ss->si += siz;
    }
    struct blob d6b = query_dns6_search_blob(self->ifindex);
    if (d6s->optreq_dns_search && (d6b.s && d6b.n)) {
        struct dhcp6_opt send_dns_search = dhcp6_opt_create(24, d6b.n);
        if (!dhcp6_opt_write(&send_dns_search, ss)) return false;
        if (ss->se - ss->si < (ptrdiff_t)d6b.n) return false;
        memcpy(ss->si, d6b.s, d6b.n);
        ss->si += d6b.n;
    }
    struct addrlist ntp_servers = query_ntp_servers(self->ifindex);
    if (d6s->optreq_ntp && ntp_servers.n) {
        size_t siz = ntp_servers.n * 20;
        if (ss->se - ss->si < (ptrdiff_t)(siz + 4)) return false;
        struct dhcp6_opt send_ntp = dhcp6_opt_create(56, siz);
        if (!dhcp6_opt_write(&send_ntp, ss)) abort();
        for (size_t i = 0; i < ntp_servers.n; ++i) {
            struct dhcp6_opt n6_svr = dhcp6_opt_create(1, 16);
            if (!dhcp6_opt_write(&n6_svr, ss)) abort();
            memcpy(ss->si, &ntp_servers.addrs[i], 16);
            ss->si += 16;
        }
    }
    if (d6s->optreq_sntp) {
        size_t siz = ntp_servers.n * 16;
        if (ss->se - ss->si < (ptrdiff_t)(siz + 4)) return false;
        struct dhcp6_opt send_sntp = dhcp6_opt_create(31, siz);
        if (!dhcp6_opt_write(&send_sntp, ss)) abort();
        memcpy(ss->si, ntp_servers.addrs, siz);
        ss->si += siz;
    }
    return true;
}

static bool confirm_match(struct D6Listener *self, const struct d6msg_state *d6s, bool *confirmed)
{
    *confirmed = false;
    if (!d6s->ias_n) return false;
    for (size_t i = 0; i < d6s->ias_n; ++i) {
        log_line("dhcp6: Confirming match for duid='%s' iaid=%u...\n", d6s->client_duid_str, d6s->ias[i].iaid);
        if (!d6s->ias[i].ia_na_addrs_n) return false; // See RFC8415 18.3.3 p3
        for (size_t j = 0; j < d6s->ias[i].ia_na_addrs_n; ++j) {
            if (!ipaddr_compare_masked(&d6s->ias[i].ia_na_addrs[j].addr, &self->local_ip_prefix, self->prefixlen)) {
                char abuf[48];
                if (!ipaddr_to_string(abuf, sizeof abuf, &d6s->ias[i].ia_na_addrs[j].addr)) abort();
                log_line("dhcp6: Invalid prefix for IA IP %s on %s. NAK.\n", abuf, self->ifname);
                return true;
            } else {
                log_line("dhcp6: IA iaid=%u has a valid prefix on %s\n", d6s->ias[i].iaid, self->ifname);
            }
        }
    }
    *confirmed = true;
    return true;
}

static bool mark_addr_unused(struct D6Listener *self, const struct d6msg_state *d6s, struct sbufs *ss)
{
    for (size_t i = 0; i < d6s->ias_n; ++i) {
        bool freed_ia_addr = false;
        log_line("dhcp6: Marking duid='%s' iaid=%u unused on %s...\n",
                 d6s->client_duid_str, d6s->ias[i].iaid, self->ifname);
        const struct dhcpv6_entry *x = query_dhcp6_state(self->ifindex, d6s->client_duid_str,
                                                         d6s->client_duid_str_size, d6s->ias[i].iaid);
        for (size_t j = 0; j < d6s->ias[i].ia_na_addrs_n; ++j) {
            if (x && !memcmp(&d6s->ias[i].ia_na_addrs[j].addr, &x->address, 16)) {
                log_line("dhcp6: found static lease on %s\n", self->ifname);
                freed_ia_addr = true;
            } else if (dynlease6_del(self->ifindex, &d6s->ias[i].ia_na_addrs[j].addr, d6s->client_duid_str,
                                     d6s->client_duid_str_size, d6s->ias[i].iaid)) {
                log_line("dhcp6: found dynamic lease on %s\n", self->ifname);
                freed_ia_addr = true;
            }
        }
        if (!freed_ia_addr) {
            if (!emit_IA_code(ss, d6s->ias[i].iaid, D6_CODE_NOBINDING)) return false;
            log_line("dhcp6: no dynamic lease found on %s\n", self->ifname);
        }
    }
    return true;
}

#define OPTIONS_CONSUME(BLD_VAL) do {                                   \
        if (!options_consume(&d6s, (BLD_VAL), self->ifname)) return;   \
    } while (0)

static bool options_consume(struct d6msg_state *d6s, size_t v, const char *ifname)
{
    size_t nempty = 0;
    for (size_t i = 0; i < d6s->prev_opt_n; ++i) {
        if (d6s->prev_opt_remlen[i] < v) {
            log_line("dhcp6: Received malformed message on %s\n", ifname);
            return false; // option_depth would underflow
        }
        d6s->prev_opt_remlen[i] -= v;
        if (d6s->prev_opt_remlen[i] == 0) ++nempty;
    }
    assert(nempty <= d6s->prev_opt_n);
    d6s->prev_opt_n -= nempty;
    return true;
}

static bool serverid_incorrect(const struct d6msg_state *d6s)
{
    return d6s->server_duid_blob_size != sizeof g_server_duid
        || memcmp(d6s->server_duid_blob, g_server_duid, sizeof g_server_duid);
}

static void process_receive(struct D6Listener *self, char *buf, size_t buflen,
                            const struct sockaddr_in6 *sai)
{
    if (sai->sin6_family != AF_INET6) return;

    char ip[32];
    struct sbufs rs = { buf, buf + buflen };
    if (!self->using_bpf && buflen < DHCP6_HEADER_SIZE) {
        // Discard if the DHCP6 length < the size of a DHCP6 header.
        ipaddr_to_string(ip, sizeof ip, &sai->sin6_addr);
        log_line("dhcp6: Packet from %s is too short (%zu) on %s\n", ip, buflen, self->ifname);
        return;
    }

    struct d6msg_state d6s = {0};
    if (!dhcp6_header_read(&d6s.header, &rs)) {
        ipaddr_to_string(ip, sizeof ip, &sai->sin6_addr);
        log_line("dhcp6: Packet from %s has no valid option headers on %s\n", ip, self->ifname);
        return;
    }
    OPTIONS_CONSUME(DHCP6_HEADER_SIZE);

    enum dhcp6_msgtype msgtype = dhcp6_header_msgtype(&d6s.header);
    log_line("dhcp6: Message (%s) on %s\n", dhcp6_msgtype_to_string(msgtype), self->ifname);

    // These message types are not allowed to be sent to servers.
    if (!self->using_bpf) {
        switch (d6s.header.type) {
        case D6_MSGTYPE_ADVERTISE:
        case D6_MSGTYPE_REPLY:
        case D6_MSGTYPE_RECONFIGURE:
        case D6_MSGTYPE_RELAY_REPLY:
            return;
        default: break;
        }
    }

    while (sbufs_brem(&rs) >= 4) {
         struct dhcp6_opt opt;
         if (!dhcp6_opt_read(&opt, &rs)) return;
         OPTIONS_CONSUME(DHCP6_OPT_SIZE);
         uint16_t l = dhcp6_opt_length(&opt);
         uint16_t ot = dhcp6_opt_type(&opt);

         if (l > sbufs_brem(&rs)) {
             log_debug("dhcp6: Option is too long on %s\n", self->ifname);
             return;
         }

         if (ot == 1) { // ClientID
             if (l > sizeof d6s.client_duid_blob) return;
             d6s.client_duid_blob_size = l;
             memcpy(d6s.client_duid_blob, rs.si, l);
             rs.si += l;
             OPTIONS_CONSUME(l);
             for (size_t j = 0; j < d6s.client_duid_blob_size; ++j) {
                 snprintf(d6s.client_duid_str + 2 * j, sizeof d6s.client_duid_str - 2 * j,
                          "%.2hhx", (uint8_t)d6s.client_duid_blob[j]);
                 d6s.client_duid_str_size += 2;
             }
         } else if (ot == 2) { // ServerID
             if (l > sizeof d6s.server_duid_blob) return;
             d6s.server_duid_blob_size = l;
             memcpy(d6s.server_duid_blob, rs.si, l);
             rs.si += l;
             OPTIONS_CONSUME(l);
         } else if (ot == 3) { // Option_IA_NA
             if (l < 12) {
                 log_debug("dhcp6: Client-sent option IA_NA has a bad length on %s\n", self->ifname);
                 return;
             }
             if (d6s.ias_n >= D6_MAX_IAS) {
                 log_debug("dhcp6: Client sent too many >(%zu) IA_NA options on %s\n",
                           d6s.ias_n, self->ifname);
                 return;
             }
             if (!dhcp6_ia_na_read(&d6s.ias[d6s.ias_n], &rs)) return;
             OPTIONS_CONSUME(DHCP6_IA_NA_SIZE);
             ++d6s.ias_n;

             int na_options_len = l - 12;
             if (na_options_len > 0) {
                 if (d6s.prev_opt_n >= D6_MAX_ENCAP_DEPTH) {
                     log_line("dhcp6: Client sent too deep >(%zu) of option encapsulation on %s\n",
                              d6s.prev_opt_n, self->ifname);
                     return;
                 }
                 d6s.prev_opt_code[d6s.prev_opt_n] = 3;
                 d6s.prev_opt_remlen[d6s.prev_opt_n++] = na_options_len;
             }
         } else if (ot == 5) { // Address
             if (l < 24) {
                 log_debug("dhcp6: Client-sent option IAADDR has a bad length (%u) on %s\n", l, self->ifname);
                 return;
             }
             if (d6s.prev_opt_n != 1) {
                 log_debug("dhcp6: Client-sent option IAADDR is not nested on %s\n", self->ifname);
                 return;
             }
             if (d6s.prev_opt_code[0] != 3) {
                 log_debug("dhcp6: Client-sent option IAADDR must follow IA_NA on %s\n", self->ifname);
                 return;
             }
             if (!d6s.ias_n) {
                 log_debug("dhcp6: d6.ias is empty on %s\n", self->ifname);
                 return;
             }
             size_t niana = d6s.ias[d6s.ias_n - 1].ia_na_addrs_n;
             if (d6s.ias[d6s.ias_n - 1].ia_na_addrs_n >= D6_MAX_IA_ADDRS) {
                 log_line("dhcp6: Client sent too many >(%zu) IA_NA addresses on %s\n",
                          niana, self->ifname);
                 return;
             }
             if (!dhcp6_ia_addr_read(&d6s.ias[d6s.ias_n - 1].ia_na_addrs[niana], &rs)) return;
             OPTIONS_CONSUME(DHCP6_IA_ADDR_SIZE);

             int iaa_options_len = l - DHCP6_IA_ADDR_SIZE;
             if (iaa_options_len > 0) {
                 d6s.prev_opt_code[d6s.prev_opt_n] = 5;
                 d6s.prev_opt_remlen[d6s.prev_opt_n++] = iaa_options_len;
             }
             d6s.ias[d6s.ias_n - 1].ia_na_addrs_n++;
         } else if (ot == 6) { // OptionRequest
             if (l % 2) {
                 log_debug("dhcp6: Client-sent option Request has a bad length (%d) on %s\n", l, self->ifname);
                 return;
             }
             d6s.optreq_exists = true;
             l /= 2;
             while (l--) {
                 uint16_t v = decode16be(rs.si); rs.si += 2;
                 OPTIONS_CONSUME(2);
                 switch (v) {
                 case 23: d6s.optreq_dns = true; break;
                 case 24: d6s.optreq_dns_search = true; break;
                 case 31: d6s.optreq_sntp = true; break;
                 case 32: d6s.optreq_info_refresh_time = true; break;
                 case 56: d6s.optreq_ntp = true; break;
                 default: break;
                 }
             }
         } else if (ot == 8) { // ElapsedTime
             // 16-bit hundreths of a second since start of exchange
             if (l != 2) {
                 log_debug("dhcp6: Client-sent option ElapsedTime has a bad length on %s\n", self->ifname);
                 return;
             }
             d6s.elapsed_time = decode16be(rs.si); rs.si += 2;
             OPTIONS_CONSUME(2);
         } else if (ot == 14) { // Rapid Commit
             if (l != 0) {
                 log_debug("dhcp6: Client-sent option Rapid Commit has a bad length on %s\n", self->ifname);
                 return;
             }
             d6s.use_rapid_commit = true;
         } else if (ot == 39) { // Client FQDN
             if (l < 3) {
                 log_debug("dhcp6: Client-sent option Client FQDN has a bad length on %s\n", self->ifname);
                 return;
             }
             uint8_t flags = (uint8_t)*rs.si++;
             uint8_t namelen = (uint8_t)*rs.si++;
             OPTIONS_CONSUME(2);
             l -= 2;
             if (l != namelen) {
                 log_debug("dhcp6: Client-sent option Client FQDN namelen disagrees with length on %s\n", self->ifname);
                 return;
             }
             log_line("dhcp6: Client FQDN: flags='%u' '%.*s' on %s\n", flags, namelen, rs.si, self->ifname);
             rs.si += l;
             OPTIONS_CONSUME(l);
         } else {
             rs.si += l;
             OPTIONS_CONSUME(l);
         }
     }

     if (!d6s.optreq_exists) {
         // These message types MUST include Option Request (cf. RFC 8415 21.27)
         switch (d6s.header.type) {
         case D6_MSGTYPE_SOLICIT:
         case D6_MSGTYPE_REQUEST:
         case D6_MSGTYPE_RENEW:
         case D6_MSGTYPE_REBIND:
         case D6_MSGTYPE_INFORMATION_REQUEST:
             log_line("Client sent invalid %s -- no Option Request is present\n", dhcp6_msgtype_to_string(msgtype));
             return;
         default: break;
         }
     }

     char sbuf[4096];
     struct sbufs ss = { &sbuf[0], &sbuf[4096] };

     // Clients are required to send a client identifier.
     if (!d6s.client_duid_str_size && msgtype != D6_MSGTYPE_INFORMATION_REQUEST) {
         return;
     }

     switch (msgtype) {
     case D6_MSGTYPE_SOLICIT: {
         if (d6s.server_duid_blob_size) return;
         if (!write_response_header(self, &d6s, &ss,
                                    !d6s.use_rapid_commit ? D6_MSGTYPE_ADVERTISE
                                    : D6_MSGTYPE_REPLY)) return;

         // RFC7550 says servers MUST NOT return top-level Status Code noaddrsavail.
         bool valid;
         if (!attach_address_info(self, &d6s, &ss, D6_CODE_NOADDRSAVAIL, &valid)) return;
         if (!attach_dns_ntp_info(self, &d6s, &ss)) return;

         if (valid && d6s.use_rapid_commit) {
             struct dhcp6_opt rapid_commit = dhcp6_opt_create(14, 0);
             if (!dhcp6_opt_write(&rapid_commit, &ss)) return;
         }
         break;
     }
     case D6_MSGTYPE_CONFIRM:
         if (d6s.server_duid_blob_size) return;
         if (!write_response_header(self, &d6s, &ss, D6_MSGTYPE_REPLY)) return;
         bool confirmed;
         if (!confirm_match(self, &d6s, &confirmed)) return;
         if (!attach_status_code(&ss, confirmed ? D6_CODE_SUCCESS
                                               : D6_CODE_NOTONLINK)) return;
         if (!attach_dns_ntp_info(self, &d6s, &ss)) return;
         break;
     case D6_MSGTYPE_REQUEST:
     case D6_MSGTYPE_RENEW:
         if (serverid_incorrect(&d6s)) return;
         if (!write_response_header(self, &d6s, &ss, D6_MSGTYPE_REPLY)) return;
         if (!attach_address_info(self, &d6s, &ss, msgtype == D6_MSGTYPE_RENEW
                                  ? D6_CODE_NOBINDING
                                  : D6_CODE_NOADDRSAVAIL, NULL)) return;
         if (!attach_dns_ntp_info(self, &d6s, &ss)) return;
         break;
     case D6_MSGTYPE_REBIND:
         if (d6s.server_duid_blob_size) return;
         if (!write_response_header(self, &d6s, &ss, D6_MSGTYPE_REPLY)) return;
         if (!attach_address_info(self, &d6s, &ss, D6_CODE_NOBINDING, NULL)) return;
         if (!attach_dns_ntp_info(self, &d6s, &ss)) return;
         break;
     case D6_MSGTYPE_RELEASE:
     case D6_MSGTYPE_DECLINE:
         if (serverid_incorrect(&d6s)) return;
         if (!write_response_header(self, &d6s, &ss, D6_MSGTYPE_REPLY)) return;
         if (!mark_addr_unused(self, &d6s, &ss)) return;
         break;
     case D6_MSGTYPE_INFORMATION_REQUEST:
         if (d6s.server_duid_blob_size && serverid_incorrect(&d6s)) return;
         if (!d6s.ias_n) return;
         if (!write_response_header(self, &d6s, &ss, D6_MSGTYPE_REPLY)) return;
         if (!attach_dns_ntp_info(self, &d6s, &ss)) return;
         log_line("dhcp6: Sending Information Message in response on %s\n", self->ifname);
         break;
     default: return;
     }

     struct sockaddr_in6 sao;
     memcpy(&sao, sai, sizeof sao);
     sao.sin6_port = htons(546);
     size_t slen = ss.si > sbuf ? (size_t)(ss.si - sbuf) : 0;
     if (safe_sendto(self->fd, sbuf, slen, 0, (const struct sockaddr *)&sao, sizeof sao) < 0) {
         ipaddr_to_string(ip, sizeof ip, &sai->sin6_addr);
         log_line("dhcp6: sendto (%s) failed on %s: %s\n", ip, self->ifname, strerror(errno));
         return;
     }
}

void D6Listener_process_input(struct D6Listener *self)
{
    char buf[8192];
    for (;;) {
        struct sockaddr_in6 sai;
        socklen_t sailen = sizeof sai;
        ssize_t buflen = recvfrom(self->fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&sai, &sailen);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("dhcp6: recvfrom failed on %s: %s\n", self->ifname, strerror(err));
        }
        process_receive(self, buf, (size_t)buflen, &sai);
    }
}

int D6Listener_fd(const struct D6Listener *self) { return self->fd; }
