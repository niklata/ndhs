// Copyright 2014-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <net/if.h>
#include <sys/socket.h>

#include <nk/netbits.h>
#include "radv6.h"
#include "nlsocket.h"
#include "dhcp6.h"
#include "multicast6.h"
#include "attach_bpf.h"
#include "sbufs.h"
#include "dhcp_state.h"
#include "nk/net_checksum16.h"
#include "nk/log.h"
#include "nk/io.h"
#include "nk/random.h"

extern struct nk_random_state g_rngstate;

struct RA6Listener
{
    struct timespec advert_ts_;
    char ifname_[IFNAMSIZ];
    int ifindex;
    int fd_;
    unsigned advi_s_max_;
    bool using_bpf_:1;
};

static inline void toggle_bit(bool v, void *data, size_t arrayidx, unsigned char bitidx)
{
    unsigned char *d = data;
    if (v) d[arrayidx] |= bitidx;
    else d[arrayidx] &= ~bitidx;
}

static inline bool sa6_from_string(struct sockaddr_in6 *sin, const char *str)
{
    memset(sin, 0, sizeof(struct sockaddr_in6));
    sin->sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, str, &sin->sin6_addr) != 1) {
        log_line("inet_pton failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

/* XXX: Configuration options:
 *
 * is_router = false :: Can we forward packets to/from the interface?
 *                      -> If true, we send periodic router advertisements.
 * Send times are randomized between interval/min_interval using
 * a UNIFORM distribution.
 * advert_interval_sec = 600 :: Maximum time between multicast router
 *                              adverts.  min=4, max=1800
 * advert_min_interval_sec (NOT CONFIGURABLE) ::
 *                 min,max = [3, 0.75 * advert_interval_sec]
 *                 default = max(0.33 * advert_interval_sec, 3)
 *
 * is_managed = false :: Does the network use DHCPv6 for address assignment?
 * other_config = false :: Does the network use DHCPv6 for other net info?
 * mtu = 0 :: Advertise specified MTU if value >= IPv6 Min MTU (1280?)
 * reachable_time = 0 :: Value for the reachable time field.
 *                       0 means unspecified.
 *                       Must be <= 3600000ms (1h)
 * retransmit_time = 0 :: Value for the retransmit time field.
 *                       0 means unspecified.
 * curhoplimit = 0 :: Value for the Cur Hop Limit field.
 *                       0 means unspecified.
 * default_lifetime = 3 * advert_interval_sec ::
 *                Router lifetime field value.
 *
 * prefix_list = everything but link local ::
 *                Prefix Information options.
 *                Valid Lifetime should default to 2592000 seconds (30d)
 *                On Link Flag (L-bit) : True
 *                Preferred Lifetime should default to 604800 seconds (7d)
 *                    MUST be <= Valid Lifetime
 *                Autonomous Flag: True
 */

#define ICMP_HEADER_SIZE 4
struct icmp_header { uint8_t data_[4]; };
static uint8_t icmp_header_type(const struct icmp_header *self) { return self->data_[0]; }
static uint8_t icmp_header_code(const struct icmp_header *self) { return self->data_[1]; }
static void icmp_header_set_type(struct icmp_header *self, uint8_t v) { self->data_[0] = v; }
static void icmp_header_set_checksum(struct icmp_header *self, uint8_t v) { encode16be(v, self->data_ + 2); }
static bool icmp_header_read(struct icmp_header *self, struct sbufs *rbuf)
{
    if (sbufs_brem(rbuf) < ICMP_HEADER_SIZE) return false;
    memcpy(&self->data_, rbuf->si, sizeof self->data_);
    rbuf->si += ICMP_HEADER_SIZE;
    return true;
}
static bool icmp_header_write(const struct icmp_header *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < ICMP_HEADER_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += ICMP_HEADER_SIZE;
    return true;
}

// Just a reserved 32-bit field.
// Follow with MTU and Prefix Information options.
#define RA6_SOLICIT_HEADER_SIZE 4
struct ra6_solicit_header { uint8_t data_[4]; };
static bool ra6_solicit_header_read(struct ra6_solicit_header *self, struct sbufs *rbuf)
{
    if (sbufs_brem(rbuf) < RA6_SOLICIT_HEADER_SIZE) return false;
    memcpy(&self->data_, rbuf->si, sizeof self->data_);
    rbuf->si += RA6_SOLICIT_HEADER_SIZE;
    return true;
}

#define RA6_ADVERT_HEADER_SIZE 12
// Follow with MTU and Prefix Information options.
struct ra6_advert_header { uint8_t data_[12]; };
static void ra6_advert_header_set_hoplimit(struct ra6_advert_header *self, uint8_t v) { self->data_[0] = v; }
static void ra6_advert_header_set_managed_addresses(struct ra6_advert_header *self, bool v)
{ toggle_bit(v, self->data_, 1, 1 << 7); }
static void ra6_advert_header_set_other_stateful(struct ra6_advert_header *self, bool v)
{ toggle_bit(v, self->data_, 1, 1 << 6); }
static void ra6_advert_header_set_router_lifetime(struct ra6_advert_header *self, uint16_t v)
{ encode16be(v, self->data_ + 2); }
static void ra6_advert_header_set_reachable_time(struct ra6_advert_header *self, uint32_t v)
{ encode32be(v, self->data_ + 4); }
static void ra6_advert_header_set_retransmit_timer(struct ra6_advert_header *self, uint32_t v)
{ encode32be(v, self->data_ + 8); }
static bool ra6_advert_header_write(const struct ra6_advert_header *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < RA6_ADVERT_HEADER_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += RA6_ADVERT_HEADER_SIZE;
    return true;
}

#define RA6_SOURCE_LLA_OPT_SIZE 8
struct ra6_source_lla_opt { uint8_t data_[8]; };
static void ra6_source_lla_opt_set_macaddr(struct ra6_source_lla_opt *self, const char *mac)
{ memcpy(self->data_ + 2, mac, 6); }
static bool ra6_source_lla_opt_write(const struct ra6_source_lla_opt *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < RA6_SOURCE_LLA_OPT_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += RA6_SOURCE_LLA_OPT_SIZE;
    return true;
}

#define RA6_MTU_OPT_SIZE 8
struct ra6_mtu_opt { uint8_t data_[8]; };
static void ra6_mtu_opt_set_mtu(struct ra6_mtu_opt *self, uint32_t v) { encode32be(v, self->data_ + 4); }
static bool ra6_mtu_opt_write(const struct ra6_mtu_opt *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < RA6_MTU_OPT_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += RA6_MTU_OPT_SIZE;
    return true;
}

#define RA6_PREFIX_INFO_OPT_SIZE 32
struct ra6_prefix_info_opt { uint8_t data_[32]; };
static void ra6_prefix_info_opt_set_prefix(struct ra6_prefix_info_opt *self, const struct in6_addr *v, uint8_t pl)
{
    self->data_[2] = pl;
    uint8_t a6[16];
    memcpy(a6, v, sizeof a6);
    uint8_t keep_bytes = pl / 8;
    uint8_t keep_bits = pl % 8;
    if (keep_bits == 0)
        memset(a6 + keep_bytes, 0, 16 -  keep_bytes);
    else {
        memset(a6 + keep_bytes + 1, 0, 16u - keep_bytes - 1u);
        uint8_t mask = 0xff;
        while (keep_bits--)
            mask >>= 1;
        a6[keep_bytes] &= ~mask;
    }
    memcpy(self->data_ + 16, a6, sizeof a6);
}
static void ra6_prefix_info_opt_set_on_link(struct ra6_prefix_info_opt *self, bool v)
{ toggle_bit(v, self->data_, 3, 1 << 7); }
static void ra6_prefix_info_opt_set_auto_addr_cfg(struct ra6_prefix_info_opt *self, bool v)
{ toggle_bit(v, self->data_, 3, 1 << 6); }
static void ra6_prefix_info_opt_set_router_addr_flag(struct ra6_prefix_info_opt *self, bool v)
{ toggle_bit(v, self->data_, 3, 1 << 5); }
static void ra6_prefix_info_opt_set_valid_lifetime(struct ra6_prefix_info_opt *self, uint32_t v)
{ encode32be(v, self->data_ + 4); }
static void ra6_prefix_info_opt_set_preferred_lifetime(struct ra6_prefix_info_opt *self, uint32_t v)
{ encode32be(v, self->data_ + 8); }
static bool ra6_prefix_info_opt_write(const struct ra6_prefix_info_opt *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < RA6_PREFIX_INFO_OPT_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += RA6_PREFIX_INFO_OPT_SIZE;
    return true;
}

#define RA6_RDNS_OPT_SIZE 8
struct ra6_rdns_opt { uint8_t data_[8]; };
static void ra6_rdns_opt_set_length(struct ra6_rdns_opt *self, uint8_t numdns) { self->data_[1] = 1 + 2 * numdns; }
static void ra6_rdns_opt_set_lifetime(struct ra6_rdns_opt *self, uint32_t v) { encode32be(v, self->data_ + 4); }
static bool ra6_rdns_opt_write(const struct ra6_rdns_opt *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < RA6_RDNS_OPT_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += RA6_RDNS_OPT_SIZE;
    return true;
}

#define RA6_DNS_SEARCH_OPT_SIZE 8
struct ra6_dns_search_opt { uint8_t data_[8]; };
static size_t ra6_dns_search_opt_set_length(struct ra6_dns_search_opt *self, size_t sz) {
    self->data_[1] = 1 + sz / 8;
    size_t slack = sz % 8;
    self->data_[1] += slack > 0 ? 1 : 0;
    return 8 * self->data_[1] - (8 + sz);
}
static void ra6_dns_search_opt_set_lifetime(struct ra6_dns_search_opt *self, uint32_t v) { encode32be(v, self->data_ + 4); }
static bool ra6_dns_search_opt_write(const struct ra6_dns_search_opt *self, struct sbufs *sbuf)
{
    if (sbufs_brem(sbuf) < RA6_DNS_SEARCH_OPT_SIZE) return false;
    memcpy(sbuf->si, &self->data_, sizeof self->data_);
    sbuf->si += RA6_DNS_SEARCH_OPT_SIZE;
    return true;
}

static void attach_bpf(struct RA6Listener *self)
{
    self->using_bpf_ = attach_bpf_icmp6_ra(self->fd_, self->ifname_);
}

static void set_next_advert_ts(struct RA6Listener *self)
{
    unsigned advi_s_min = self->advi_s_max_ / 3 > 3u ? self->advi_s_max_ / 3 : 3u;
    // The extremely small distribution skew does not matter here.
    unsigned advi_s = (unsigned)(nk_random_u64(&g_rngstate) % (self->advi_s_max_ - advi_s_min)) + advi_s_min;
    clock_gettime(CLOCK_BOOTTIME, &self->advert_ts_);
    self->advert_ts_.tv_sec += advi_s;
}

static void set_advi_s_max(struct RA6Listener *self, unsigned v)
{
    v = v > 4u ? v : 4u;
    v = v < 1800u ? v : 1800u;
    self->advi_s_max_ = v;
}

static bool send_advert(struct RA6Listener *self);

/*
 * We will need to minimally support DHCPv6 for providing
 * DNS server information.  We will support RFC6106, too, but
 * Windows needs DHCPv6 for DNS.
 */
extern struct NLSocket nl_socket;
static bool init_addrs;
static struct sockaddr_in6 ip6_any;
static struct sockaddr_in6 mc6_allhosts;
static struct sockaddr_in6 mc6_allrouters;
static const uint8_t icmp_nexthdr = 58; // Assigned value

struct RA6Listener *RA6Listener_create(const char *ifname, const struct netif_info *ifinfo)
{
    if (!init_addrs) {
        if (!sa6_from_string(&ip6_any, "::")) return NULL; // XXX: All-zero is fine, no need to do this.
        if (!sa6_from_string(&mc6_allhosts, "ff02::1")) return NULL;
        if (!sa6_from_string(&mc6_allrouters, "ff02::2")) return NULL;
        init_addrs = true;
    }

    struct RA6Listener *self;
    struct sockaddr_in6 sai = { .sin6_family = AF_INET6, };
    size_t ifname_src_size = strlen(ifname);
    if (ifname_src_size >= sizeof self->ifname_) {
        log_line("RA6Listener: Interface name (%s) too long\n", ifname);
        return NULL;
    }
    if (!ifinfo->has_v6_address_global) {
        log_line("ra6: Failed to get global ipv6 address for %s\n", ifname);
        return NULL;
    }
    self = calloc(1, sizeof(struct RA6Listener));
    if (!self) return NULL;

    self->ifindex = ifinfo->index;
    set_advi_s_max(self, 600);
    self->using_bpf_ = false;
    *(char *)(mempcpy(self->ifname_, ifname, ifname_src_size)) = 0;

    if (self->fd_ >= 0) close(self->fd_);
    self->fd_ = socket(AF_INET6, SOCK_RAW|SOCK_CLOEXEC, IPPROTO_ICMPV6);
    if (self->fd_ < 0) {
        log_line("ra6: Failed to create v6 ICMP socket on %s: %s\n", self->ifname_, strerror(errno));
        goto err0;
    }
    if (!attach_multicast_sockaddr_in6(self->fd_, self->ifname_, &mc6_allrouters)) {
        goto err1;
    }
    attach_bpf(self);

    if (bind(self->fd_, (const struct sockaddr *)&sai, sizeof sai)) {
        log_line("ra6: Failed to bind ICMP route advertisement listener on %s: %s\n", self->ifname_, strerror(errno));
        goto err1;
    }

    if (!send_advert(self))
        log_line("ra6: Failed to send initial router advertisement on %s\n", self->ifname_);
    set_next_advert_ts(self);

    return self;
err1:
    close(self->fd_);
    self->fd_ = -1;
err0:
    free(self);
    return NULL;
}

static bool send_advert(struct RA6Listener *self)
{
    struct icmp_header icmp_hdr = {0};
    struct ra6_advert_header ra6adv_hdr = {0};
    struct ra6_source_lla_opt ra6_slla = {{ 1, 1 }};
    struct ra6_mtu_opt ra6_mtu = {{ 5, 1 }};
    struct ra6_prefix_info_opt ra6_pfxi = {{ 3, 4 }};
    struct ra6_rdns_opt ra6_dns = {{ 25 }};
    struct ra6_dns_search_opt ra6_dsrch = {{ 31 }};
    uint32_t pktl = sizeof icmp_hdr + sizeof ra6adv_hdr + sizeof ra6_slla
                  + sizeof ra6_mtu;

    struct netif_info *ifinfo = NLSocket_get_ifinfo(&nl_socket, self->ifindex);
    if (!ifinfo) {
        log_line("ra6: Failed to get interface info for %s\n", self->ifname_);
        return false;
    }

    icmp_header_set_type(&icmp_hdr, 134);
    uint16_t csum = net_checksum16(&icmp_hdr, sizeof icmp_hdr);

    ra6_advert_header_set_hoplimit(&ra6adv_hdr, 0);
    ra6_advert_header_set_managed_addresses(&ra6adv_hdr, true);
    ra6_advert_header_set_other_stateful(&ra6adv_hdr, true);
    ra6_advert_header_set_router_lifetime(&ra6adv_hdr, 3 * self->advi_s_max_);
    ra6_advert_header_set_reachable_time(&ra6adv_hdr, 0);
    ra6_advert_header_set_retransmit_timer(&ra6adv_hdr, 0);
    csum = net_checksum16_add
        (csum, net_checksum16(&ra6adv_hdr, sizeof ra6adv_hdr));

    ra6_source_lla_opt_set_macaddr(&ra6_slla, ifinfo->macaddr);
    csum = net_checksum16_add
           (csum, net_checksum16(&ra6_slla, sizeof ra6_slla));
    ra6_mtu_opt_set_mtu(&ra6_mtu, ifinfo->mtu);
    csum = net_checksum16_add
           (csum, net_checksum16(&ra6_mtu, sizeof ra6_mtu));

    // Prefix Information
    ra6_prefix_info_opt_set_prefix(&ra6_pfxi, &ifinfo->v6_address_global, ifinfo->v6_prefixlen_global);
    ra6_prefix_info_opt_set_on_link(&ra6_pfxi, true);
    ra6_prefix_info_opt_set_auto_addr_cfg(&ra6_pfxi, false);
    ra6_prefix_info_opt_set_router_addr_flag(&ra6_pfxi, true);
    ra6_prefix_info_opt_set_valid_lifetime(&ra6_pfxi, 2592000);
    ra6_prefix_info_opt_set_preferred_lifetime(&ra6_pfxi, 604800);
    csum = net_checksum16_add(csum, net_checksum16(&ra6_pfxi, sizeof ra6_pfxi));
    pktl += sizeof ra6_pfxi;

    struct addrlist dns_servers = query_dns_servers(ifinfo->index);
    struct blob d6b = query_dns6_search_blob(ifinfo->index);

    if (dns_servers.n) {
        ra6_rdns_opt_set_length(&ra6_dns, dns_servers.n);
        ra6_rdns_opt_set_lifetime(&ra6_dns, self->advi_s_max_ * 2);
        csum = net_checksum16_add(csum, net_checksum16(&ra6_dns, sizeof ra6_dns));
        pktl += sizeof ra6_dns + 16 * dns_servers.n;
    }

    size_t dns_search_slack = 0;
    if (d6b.s && d6b.n) {
        dns_search_slack = ra6_dns_search_opt_set_length(&ra6_dsrch, d6b.n);
        ra6_dns_search_opt_set_lifetime(&ra6_dsrch, self->advi_s_max_ * 2);
        csum = net_checksum16_add(csum, net_checksum16(&ra6_dsrch, sizeof ra6_dsrch));
        csum = net_checksum16_add(csum, net_checksum16(d6b.s, d6b.n));
        pktl += sizeof ra6_dsrch + d6b.n + dns_search_slack;
    }

    csum = net_checksum16_add(csum, net_checksum16(&ip6_any.sin6_addr, sizeof ip6_any.sin6_addr));
    csum = net_checksum16_add(csum, net_checksum16(&mc6_allhosts.sin6_addr, sizeof mc6_allhosts.sin6_addr));
    csum = net_checksum16_add(csum, net_checksum16(&pktl, sizeof pktl));
    csum = net_checksum16_add(csum, net_checksum16(&icmp_nexthdr, 1));
    if (dns_servers.n) {
        for (size_t i = 0; i < dns_servers.n; ++i) {
            csum = net_checksum16_add(csum, net_checksum16(&dns_servers.addrs[i], sizeof dns_servers.addrs[i]));
        }
    }
    icmp_header_set_checksum(&icmp_hdr, csum);

    char sbuf[4096];
    struct sbufs ss = { &sbuf[0], &sbuf[4096] };
    if (!icmp_header_write(&icmp_hdr, &ss)) return false;
    if (!ra6_advert_header_write(&ra6adv_hdr, &ss)) return false;
    if (!ra6_source_lla_opt_write(&ra6_slla, &ss)) return false;
    if (!ra6_mtu_opt_write(&ra6_mtu, &ss)) return false;
    if (!ra6_prefix_info_opt_write(&ra6_pfxi, &ss)) return false;
    if (dns_servers.n) {
        if (!ra6_rdns_opt_write(&ra6_dns, &ss)) return false;
        size_t siz = 16 * dns_servers.n;
        if (ss.se - ss.si < (ptrdiff_t)siz) return false;
        memcpy(ss.si, dns_servers.addrs, siz);
        ss.si += siz;
    }
    if (d6b.s && d6b.n) {
        if (!ra6_dns_search_opt_write(&ra6_dsrch, &ss)) return false;
        if (ss.se - ss.si < (ptrdiff_t)d6b.n) return false;
        memcpy(ss.si, d6b.s, d6b.n);
        ss.si += d6b.n;
        for (size_t i = 0; i < dns_search_slack; ++i) {
            if (ss.si == ss.se) return false;
            *ss.si++ = 0;
        }
    }
    size_t slen = ss.si > sbuf ? (size_t)(ss.si - sbuf) : 0;

    if (safe_sendto(self->fd_, sbuf, slen, 0, (const struct sockaddr *)&mc6_allhosts, sizeof mc6_allhosts) < 0) {
        log_line("ra6: sendto failed on %s: %s\n", self->ifname_, strerror(errno));
        return false;
    }
    return true;
}

int RA6Listener_send_periodic_advert(struct RA6Listener *self)
{
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    if (now.tv_sec > self->advert_ts_.tv_sec
        || (now.tv_sec == self->advert_ts_.tv_sec && now.tv_nsec > self->advert_ts_.tv_nsec)) {
        if (!send_advert(self))
            log_line("ra6: Failed to send periodic router advertisement on %s\n", self->ifname_);
        set_next_advert_ts(self);
    }
    return 1000 + (self->advert_ts_.tv_sec - now.tv_sec) * 1000; // Always wait at least 1s
}

static bool ip6_is_unspecified(const struct sockaddr_storage *sa)
{
    struct sockaddr_in6 sai, t = {0};
    memcpy(&sai, &sa, sizeof sai);
    return memcmp(&sai.sin6_addr, &t.sin6_addr, sizeof t.sin6_addr) == 0;
}

static void process_receive(struct RA6Listener *self, char *buf, size_t buflen,
                            const struct sockaddr_storage *sai, socklen_t sailen)
{
    if (sailen < sizeof(struct sockaddr_in6)) {
        log_line("ra6: Received too-short address family on %s: %u\n", self->ifname_, sailen);
        return;
    }
    char sip_str[32];
    if (!sa6_to_string(sip_str, sizeof sip_str, sai, sailen)) {
        log_line("ra6: Failed to stringize sender ip on %s\n", self->ifname_);
        return;
    }
    bool sender_unspecified = ip6_is_unspecified(sai);

    struct sbufs rs = { buf, buf + buflen };
    // Discard if the ICMP length < 8 octets.
    if (buflen < ICMP_HEADER_SIZE + RA6_SOLICIT_HEADER_SIZE) {
        log_line("ra6: ICMP from %s is too short: %zu\n", sip_str, buflen);
        return;
    }

    struct icmp_header icmp_hdr;
    if (!icmp_header_read(&icmp_hdr, &rs)) return;

    // XXX: Discard if the ip header hop limit field != 255
#if 0
    if (ipv6_hdr.hop_limit() != 255) {
        log_line("ra6: Hop limit != 255\n");
        return;
    }
#endif

    if (!self->using_bpf_) {
        // Discard if the ICMP code is not 0.
        if (icmp_header_code(&icmp_hdr) != 0) {
            log_line("ra6: ICMP code != 0 on %s\n", self->ifname_);
            return;
        }

        if (icmp_header_type(&icmp_hdr) != 133) {
            log_line("ra6: ICMP type != 133 on %s\n", self->ifname_);
            return;
        }
    }

    struct ra6_solicit_header ra6_solicit_hdr;
    if (!ra6_solicit_header_read(&ra6_solicit_hdr, &rs)) return;

    uint8_t macaddr[6];
    bool got_macaddr = false;

    // Only the source link-layer address option is defined.
    while (rs.se >= 2 + rs.si) {
        uint8_t opt_type = (uint8_t)(*rs.si++);
        size_t opt_length = 8 * (size_t)(*rs.si++);
        // Discard if any included option has a length <= 0.
        if (opt_length <= 0) {
            log_line("ra6: Solicitation option length <= 0 on %s\n", self->ifname_);
            return;
        }
        if (opt_type == 1) {
            if (got_macaddr) {
                log_line("ra6: More than one Source Link-Layer Address option on %s; dropping\n", self->ifname_);
                return;
            }
            if (opt_length == 8) {
                if (rs.se - rs.si < (ptrdiff_t)sizeof macaddr) {
                    log_line("ra6: Source Link-Layer Address is wrong size for ethernet on %s\n", self->ifname_);
                    return;
                }
                got_macaddr = true;
                for (size_t i = 0; i < sizeof macaddr; ++i) {
                    macaddr[i] = (uint8_t)(*rs.si++);
                }
            } else {
                log_line("ra6: Source Link-Layer Address is wrong size for ethernet on %s\n", self->ifname_);
                return;
            }
        } else {
            if (rs.se - rs.si < (ptrdiff_t)opt_length - 2) {
                log_line("ra6: Invalid length(%zu) for option type(%u) on %s\n", opt_length, +opt_type, self->ifname_);
                return;
            }
            log_line("ra6: Ignoring unknown option type(%u) on %s\n", +opt_type, self->ifname_);
            for (size_t i = 0; i < opt_length - 2; ++i) rs.si++;
        }
    }

    // Discard if the source address is unspecified and
    // there is no source link-layer address option included.
    if (!got_macaddr && sender_unspecified) {
        log_line("ra6: Solicitation provides no specified source address or option on %s\n", self->ifname_);
        return;
    }

    // Send a router advertisement in reply.
    if (!send_advert(self))
        log_line("ra6: Failed to send router advertisement on %s\n", self->ifname_);
    set_next_advert_ts(self);
}

void RA6Listener_process_input(struct RA6Listener *self)
{
    char buf[8192];
    for (;;) {
        struct sockaddr_storage sai;
        socklen_t sailen = sizeof sai;
        ssize_t buflen = recvfrom(self->fd_, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&sai, &sailen);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("ra6: recvfrom failed on %s: %s\n", self->ifname_, strerror(err));
        }
        process_receive(self, buf, (size_t)buflen, &sai, sailen);
    }
}

int RA6Listener_fd(const struct RA6Listener *self) { return self->fd_; }
