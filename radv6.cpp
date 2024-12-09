// Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <net/if.h>
#include <sys/socket.h>
#include <array>

#include <nk/netbits.hpp>
#include "radv6.hpp"
#include "nlsocket.hpp"
#include "dhcp6.hpp"
#include "multicast6.hpp"
#include "attach_bpf.h"
#include "sbufs.h"
#include "rng.hpp"

extern "C" {
#include "nk/net_checksum16.h"
#include "nk/log.h"
#include "nk/io.h"
}

static inline void toggle_bit(bool v, void *data, size_t arrayidx, unsigned char bitidx)
{
    auto d = static_cast<unsigned char *>(data);
    if (v) d[arrayidx] |= bitidx;
    else d[arrayidx] &= ~bitidx;
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

class ipv6_header
{
public:
    uint8_t version() const { return (data_[0] >> 4) & 0xf; }
    uint8_t traffic_class() const {
        return (static_cast<uint32_t>(data_[0] & 0xf) << 4)
             | (static_cast<uint32_t>(data_[1] >> 4) & 0xf);
    }
    uint32_t flow_label() const {
        return (static_cast<uint32_t>(data_[1] & 0xf) << 16)
             | ((static_cast<uint32_t>(data_[2]) << 8) | data_[3]);
    }
    uint16_t payload_length() const {
        return decode16be(data_ + 4);
    }
    uint8_t next_header() const {
        return data_[6];
    }
    uint8_t hop_limit() const {
        return data_[7];
    }
    nk::ip_address source_address() const
    {
        nk::ip_address ret;
        ret.from_v6bytes(data_ + 8);
        return ret;
    }
    nk::ip_address destination_address() const
    {
        nk::ip_address ret;
        ret.from_v6bytes(data_ + 24);
        return ret;
    }
    static const size_t size = 40;

    bool read(sbufs &rbuf)
    {
        if (rbuf.brem() < size) return false;
        memcpy(&data_, rbuf.si, sizeof data_);
        if (version() != 6) return false; // XXX: Existing code was doing this check here.
        rbuf.si += size;
        return true;
    }
    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        memcpy(sbuf.si, &data_, sizeof data_);
        sbuf.si += size;
        return true;
    }
private:
    uint8_t data_[40] = {};
};

#define DEF_RW_MEMBERS() \
    bool read(sbufs &rbuf) \
    { \
        if (rbuf.brem() < size) return false; \
        memcpy(&data_, rbuf.si, sizeof data_); \
        rbuf.si += size; \
        return true; \
    } \
    bool write(sbufs &sbuf) const \
    { \
        if (sbuf.brem() < size) return false; \
        memcpy(sbuf.si, &data_, sizeof data_); \
        sbuf.si += size; \
        return true; \
    }

class icmp_header
{
public:
    uint8_t type() const { return data_[0]; }
    uint8_t code() const { return data_[1]; }
    uint16_t checksum() const { return decode16be(data_ + 2); }
    void type(uint8_t v) { data_[0] = v; }
    void code(uint8_t v) { data_[1] = v; }
    void checksum(uint16_t v) { encode16be(v, data_ + 2); }
    static const size_t size = 4;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[4] = {};
};

class ra6_solicit_header
{
public:
    // Just a reserved 32-bit field.
    // Follow with MTU and Prefix Information options.
    static const size_t size = 4;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[4] = {};
};

class ra6_advert_header
{
public:
    uint8_t hoplimit() const { return data_[0]; }
    bool managed_addresses() const { return data_[1] & (1 << 7); }
    bool other_stateful() const { return data_[1] & (1 << 6); }
    bool home_address() const { return data_[1] & (1 << 5); }
    uint16_t router_lifetime() const { return decode16be(data_ + 2); }
    uint32_t reachable_time() const { return decode32be(data_ + 4); }
    uint32_t retransmit_timer() const { return decode32be(data_ + 8); }
    void hoplimit(uint8_t v) { data_[0] = v; }
    void managed_addresses(bool v) { toggle_bit(v, data_, 1, 1 << 7); }
    void other_stateful(bool v) { toggle_bit(v, data_, 1, 1 << 6); }
    void home_address(bool v) { toggle_bit(v, data_, 1, 1 << 5); }
    enum class RouterPref { High, Medium, Low };
    void default_router_preference(RouterPref v) {
        switch (v) {
        case RouterPref::High:
            toggle_bit(false, data_, 1, 1 << 4);
            toggle_bit(true, data_, 1, 1 << 3);
            break;
        case RouterPref::Medium:
            toggle_bit(false, data_, 1, 1 << 4);
            toggle_bit(false, data_, 1, 1 << 3);
            break;
        case RouterPref::Low:
            toggle_bit(true, data_, 1, 1 << 4);
            toggle_bit(true, data_, 1, 1 << 3);
            break;
        }
    }
    void router_lifetime(uint16_t v) { encode16be(v, data_ + 2); }
    void reachable_time(uint32_t v) { encode32be(v, data_ + 4); }
    void retransmit_timer(uint32_t v) { encode32be(v, data_ + 8); }
    // Follow with MTU and Prefix Information options.
    static const size_t size = 12;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[12] = {};
};

class ra6_source_lla_opt
{
public:
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    const uint8_t *macaddr() const { return data_ + 2; }
    void macaddr(char *mac, size_t maclen) {
        if (maclen != 6) suicide("ra6: wrong maclen\n");
        memcpy(data_ + 2, mac, 6);
    }
    static const size_t size = 8;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[8] = { 1, 1 };
};

class ra6_mtu_opt
{
public:
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t mtu() const { return decode32be(data_ + 4); }
    void mtu(uint32_t v) { encode32be(v, data_ + 4); }
    static const size_t size = 8;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[8] = { 5, 1 };
};

class ra6_prefix_info_opt
{
public:
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1]; }
    uint8_t prefix_length() const { return data_[2]; }
    bool on_link() const { return data_[3] & (1 << 7); }
    bool auto_addr_cfg() const { return data_[3] & (1 << 6); }
    bool router_addr_flag() const { return data_[3] & (1 << 5); }
    uint32_t valid_lifetime() const { return decode32be(data_ + 4); }
    uint32_t preferred_lifetime() const { return decode32be(data_ + 8); }
    nk::ip_address prefix() const
    {
        nk::ip_address ret;
        ret.from_v6bytes(data_ + 16);
        return ret;
    }
    void on_link(bool v) { toggle_bit(v, data_, 3, 1 << 7); }
    void auto_addr_cfg(bool v) { toggle_bit(v, data_, 3, 1 << 6); }
    void router_addr_flag(bool v) { toggle_bit(v, data_, 3, 1 << 5); }
    void valid_lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    void preferred_lifetime(uint32_t v) { encode32be(v, data_ + 8); }
    void prefix(const nk::ip_address &v, uint8_t pl) {
        uint8_t a6[16];
        data_[2] = pl;
        v.raw_v6bytes(a6);
        uint8_t keep_bytes = pl / 8;
        uint8_t keep_bits = pl % 8;
        if (keep_bits == 0)
            memset(a6 + keep_bytes, 0, 16 -  keep_bytes);
        else {
            memset(a6 + keep_bytes + 1, 0, 16 - keep_bytes - 1);
            uint8_t mask = 0xff;
            while (keep_bits--)
                mask >>= 1;
            a6[keep_bytes] &= ~mask;
        }
        memcpy(data_ + 16, a6, sizeof a6);
    }
    static const size_t size = 32;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[32] = { 3, 4 };
};

class ra6_rdns_opt
{
public:
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t lifetime() const { return decode32be(data_ + 4); }
    void length(uint8_t numdns) { data_[1] = 1 + 2 * numdns; }
    void lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    static const size_t size = 8;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[8] = { 25 };
};

class ra6_dns_search_opt
{
public:
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t lifetime() const { return decode32be(data_ + 4); }
    size_t length(size_t sz) {
        data_[1] = 1 + sz / 8;
        size_t slack = sz % 8;
        data_[1] += slack > 0 ? 1 : 0;
        return 8 * data_[1] - (8 + sz);
    }
    void lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    static const size_t size = 8;
    DEF_RW_MEMBERS()
private:
    uint8_t data_[8] = { 31 };
};
#undef DEF_RW_MEMBERS

/*
 * We will need to minimally support DHCPv6 for providing
 * DNS server information.  We will support RFC6106, too, but
 * Windows needs DHCPv6 for DNS.
 */
extern NLSocket nl_socket;
static bool init_addrs(false);
static sockaddr_in6 ip6_any;
static sockaddr_in6 mc6_allhosts;
static sockaddr_in6 mc6_allrouters;
static const uint8_t icmp_nexthdr(58); // Assigned value

bool RA6Listener::init(const char *ifname)
{
    if (!init_addrs) {
        if (!sa6_from_string(&ip6_any, "::")) return false;
        if (!sa6_from_string(&mc6_allhosts, "ff02::1")) return false;
        if (!sa6_from_string(&mc6_allrouters, "ff02::2")) return false;
        init_addrs = true;
    }

    advi_s_max_ = 600;
    using_bpf_ = false;
    size_t ifname_src_size = strlen(ifname);
    if (ifname_src_size >= sizeof ifname_) {
        log_line("RA6Listener: Interface name (%s) too long\n", ifname);
        return false;
    }
    *static_cast<char *>(mempcpy(ifname_, ifname, ifname_src_size)) = 0;

    auto tfd = nk::sys::handle{ socket(AF_INET6, SOCK_RAW|SOCK_CLOEXEC, IPPROTO_ICMPV6) };
    if (!tfd) {
        log_line("ra6: Failed to create v6 ICMP socket on %s: %s\n", ifname_, strerror(errno));
        return false;
    }
    if (!attach_multicast(tfd(), ifname_, mc6_allrouters))
        return false;
    attach_bpf(tfd());

    sockaddr_in6 sai;
    memset(&sai, 0, sizeof sai); // s6_addr, s6_port are set to any/0 here
    sai.sin6_family = AF_INET6;
    if (bind(tfd(), (const sockaddr *)&sai, sizeof sai)) {
        log_line("ra6: Failed to bind ICMP route advertisement listener on %s: %s\n", ifname_, strerror(errno));
        return false;
    }
    swap(fd_, tfd);

    if (!send_advert())
        log_line("ra6: Failed to send initial router advertisement on %s\n", ifname_);
    set_next_advert_ts();

    return true;
}

void RA6Listener::process_input()
{
    char buf[8192];
    for (;;) {
        sockaddr_storage sai;
        socklen_t sailen = sizeof sai;
        auto buflen = recvfrom(fd_(), buf, sizeof buf, MSG_DONTWAIT, (sockaddr *)&sai, &sailen);
        if (buflen < 0) {
            int err = errno;
            if (err == EINTR) continue;
            if (err == EAGAIN || err == EWOULDBLOCK) break;
            suicide("ra6: recvfrom failed on %s: %s\n", ifname_, strerror(err));
        }
        process_receive(buf, static_cast<size_t>(buflen), sai, sailen);
    }
}

void RA6Listener::attach_bpf(int fd)
{
    using_bpf_ = attach_bpf_icmp6_ra(fd, ifname_);
}

void RA6Listener::set_advi_s_max(unsigned v)
{
    v = std::max(v, 4U);
    v = std::min(v, 1800U);
    advi_s_max_ = v;
}

void RA6Listener::set_next_advert_ts()
{
    unsigned advi_s_min = std::max(advi_s_max_ / 3, 3U);
    // The extremely small distribution skew does not matter here.
    unsigned advi_s = (unsigned)(nk_random_u64() % (advi_s_max_ - advi_s_min)) + advi_s_min;
    clock_gettime(CLOCK_BOOTTIME, &advert_ts_);
    advert_ts_.tv_sec += advi_s;
}

bool RA6Listener::send_advert()
{
    icmp_header icmp_hdr;
    ra6_advert_header ra6adv_hdr;
    ra6_source_lla_opt ra6_slla;
    ra6_mtu_opt ra6_mtu;
    std::vector<ra6_prefix_info_opt> ra6_pfxs;
    ra6_rdns_opt ra6_dns;
    ra6_dns_search_opt ra6_dsrch;
    uint16_t csum;
    uint32_t pktl(sizeof icmp_hdr + sizeof ra6adv_hdr + sizeof ra6_slla
                  + sizeof ra6_mtu);

    auto ifinfo = nl_socket.get_ifinfo(ifname_);
    if (!ifinfo) {
        log_line("ra6: Failed to get interface index for %s\n", ifname_);
        return false;
    }

    icmp_hdr.type(134);
    icmp_hdr.code(0);
    icmp_hdr.checksum(0);
    csum = net_checksum16(&icmp_hdr, sizeof icmp_hdr);

    ra6adv_hdr.hoplimit(0);
    ra6adv_hdr.managed_addresses(true);
    ra6adv_hdr.other_stateful(true);
    ra6adv_hdr.router_lifetime(3 * advi_s_max_);
    ra6adv_hdr.reachable_time(0);
    ra6adv_hdr.retransmit_timer(0);
    csum = net_checksum16_add
        (csum, net_checksum16(&ra6adv_hdr, sizeof ra6adv_hdr));

    ra6_slla.macaddr(ifinfo->macaddr, sizeof ifinfo->macaddr);
    csum = net_checksum16_add
           (csum, net_checksum16(&ra6_slla, sizeof ra6_slla));
    ra6_mtu.mtu(ifinfo->mtu);
    csum = net_checksum16_add
           (csum, net_checksum16(&ra6_mtu, sizeof ra6_mtu));

    // Prefix Information
    for (const auto &i: ifinfo->addrs) {
        if (i.scope == netif_addr::Scope::Global && !i.address.is_v4()) {
            ra6_prefix_info_opt ra6_pfxi;
            ra6_pfxi.prefix(i.address, i.prefixlen);
            ra6_pfxi.on_link(true);
            ra6_pfxi.auto_addr_cfg(false);
            ra6_pfxi.router_addr_flag(true);
            ra6_pfxi.valid_lifetime(2592000);
            ra6_pfxi.preferred_lifetime(604800);
            ra6_pfxs.push_back(ra6_pfxi);
            csum = net_checksum16_add
                   (csum, net_checksum16(&ra6_pfxi, sizeof ra6_pfxi));
            pktl += sizeof ra6_pfxi;
            break;
        }
    }

    const std::vector<nk::ip_address> *dns6_servers{nullptr};
    const std::vector<uint8_t> *dns_search_blob{nullptr};
    dns6_servers = query_dns6_servers(ifinfo->index);
    dns_search_blob = query_dns6_search_blob(ifinfo->index);

    if (dns6_servers && dns6_servers->size()) {
        ra6_dns.length(dns6_servers->size());
        ra6_dns.lifetime(advi_s_max_ * 2);
        csum = net_checksum16_add(csum, net_checksum16(&ra6_dns,
                                                           sizeof ra6_dns));
        pktl += sizeof ra6_dns + 16 * dns6_servers->size();
    }

    size_t dns_search_slack = 0;
    if (dns_search_blob && dns_search_blob->size()) {
        dns_search_slack = ra6_dsrch.length(dns_search_blob->size());
        ra6_dsrch.lifetime(advi_s_max_ * 2);
        csum = net_checksum16_add
            (csum, net_checksum16(&ra6_dsrch, sizeof ra6_dsrch));
        csum = net_checksum16_add
            (csum, net_checksum16(dns_search_blob->data(),
                                    dns_search_blob->size()));
        pktl += sizeof ra6_dsrch + dns_search_blob->size() + dns_search_slack;
    }

    csum = net_checksum16_add(csum, net_checksum16(&ip6_any.sin6_addr, sizeof ip6_any.sin6_addr));
    csum = net_checksum16_add(csum, net_checksum16(&mc6_allhosts.sin6_addr, sizeof mc6_allhosts.sin6_addr));
    csum = net_checksum16_add(csum, net_checksum16(&pktl, sizeof pktl));
    csum = net_checksum16_add(csum, net_checksum16(&icmp_nexthdr, 1));
    if (dns6_servers) {
        for (const auto &i: *dns6_servers) {
            csum = net_checksum16_add(csum, net_checksum16(&i.native_type(), sizeof i.native_type()));
        }
    }
    icmp_hdr.checksum(csum);

    char sbuf[4096];
    sbufs ss{ &sbuf[0], &sbuf[4096] };
    if (!icmp_hdr.write(ss)) return false;
    if (!ra6adv_hdr.write(ss)) return false;
    if (!ra6_slla.write(ss)) return false;
    if (!ra6_mtu.write(ss)) return false;
    for (const auto &i: ra6_pfxs) {
        if (!i.write(ss)) return false;
    }
    if (dns6_servers && dns6_servers->size()) {
        if (!ra6_dns.write(ss)) return false;
        for (const auto &i: *dns6_servers) {
            std::array<char, 16> b6;
            i.raw_v6bytes(b6.data());
            for (const auto &j: b6) {
                if (ss.si == ss.se) return false;
                *ss.si++ = j;
            }
        }
    }
    if (dns_search_blob && dns_search_blob->size()) {
        if (!ra6_dsrch.write(ss)) return false;
        for (const auto &i: *dns_search_blob) {
            if (ss.si == ss.se) return false;
            *ss.si++ = static_cast<char>(i);
        }
        for (size_t i = 0; i < dns_search_slack; ++i) {
            if (ss.si == ss.se) return false;
            *ss.si++ = 0;
        }
    }
    const size_t slen = ss.si > sbuf ? static_cast<size_t>(ss.si - sbuf) : 0;

    if (safe_sendto(fd_(), sbuf, slen, 0, (const sockaddr *)&mc6_allhosts, sizeof mc6_allhosts) < 0) {
        log_line("ra6: sendto failed on %s: %s\n", ifname_, strerror(errno));
        return false;
    }
    return true;
}

int RA6Listener::send_periodic_advert()
{
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    if (now.tv_sec > advert_ts_.tv_sec
        || (now.tv_sec == advert_ts_.tv_sec && now.tv_nsec > advert_ts_.tv_nsec)) {
        if (!send_advert())
            log_line("ra6: Failed to send periodic router advertisement on %s\n", ifname_);
        set_next_advert_ts();
    }
    return 1000 + (advert_ts_.tv_sec - now.tv_sec) * 1000; // Always wait at least 1s
}

bool ip6_is_unspecified(const sockaddr_storage &sa)
{
    sockaddr_in6 sai, t;
    memcpy(&sai, &sa, sizeof sai);
    memset(&t, 0, sizeof t);
    return memcmp(&sai.sin6_addr, &t.sin6_addr, sizeof t.sin6_addr) == 0;
}

void RA6Listener::process_receive(char *buf, size_t buflen,
                                  const sockaddr_storage &sai, socklen_t sailen)
{
    if (sailen < sizeof(sockaddr_in6)) {
        log_line("ra6: Received too-short address family on %s: %u\n", ifname_, sailen);
        return;
    }
    char sip_str[32];
    if (!sa6_to_string(sip_str, sizeof sip_str, &sai, sailen)) {
        log_line("ra6: Failed to stringize sender ip on %s\n", ifname_);
        return;
    }
    const bool sender_unspecified = ip6_is_unspecified(sai);

    sbufs rs{ buf, buf + buflen };
    // Discard if the ICMP length < 8 octets.
    if (buflen < icmp_header::size + ra6_solicit_header::size) {
        log_line("ra6: ICMP from %s is too short: %zu\n", sip_str, buflen);
        return;
    }

    icmp_header icmp_hdr;
    if (!icmp_hdr.read(rs)) return;

    // XXX: Discard if the ip header hop limit field != 255
#if 0
    if (ipv6_hdr.hop_limit() != 255) {
        log_line("ra6: Hop limit != 255\n");
        return;
    }
#endif

    if (!using_bpf_) {
        // Discard if the ICMP code is not 0.
        if (icmp_hdr.code() != 0) {
            log_line("ra6: ICMP code != 0 on %s\n", ifname_);
            return;
        }

        if (icmp_hdr.type() != 133) {
            log_line("ra6: ICMP type != 133 on %s\n", ifname_);
            return;
        }
    }

    ra6_solicit_header ra6_solicit_hdr;
    if (!ra6_solicit_hdr.read(rs)) return;

    uint8_t macaddr[6];
    bool got_macaddr(false);

    // Only the source link-layer address option is defined.
    while (rs.se >= 2 + rs.si) {
        auto opt_type = static_cast<uint8_t>(*rs.si++);
        size_t opt_length = 8 * static_cast<uint8_t>(*rs.si++);
        // Discard if any included option has a length <= 0.
        if (opt_length <= 0) {
            log_line("ra6: Solicitation option length <= 0 on %s\n", ifname_);
            return;
        }
        if (opt_type == 1) {
            if (got_macaddr) {
                log_line("ra6: More than one Source Link-Layer Address option on %s; dropping\n", ifname_);
                return;
            }
            if (opt_length == 8) {
                if (rs.se - rs.si < static_cast<ptrdiff_t>(sizeof macaddr)) {
                    log_line("ra6: Source Link-Layer Address is wrong size for ethernet on %s\n", ifname_);
                    return;
                }
                got_macaddr = true;
                for (size_t i = 0; i < sizeof macaddr; ++i) {
                    macaddr[i] = static_cast<uint8_t>(*rs.si++);
                }
            } else {
                log_line("ra6: Source Link-Layer Address is wrong size for ethernet on %s\n", ifname_);
                return;
            }
        } else {
            if (rs.se - rs.si < static_cast<ptrdiff_t>(opt_length) - 2) {
                log_line("ra6: Invalid length(%zu) for option type(%u) on %s\n", opt_length, +opt_type, ifname_);
                return;
            }
            log_line("ra6: Ignoring unknown option type(%u) on %s\n", +opt_type, ifname_);
            for (size_t i = 0; i < opt_length - 2; ++i) rs.si++;
        }
    }

    // Discard if the source address is unspecified and
    // there is no source link-layer address option included.
    if (!got_macaddr && sender_unspecified) {
        log_line("ra6: Solicitation provides no specified source address or option on %s\n", ifname_);
        return;
    }

    // Send a router advertisement in reply.
    if (!send_advert())
        log_line("ra6: Failed to send router advertisement on %s\n", ifname_);
    set_next_advert_ts();
}

