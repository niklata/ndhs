/* radv6.cpp - ipv6 router advertisement handling
 *
 * (c) 2014-2017 Nicholas J. Kain <njkain at gmail dot com>
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

#include <sstream>
#include <algorithm>
#include <random>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <net/if.h>
#include <sys/socket.h>

#include <fmt/format.h>
#include <nk/netbits.hpp>
#include <nk/xorshift.hpp>
#include "radv6.hpp"
#include "nlsocket.hpp"
#include "dhcp6.hpp"
#include "multicast6.hpp"
#include "attach_bpf.h"

extern "C" {
#include "nk/net_checksum.h"
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
    ipv6_header() { std::fill(data_, data_ + sizeof data_, 0); }
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
    asio::ip::address_v6 source_address() const
    {
        asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, data_ + 8, 16);
        return asio::ip::address_v6(bytes);
    }
    asio::ip::address_v6 destination_address() const
    {
        asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, data_ + 24, 16);
        return asio::ip::address_v6(bytes);
    }
    static const std::size_t size = 40;
    friend std::istream& operator>>(std::istream &is, ipv6_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        if (header.version() != 6)
            is.setstate(std::ios::failbit);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ipv6_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[40];
};

class icmp_header
{
public:
    icmp_header() { std::fill(data_, data_ + sizeof data_, 0); }
    uint8_t type() const { return data_[0]; }
    uint8_t code() const { return data_[1]; }
    uint16_t checksum() const { return decode16be(data_ + 2); }
    void type(uint8_t v) { data_[0] = v; }
    void code(uint8_t v) { data_[1] = v; }
    void checksum(uint16_t v) { encode16be(v, data_ + 2); }
    static const std::size_t size = 4;
    friend std::istream& operator>>(std::istream &is, icmp_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const icmp_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[4];
};

class ra6_solicit_header
{
public:
    ra6_solicit_header() { std::fill(data_, data_ + sizeof data_, 0); }
    // Just a reserved 32-bit field.
    // Follow with MTU and Prefix Information options.
    static const std::size_t size = 4;
    friend std::istream& operator>>(std::istream &is, ra6_solicit_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_solicit_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[4];
};

class ra6_advert_header
{
public:
    ra6_advert_header() { std::fill(data_, data_ + sizeof data_, 0); }
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
    static const std::size_t size = 12;
    friend std::istream& operator>>(std::istream &is, ra6_advert_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_advert_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[12];
};

class ra6_source_lla_opt
{
public:
    ra6_source_lla_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 1;
        data_[1] = 1;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    const uint8_t *macaddr() const { return data_ + 2; }
    void macaddr(char *mac, std::size_t maclen) {
        if (maclen != 6)
            throw std::logic_error("wrong maclen");
        memcpy(data_ + 2, mac, 6);
    }
    static const std::size_t size = 8;
    friend std::istream& operator>>(std::istream &is, ra6_source_lla_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_source_lla_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[8];
};

class ra6_mtu_opt
{
public:
    ra6_mtu_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 5;
        data_[1] = 1;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t mtu() const { return decode32be(data_ + 4); }
    void mtu(uint32_t v) { encode32be(v, data_ + 4); }
    static const std::size_t size = 8;
    friend std::istream& operator>>(std::istream &is, ra6_mtu_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_mtu_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[8];
};

class ra6_prefix_info_opt
{
public:
    ra6_prefix_info_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 3;
        data_[1] = 4;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1]; }
    uint8_t prefix_length() const { return data_[2]; }
    bool on_link() const { return data_[3] & (1 << 7); }
    bool auto_addr_cfg() const { return data_[3] & (1 << 6); }
    bool router_addr_flag() const { return data_[3] & (1 << 5); }
    uint32_t valid_lifetime() const { return decode32be(data_ + 4); }
    uint32_t preferred_lifetime() const { return decode32be(data_ + 8); }
    asio::ip::address_v6 prefix() const
    {
        asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, data_ + 16, 16);
        return asio::ip::address_v6(bytes);
    }
    void on_link(bool v) { toggle_bit(v, data_, 3, 1 << 7); }
    void auto_addr_cfg(bool v) { toggle_bit(v, data_, 3, 1 << 6); }
    void router_addr_flag(bool v) { toggle_bit(v, data_, 3, 1 << 5); }
    void valid_lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    void preferred_lifetime(uint32_t v) { encode32be(v, data_ + 8); }
    void prefix(const asio::ip::address_v6 &v, uint8_t pl) {
        uint8_t a6[16];
        data_[2] = pl;
        auto bytes = v.to_bytes();
        memcpy(a6, bytes.data(), 16);
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
    static const std::size_t size = 32;
    friend std::istream& operator>>(std::istream &is, ra6_prefix_info_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_prefix_info_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[32];
};

class ra6_rdns_opt
{
public:
    ra6_rdns_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 25;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t lifetime() const { return decode32be(data_ + 4); }
    void length(uint8_t numdns) { data_[1] = 1 + 2 * numdns; }
    void lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    static const std::size_t size = 8;
    friend std::istream& operator>>(std::istream &is, ra6_rdns_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_rdns_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[8];
};

class ra6_dns_search_opt
{
public:
    ra6_dns_search_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 31;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t lifetime() const { return decode32be(data_ + 4); }
    size_t length(size_t size) {
        data_[1] = 1 + size / 8;
        size_t slack = size % 8;
        data_[1] += slack > 0 ? 1 : 0;
        return 8 * data_[1] - (8 + size);
    }
    void lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    static const std::size_t size = 8;
    friend std::istream& operator>>(std::istream &is, ra6_dns_search_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const ra6_dns_search_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[8];
};

/*
 * We will need to minimally support DHCPv6 for providing
 * DNS server information.  We will support RFC6106, too, but
 * Windows needs DHCPv6 for DNS.
 */
extern std::unique_ptr<NLSocket> nl_socket;
static auto mc6_allhosts = asio::ip::address_v6::from_string("ff02::1");
static auto mc6_allrouters = asio::ip::address_v6::from_string("ff02::2");
static const uint8_t icmp_nexthdr(58); // Assigned value
extern nk::rng::xoroshiro128p g_random_prng;

// Can throw std::out_of_range
RA6Listener::RA6Listener(asio::io_service &io_service, const std::string &ifname)
    : timer_(io_service), socket_(io_service), ifname_(ifname),
      advi_s_max_(600), using_bpf_(false)
{
    const asio::ip::icmp::endpoint global_ep(asio::ip::address_v6::any(), 0);
    socket_.open(asio::ip::icmp::v6());
    attach_multicast(socket_.native(), ifname, mc6_allrouters);
    attach_bpf(socket_.native());
    socket_.bind(global_ep);

    send_advert();
    start_periodic_announce();
    start_receive();
}

void RA6Listener::attach_bpf(int fd)
{
    using_bpf_ = attach_bpf_icmp6_ra(fd, ifname_.c_str());
}

void RA6Listener::set_advi_s_max(unsigned int v)
{
    v = std::max(v, 4U);
    v = std::min(v, 1800U);
    advi_s_max_ = v;
}

void RA6Listener::start_periodic_announce()
{
    unsigned int advi_s_min = std::max(advi_s_max_ / 3, 3U);
    std::uniform_int_distribution<> dist(advi_s_min, advi_s_max_);
    auto advi_s = dist(g_random_prng);
    timer_.expires_from_now(boost::posix_time::seconds(advi_s));
    timer_.async_wait
        ([this](const std::error_code &ec)
         {
             if (ec)
                return;
             try {
                send_advert();
             } catch (const std::out_of_range &) {}
             start_periodic_announce();
         });
}

// Can throw std::out_of_range
void RA6Listener::send_advert()
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

    icmp_hdr.type(134);
    icmp_hdr.code(0);
    icmp_hdr.checksum(0);
    csum = net_checksum161c(&icmp_hdr, sizeof icmp_hdr);

    ra6adv_hdr.hoplimit(0);
    ra6adv_hdr.managed_addresses(true);
    ra6adv_hdr.other_stateful(true);
    ra6adv_hdr.router_lifetime(3 * advi_s_max_);
    ra6adv_hdr.reachable_time(0);
    ra6adv_hdr.retransmit_timer(0);
    csum = net_checksum161c_add
        (csum, net_checksum161c(&ra6adv_hdr, sizeof ra6adv_hdr));

    auto ifidx = nl_socket->get_ifindex(ifname_);
    auto &ifinfo = nl_socket->interfaces.at(ifidx);

    ra6_slla.macaddr(ifinfo.macaddr, sizeof ifinfo.macaddr);
    csum = net_checksum161c_add
        (csum, net_checksum161c(&ra6_slla, sizeof ra6_slla));
    ra6_mtu.mtu(ifinfo.mtu);
    csum = net_checksum161c_add
        (csum, net_checksum161c(&ra6_mtu, sizeof ra6_mtu));

    // Prefix Information
    for (const auto &i: ifinfo.addrs) {
        if (i.scope == netif_addr::Scope::Global && i.address.is_v6()) {
            ra6_prefix_info_opt ra6_pfxi;
            ra6_pfxi.prefix(i.address.to_v6(), i.prefixlen);
            ra6_pfxi.on_link(true);
            ra6_pfxi.auto_addr_cfg(false);
            ra6_pfxi.router_addr_flag(true);
            ra6_pfxi.valid_lifetime(2592000);
            ra6_pfxi.preferred_lifetime(604800);
            ra6_pfxs.push_back(ra6_pfxi);
            csum = net_checksum161c_add
                (csum, net_checksum161c(&ra6_pfxi, sizeof ra6_pfxi));
            pktl += sizeof ra6_pfxi;
            break;
        }
    }

    const std::vector<asio::ip::address_v6> *dns6_servers{nullptr};
    const std::vector<uint8_t> *dns_search_blob{nullptr};
    try {
        const auto tt = query_dns6_servers(ifname_);
        dns6_servers = &tt;
    } catch (const std::runtime_error &) { }
    try {
        const auto tt = query_dns6_search_blob(ifname_);
        dns_search_blob = &tt;
    } catch (const std::runtime_error &) { }

    if (dns6_servers && dns6_servers->size()) {
        ra6_dns.length(dns6_servers->size());
        ra6_dns.lifetime(advi_s_max_ * 2);
        csum = net_checksum161c_add(csum, net_checksum161c(&ra6_dns,
                                                           sizeof ra6_dns));
        pktl += sizeof ra6_dns + 16 * dns6_servers->size();
    }

    size_t dns_search_slack = 0;
    if (dns_search_blob && dns_search_blob->size()) {
        dns_search_slack = ra6_dsrch.length(dns_search_blob->size());
        ra6_dsrch.lifetime(advi_s_max_ * 2);
        csum = net_checksum161c_add
            (csum, net_checksum161c(&ra6_dsrch, sizeof ra6_dsrch));
        csum = net_checksum161c_add
            (csum, net_checksum161c(dns_search_blob->data(),
                                    dns_search_blob->size()));
        pktl += sizeof ra6_dsrch + dns_search_blob->size() + dns_search_slack;
    }

    auto llab = asio::ip::address_v6::any().to_bytes();
    auto dstb = mc6_allhosts.to_bytes();
    csum = net_checksum161c_add(csum, net_checksum161c(&llab, sizeof llab));
    csum = net_checksum161c_add(csum, net_checksum161c(&dstb, sizeof dstb));
    csum = net_checksum161c_add(csum, net_checksum161c(&pktl, sizeof pktl));
    csum = net_checksum161c_add(csum, net_checksum161c(&icmp_nexthdr, 1));
    if (dns6_servers) {
        for (const auto &i: *dns6_servers) {
            auto db = i.to_bytes();
            csum = net_checksum161c_add(csum, net_checksum161c(&db, sizeof db));
        }
    }
    icmp_hdr.checksum(csum);

    asio::streambuf send_buffer;
    std::ostream os(&send_buffer);
    os << icmp_hdr << ra6adv_hdr << ra6_slla << ra6_mtu;
    for (const auto &i: ra6_pfxs)
        os << i;
    if (dns6_servers && dns6_servers->size()) {
        os << ra6_dns;
        for (const auto &i: *dns6_servers) {
            auto b6 = i.to_bytes();
            for (const auto &j: b6)
                os << j;
        }
    }
    if (dns_search_blob && dns_search_blob->size()) {
        os << ra6_dsrch;
        for (const auto &i: *dns_search_blob)
            os << i;
        uint8_t zerob(0);
        for (size_t i = 0; i < dns_search_slack; ++i)
            os << zerob;
    }

    asio::ip::icmp::endpoint dst(mc6_allhosts, 0);
    std::error_code ec;
    socket_.send_to(send_buffer.data(), dst, 0, ec);
}

void RA6Listener::start_receive()
{
    recv_buffer_.consume(recv_buffer_.size());
    socket_.async_receive_from
        (recv_buffer_.prepare(8192), remote_endpoint_,
         [this](const std::error_code &error, std::size_t bytes_xferred)
         {
             recv_buffer_.commit(bytes_xferred);

             // Discard if the ICMP length < 8 octets.
             std::size_t bytes_left = bytes_xferred;
             if (bytes_xferred < icmp_header::size
                                 + ra6_solicit_header::size) {
                fmt::print(stderr, "ICMP from {} is too short: {}\n", remote_endpoint_, bytes_xferred);
                start_receive();
                return;
             }

             std::istream is(&recv_buffer_);
             icmp_header icmp_hdr;
             is >> icmp_hdr;
             bytes_left -= icmp_header::size;

             // XXX: Discard if the ip header hop limit field != 255
#if 0
             if (ipv6_hdr.hop_limit() != 255) {
                fmt::print(stderr, "Hop limit != 255\n");
                start_receive();
                return;
             }
#endif

             if (!using_bpf_) {
                 // Discard if the ICMP code is not 0.
                 if (icmp_hdr.code() != 0) {
                    fmt::print(stderr, "ICMP code != 0\n");
                    start_receive();
                    return;
                 }

                 if (icmp_hdr.type() != 133) {
                    fmt::print(stderr, "ICMP type != 133\n");
                    start_receive();
                    return;
                 }
             }

             ra6_solicit_header ra6_solicit_hdr;
             is >> ra6_solicit_hdr;
             bytes_left -= ra6_solicit_header::size;

             uint8_t macaddr[6];
             bool got_macaddr(false);

             // Only the source link-layer address option is defined.
             while (bytes_left > 1) {
                 uint8_t opt_type(is.get());
                 std::size_t opt_length(8 * is.get());
                 // Discard if any included option has a length <= 0.
                 if (opt_length <= 0) {
                     fmt::print(stderr, "Solicitation option length == 0\n");
                     start_receive();
                     return;
                 }
                 if (opt_type == 1 && opt_length == 8 && !got_macaddr) {
                     got_macaddr = true;
                     for (size_t i = 0; i < sizeof macaddr; ++i)
                         macaddr[i] = is.get();
                 } else {
                     if (opt_type == 1) {
                         if (opt_length != 8)
                             fmt::print(stderr, "Source Link-Layer Address is wrong size for ethernet.\n");
                         else
                             fmt::print(stderr, "Solicitation has more than one Source Link-Layer Address option.  Using the first.\n");
                     }
                     for (size_t i = 0; i < opt_length - 2; ++i)
                         is.get();
                 }
                 bytes_left -= opt_length;
             }

             // Discard if the source address is unspecified and
             // there is no source link-layer address option included.
             if (!got_macaddr && remote_endpoint_.address().is_unspecified()) {
                fmt::print(stderr, "Solicitation provides no specified source address or option.\n");
                start_receive();
                return;
             }

             // Send a router advertisement in reply.
             try {
                 timer_.cancel();
                 send_advert();
                 start_periodic_announce();
             } catch (const std::out_of_range &) {}

             start_receive();
         });
}


