// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP6_HPP_
#define NDHS_DHCP6_HPP_

#include <stdint.h>
#include <nk/netbits.h>
#include "dhcp_state.hpp"
#include "radv6.hpp"
#include "sbufs.h"
extern "C" {
#include <ipaddr.h>
#include <net/if.h>
}

enum class dhcp6_msgtype {
    unknown = 0,
    solicit = 1,
    advertise = 2,
    request = 3,
    confirm = 4,
    renew = 5,
    rebind = 6,
    reply = 7,
    release = 8,
    decline = 9,
    reconfigure = 10,
    information_request = 11,
    relay_forward = 12,
    relay_reply = 13,
};

// Packet header.
struct dhcp6_header
{
    dhcp6_msgtype msg_type() const {
        if (type_ >= 1 && type_ <= 13)
            return static_cast<dhcp6_msgtype>(type_);
        return dhcp6_msgtype::unknown;
    };
    void msg_type(dhcp6_msgtype v) { type_ = static_cast<uint8_t>(v); }
    static const size_t size = 4;

    bool read(sbufs &rbuf)
    {
        if (rbuf.brem() < size) return false;
        memcpy(&type_, rbuf.si, sizeof type_);
        memcpy(&xid_, rbuf.si + 1, sizeof xid_);
        rbuf.si += size;
        return true;
    }
    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        memcpy(sbuf.si, &type_, sizeof type_);
        memcpy(sbuf.si + 1, &xid_, sizeof xid_);
        sbuf.si += size;
        return true;
    }
private:
    uint8_t type_ = 0;
    char xid_[3] = {};
};

#define D6_MAX_IAS 4
#define D6_MAX_IA_ADDRS 4

struct d6_ia_addr {
    in6_addr addr;
    uint32_t prefer_lifetime;
    uint32_t valid_lifetime;
    static const size_t size = 24;

    bool read(sbufs &rbuf)
    {
        if (rbuf.brem() < size) return false;
        memcpy(&addr, rbuf.si, sizeof addr);
        prefer_lifetime = 0; // RFC8415 S25
        valid_lifetime = 0; // RFC8415 S25
        rbuf.si += size;
        return true;
    }
    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        memcpy(sbuf.si, &addr, sizeof addr);
        encode32be(prefer_lifetime, sbuf.si + 16);
        encode32be(valid_lifetime, sbuf.si + 20);
        sbuf.si += size;
        return true;
    }
};
struct d6_ia {
    uint32_t iaid;
    uint32_t t1_seconds;
    uint32_t t2_seconds;
    size_t ia_na_addrs_n;
    d6_ia_addr ia_na_addrs[D6_MAX_IA_ADDRS];
    static const size_t size = 12;

    d6_ia() : ia_na_addrs_n(0) {}

    bool read(sbufs &rbuf)
    {
        if (rbuf.brem() < size) return false;
        iaid = decode32be(rbuf.si);
        t1_seconds = 0; // RFC8415 S25
        t2_seconds = 0; // RFC8415 S25
        rbuf.si += size;
        return true;
    }
    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        encode32be(iaid, sbuf.si);
        encode32be(t1_seconds, sbuf.si + 4);
        encode32be(t2_seconds, sbuf.si + 8);
        sbuf.si += size;
        return true;
    }
};
struct d6_statuscode
{
    enum class code {
        success = 0,
        unspecfail = 1,
        noaddrsavail = 2,
        nobinding = 3,
        notonlink = 4,
        usemulticast = 5,
    };
    d6_statuscode() : status_code(code::success) {}
    explicit d6_statuscode(code c) : status_code(c) {}
    code status_code;
    static const size_t size = 2;

    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        encode16be(static_cast<uint16_t>(status_code), sbuf.si);
        sbuf.si += size;
        return true;
    }
};

#define D6_MAX_ENCAP_DEPTH 4

struct D6Listener
{
    D6Listener() {}
    D6Listener(const D6Listener &) = delete;
    D6Listener &operator=(const D6Listener &) = delete;

    [[nodiscard]] bool init(const char *ifname, uint8_t preference);
    void process_input();
    auto fd() const { return fd_; }
    const char *ifname() const { return ifname_; }
private:
    struct d6msg_state
    {
        d6msg_state() : ias_n(0), prev_opt_n(0), client_duid_str_size(0),
                        client_duid_blob_size(0), server_duid_blob_size(0),
                        optreq_exists(false), optreq_dns(false), optreq_dns_search(false),
                        optreq_sntp(false), optreq_info_refresh_time(false), optreq_ntp(false),
                        use_rapid_commit(false) {}
        dhcp6_header header;
        char client_duid_str[320];
        char client_duid_blob[128];
        char server_duid_blob[128];
        d6_ia ias[D6_MAX_IAS];
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

    bool create_dhcp6_socket();
    [[nodiscard]] bool allot_dynamic_ip(const char *client_duid, size_t client_duid_size,
                                        sbufs &ss, uint32_t iaid,
                                        d6_statuscode::code failcode, bool &use_dynamic);
    [[nodiscard]] bool emit_IA_addr(sbufs &ss, const dhcpv6_entry *v);
    [[nodiscard]] bool emit_IA_code(sbufs &ss, uint32_t iaid, d6_statuscode::code scode);
    [[nodiscard]] bool attach_address_info(const d6msg_state &d6s, sbufs &ss,
                                           d6_statuscode::code failcode, bool *has_addrs = nullptr);
    [[nodiscard]] bool attach_dns_ntp_info(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool attach_status_code(sbufs &ss, d6_statuscode::code scode);
    [[nodiscard]] bool write_response_header(const d6msg_state &d6s, sbufs &ss, dhcp6_msgtype mtype);
    [[nodiscard]] bool handle_solicit_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_request_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool confirm_match(const d6msg_state &d6s, bool &confirmed);
    [[nodiscard]] bool mark_addr_unused(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_confirm_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_renew_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_rebind_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_information_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_release_msg(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool handle_decline_msg(const d6msg_state &d6s, sbufs &ss);
    bool serverid_incorrect(const d6msg_state &d6s) const;
    void attach_bpf(int fd);
    void process_receive(char *buf, size_t buflen,
                         const sockaddr_storage &sai, socklen_t sailen);

    in6_addr local_ip_;
    in6_addr local_ip_prefix_;
    in6_addr link_local_ip_;
    char ifname_[IFNAMSIZ];
    int ifindex_;
    int fd_;
    unsigned char prefixlen_;
    uint8_t preference_;
    bool using_bpf_:1;

    [[nodiscard]] bool options_consume(d6msg_state &d6s, size_t v);
};

#endif
