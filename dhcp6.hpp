// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DHCP6_HPP_
#define NDHS_DHCP6_HPP_

#include <stdint.h>
#include <nk/netbits.h>
#include "dhcp_state.h"
#include "radv6.hpp"
#include "sbufs.h"
extern "C" {
#include <ipaddr.h>
#include <net/if.h>
}

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
};
enum dhcp6_code {
    D6_CODE_SUCCESS = 0,
    D6_CODE_UNSPECFAIL = 1,
    D6_CODE_NOADDRSAVAIL = 2,
    D6_CODE_NOBINDING = 3,
    D6_CODE_NOTONLINK = 4,
    D6_CODE_USEMULTICAST = 5,
};

// Packet header.
struct dhcp6_header
{
    uint8_t type;
    char xid[3];
};

#define D6_MAX_IAS 4
#define D6_MAX_IA_ADDRS 4
#define D6_MAX_ENCAP_DEPTH 4

struct dhcp6_ia_addr {
    in6_addr addr;
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
                        use_rapid_commit(false) {
            memset(ias, 0, sizeof ias);
        }
        dhcp6_header header;
        char client_duid_str[320];
        char client_duid_blob[128];
        char server_duid_blob[128];
        dhcp6_ia_na ias[D6_MAX_IAS];
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
                                        dhcp6_code failcode, bool &use_dynamic);
    [[nodiscard]] bool emit_IA_addr(sbufs &ss, in6_addr ipa, uint32_t iaid, uint32_t lifetime);
    [[nodiscard]] bool emit_IA_code(sbufs &ss, uint32_t iaid, dhcp6_code scode);
    [[nodiscard]] bool attach_address_info(const d6msg_state &d6s, sbufs &ss,
                                           dhcp6_code failcode, bool *has_addrs = nullptr);
    [[nodiscard]] bool attach_dns_ntp_info(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool attach_status_code(sbufs &ss, dhcp6_code scode);
    [[nodiscard]] bool write_response_header(const d6msg_state &d6s, sbufs &ss, dhcp6_msgtype mtype);
    [[nodiscard]] bool confirm_match(const d6msg_state &d6s, bool &confirmed);
    [[nodiscard]] bool mark_addr_unused(const d6msg_state &d6s, sbufs &ss);
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
