#ifndef NK_NRAD6_DHCP6_HPP_
#define NK_NRAD6_DHCP6_HPP_

#include <string>
#include <stdint.h>
#include <iterator>
#include <asio.hpp>
#include <nk/netbits.hpp>
#include <nk/sys/posix/handle.hpp>
#include "dhcp_state.hpp"
#include "radv6.hpp"
#include "sbufs.h"

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
class dhcp6_header
{
public:
    dhcp6_header() : type_(0), xid_{0, 0, 0} {}
    dhcp6_header(const dhcp6_header &o) : type_(o.type_) {
        memcpy(xid_, o.xid_, sizeof xid_);
    }
    dhcp6_header &operator=(const dhcp6_header &o) {
        type_ = o.type_;
        memcpy(xid_, o.xid_, sizeof xid_);
        return *this;
    }
    dhcp6_msgtype msg_type() const {
        if (type_ >= 1 && type_ <= 13)
            return static_cast<dhcp6_msgtype>(type_);
        return dhcp6_msgtype::unknown;
    };
    void msg_type(dhcp6_msgtype v) { type_ = static_cast<uint8_t>(v); }
    static const std::size_t size = 4;

    int read(const void *buf, size_t len)
    {
        if (len < size) return -1;
        auto b = static_cast<const char *>(buf);
        memcpy(&type_, b, sizeof type_);
        memcpy(&xid_, b + 1, sizeof xid_);
        return size;
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
    uint8_t type_;
    char xid_[3];
};

// Option header.
class dhcp6_opt
{
public:
    dhcp6_opt() { std::fill(data_, data_ + sizeof data_, 0); }
    uint16_t type() const { return decode16be(data_); }
    uint16_t length() const { return decode16be(data_ + 2); }
    void type(uint16_t v) { encode16be(v, data_); }
    void length(uint16_t v) { encode16be(v, data_ + 2); }
    static const std::size_t size = 4;

    int read(const void *buf, size_t len)
    {
        if (len < size) return -1;
        auto b = static_cast<const char *>(buf);
        memcpy(&data_, b, sizeof data_);
        return size;
    }
    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        memcpy(sbuf.si, &data_, sizeof data_);
        sbuf.si += size;
        return true;
    }
private:
    uint8_t data_[4];
};

// Server Identifier Option
struct dhcp6_opt_serverid
{
    dhcp6_opt_serverid(const char *s, size_t slen) : duid_string_(s), duid_len_(slen) {}
    const char *duid_string_;
    size_t duid_len_;

    bool write(sbufs &sbuf) const
    {
        const auto size = dhcp6_opt::size + duid_len_;
        if (sbuf.brem() < size) return false;
        dhcp6_opt header;
        header.type(2);
        header.length(duid_len_);
        if (!header.write(sbuf)) return false;
        memcpy(sbuf.si, duid_string_, duid_len_);
        sbuf.si += duid_len_;
        return true;
    }
};

struct d6_ia_addr {
    asio::ip::address_v6 addr;
    uint32_t prefer_lifetime;
    uint32_t valid_lifetime;
    static const std::size_t size = 24;

    int read(const void *buf, size_t len)
    {
        if (len < size) return -1;
        auto b = static_cast<const char *>(buf);
        asio::ip::address_v6::bytes_type addrbytes;
        memcpy(&addrbytes, b, 16);
        char data[8];
        memcpy(&data, b + 16, sizeof data);
        addr = asio::ip::address_v6(addrbytes);
        prefer_lifetime = decode32be(data);
        valid_lifetime = decode32be(data + 4);
        return size;
    }
    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        const auto bytes = addr.to_bytes();
        memcpy(sbuf.si, bytes.data(), 16);
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
    std::vector<d6_ia_addr> ia_na_addrs;
    static const std::size_t size = 12;

    int read(const void *buf, size_t len)
    {
        if (len < size) return -1;
        auto b = static_cast<const char *>(buf);
        char data[12];
        memcpy(data, b, sizeof data);
        iaid = decode32be(data);
        t1_seconds = decode32be(data + 4);
        t2_seconds = decode32be(data + 8);
        return size;
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
    static const std::size_t size = 2;

    bool write(sbufs &sbuf) const
    {
        if (sbuf.brem() < size) return false;
        encode16be(static_cast<uint16_t>(status_code), sbuf.si);
        sbuf.si += size;
        return true;
    }
};

class D6Listener
{
public:
    D6Listener() {}
    D6Listener(const D6Listener &) = delete;
    D6Listener &operator=(const D6Listener &) = delete;

    [[nodiscard]] bool init(const std::string &ifname, uint8_t preference);
    void process_input();
    auto fd() const { return fd_(); }
    auto& ifname() const { return ifname_; }
private:
    using prev_opt_state = std::pair<int8_t, uint16_t>; // Type of parent opt and length left
    struct d6msg_state
    {
        d6msg_state() : optreq_exists(false), optreq_dns(false), optreq_dns_search(false),
                        optreq_sntp(false), optreq_info_refresh_time(false), optreq_ntp(false),
                        use_rapid_commit(false) {}
        dhcp6_header header;
        std::string fqdn_;
        std::string client_duid;
        std::vector<uint8_t> client_duid_blob;
        std::vector<uint8_t> server_duid_blob;
        std::vector<d6_ia> ias;
        std::vector<prev_opt_state> prev_opt;
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
    [[nodiscard]] bool allot_dynamic_ip(const d6msg_state &d6s, sbufs &ss, uint32_t iaid,
                                        d6_statuscode::code failcode, bool &use_dynamic);
    [[nodiscard]] bool emit_IA_addr(const d6msg_state &d6s, sbufs &ss, const dhcpv6_entry *v);
    [[nodiscard]] bool emit_IA_code(const d6msg_state &d6s, sbufs &ss, uint32_t iaid,
                                    d6_statuscode::code scode);
    [[nodiscard]] bool attach_address_info(const d6msg_state &d6s, sbufs &ss,
                                           d6_statuscode::code failcode, bool *has_addrs = nullptr);
    [[nodiscard]] bool attach_dns_ntp_info(const d6msg_state &d6s, sbufs &ss);
    [[nodiscard]] bool attach_status_code(const d6msg_state &d6s, sbufs &ss, d6_statuscode::code scode);
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
    void process_receive(char *buf, std::size_t buflen,
                         const sockaddr_storage &sai, socklen_t sailen);

    asio::ip::address_v6 local_ip_;
    asio::ip::address_v6 local_ip_prefix_;
    asio::ip::address_v6 link_local_ip_;
    std::string ifname_;
    nk::sys::handle fd_;
    bool using_bpf_:1;
    char prefixlen_;
    uint8_t preference_;

    [[nodiscard]] bool options_consume(d6msg_state &d6s, size_t v);
};

#endif

