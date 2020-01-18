#ifndef NK_NRAD6_DHCP6_HPP_
#define NK_NRAD6_DHCP6_HPP_

#include <string>
#include <stdint.h>
#include <iterator>
#include <asio.hpp>
#include <fmt/printf.h>
#include <nk/netbits.hpp>
#include "dhcp_state.hpp"
#include "radv6.hpp"

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
    dhcp6_header() : type_(0), xid_(0) {}
    uint32_t xid() const { return xid_; }
    void xid(uint32_t xid) { xid_ = xid; }
    dhcp6_msgtype msg_type() const {
        if (type_ >= 1 && type_ <= 13)
            return static_cast<dhcp6_msgtype>(type_);
        return dhcp6_msgtype::unknown;
    };
    void msg_type(dhcp6_msgtype v) { type_ = static_cast<uint8_t>(v); }
    static const std::size_t size = 4;
    friend std::istream& operator>>(std::istream &is, dhcp6_header &header)
    {
        is.read(reinterpret_cast<char *>(&header.type_), 1);
        char tt[4] = {0};
        is.read(tt, 3);
        memcpy(&header.xid_, tt, 4);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const dhcp6_header &header)
    {
        os.write(reinterpret_cast<const char *>(&header.type_), 1);
        char tt[4] = {0};
        memcpy(tt, &header.xid_, 4);
        return os.write(tt, 3);
    }
private:
    uint8_t type_;
    uint32_t xid_;
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
    friend std::istream& operator>>(std::istream &is, dhcp6_opt &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const dhcp6_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
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
    friend std::ostream& operator<<(std::ostream &os, const dhcp6_opt_serverid &opt)
    {
        dhcp6_opt header;
        header.type(2);
        header.length(opt.duid_len_);
        os << header;
        return os.write(opt.duid_string_, opt.duid_len_);
    }
};

struct d6_ia_addr {
    asio::ip::address_v6 addr;
    uint32_t prefer_lifetime;
    uint32_t valid_lifetime;
    static const std::size_t size = 24;
    friend std::istream& operator>>(std::istream &is, d6_ia_addr &ia)
    {
        asio::ip::address_v6::bytes_type addrbytes;
        char data[24];
        is.read(data, sizeof data);
        memcpy(&addrbytes, data, 16);
        ia.addr = asio::ip::address_v6(addrbytes);
        ia.prefer_lifetime = decode32be(data + 16);
        ia.valid_lifetime = decode32be(data + 20);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const d6_ia_addr &ia)
    {
        char data[24];
        const auto bytes = ia.addr.to_bytes();
        memcpy(data, bytes.data(), 16);
        encode32be(ia.prefer_lifetime, data + 16);
        encode32be(ia.valid_lifetime, data + 20);
        return os.write(data, sizeof data);
    }
};
struct d6_ia {
    uint32_t iaid;
    uint32_t t1_seconds;
    uint32_t t2_seconds;
    std::vector<d6_ia_addr> ia_na_addrs;
    static const std::size_t size = 12;
    friend std::istream& operator>>(std::istream &is, d6_ia &ia)
    {
        char data[12];
        is.read(data, size);
        ia.iaid = decode32be(data);
        ia.t1_seconds = decode32be(data + 4);
        ia.t2_seconds = decode32be(data + 8);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os, const d6_ia &ia)
    {
        char data[12];
        encode32be(ia.iaid, data);
        encode32be(ia.t1_seconds, data + 4);
        encode32be(ia.t2_seconds, data + 8);
        return os.write(data, sizeof data);
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
    friend std::ostream& operator<<(std::ostream &os, const d6_statuscode &statuscode)
    {
        auto ct = static_cast<uint16_t>(statuscode.status_code);
        char data[2];
        encode16be(ct, data);
        return os.write(data, sizeof data);
    }
};

class D6Listener
{
public:
    D6Listener(asio::io_service &io_service, const std::string &ifname, uint8_t preference);
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

    bool allot_dynamic_ip(const d6msg_state &d6s, std::ostream &os, uint32_t iaid,
                          d6_statuscode::code failcode);
    void emit_IA_addr(const d6msg_state &d6s, std::ostream &os, const dhcpv6_entry *v);
    void emit_IA_code(const d6msg_state &d6s, std::ostream &os, uint32_t iaid,
                      d6_statuscode::code scode);
    bool attach_address_info(const d6msg_state &d6s, std::ostream &os,
                             d6_statuscode::code failcode);
    void attach_dns_ntp_info(const d6msg_state &d6s, std::ostream &os);
    void attach_status_code(const d6msg_state &d6s, std::ostream &os, d6_statuscode::code scode);
    void write_response_header(const d6msg_state &d6s, std::ostream &os, dhcp6_msgtype mtype);
    void handle_solicit_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    void handle_request_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    bool confirm_match(const d6msg_state &d6s, std::ostream &os);
    bool mark_addr_unused(const d6msg_state &d6s, std::ostream &os);
    bool handle_confirm_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    void handle_renew_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    void handle_rebind_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    void handle_information_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    void handle_release_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    void handle_decline_msg(const d6msg_state &d6s, asio::streambuf &send_buffer);
    bool serverid_incorrect(const d6msg_state &d6s) const;
    void start_receive();
    void attach_bpf(int fd);
    asio::streambuf recv_buffer_;
    asio::ip::udp::endpoint sender_endpoint_;
    asio::ip::address_v6 local_ip_;
    asio::ip::address_v6 local_ip_prefix_;
    asio::ip::address_v6 link_local_ip_;
    asio::ip::udp::socket socket_;
    std::string ifname_;
    std::unique_ptr<RA6Listener> radv6_listener_;
    bool using_bpf_:1;
    char prefixlen_;
    uint8_t preference_;

    [[nodiscard]] bool bytes_left_dec(d6msg_state &d6s, std::size_t &bytes_left, size_t v);
};

#endif

