#ifndef NK_NRAD6_DHCP_STATE_HPP_
#define NK_NRAD6_DHCP_STATE_HPP_

#include <boost/asio.hpp>

struct dhcpv6_entry {
    dhcpv6_entry(uint32_t iaid_, const boost::asio::ip::address_v6 &addr_, uint32_t lifetime_)
        : address(addr_), iaid(iaid_), lifetime(lifetime_) {}
    boost::asio::ip::address_v6 address;
    uint32_t iaid;
    uint32_t lifetime;
};

struct dhcpv4_entry {
    dhcpv4_entry(const boost::asio::ip::address_v4 &addr_, uint32_t lifetime_)
        : address(addr_), lifetime(lifetime_) {}
    boost::asio::ip::address_v4 address;
    uint32_t lifetime;
};

void create_blobs();
bool emplace_bind(size_t linenum, std::string &&interface, bool is_v4);
bool emplace_interface(size_t linenum, const std::string &interface);
bool emplace_dhcp_state(size_t linenum, const std::string &interface, std::string &&duid,
                        uint32_t iaid, const std::string &v6_addr, uint32_t default_lifetime);
bool emplace_dhcp_state(size_t linenum, const std::string &interface, const std::string &macaddr,
                        const std::string &v4_addr, uint32_t default_lifetime);
bool emplace_dns_server(size_t linenum, const std::string &interface,
                        const std::string &addr, bool is_v4);
bool emplace_ntp_server(size_t linenum, const std::string &interface,
                        const std::string &addr, bool is_v4);
bool emplace_subnet(size_t linenum, const std::string &interface, const std::string &addr);
bool emplace_gateway(size_t linenum, const std::string &interface, const std::string &addr);
bool emplace_broadcast(size_t linenum, const std::string &interface, const std::string &addr);
bool emplace_dynamic_range(size_t linenum, const std::string &interface,
                           const std::string &lo_addr, const std::string &hi_addr,
                           uint32_t dynamic_lifetime);
bool emplace_dns_search(size_t linenum, const std::string &interface, std::string &&label);
const dhcpv6_entry* query_dhcp_state(const std::string &interface, const std::string &duid,
                                     uint32_t iaid);
const dhcpv4_entry* query_dhcp_state(const std::string &interface, const uint8_t *hwaddr);
const std::vector<boost::asio::ip::address_v6> &query_dns6_servers(const std::string &interface);
const std::vector<boost::asio::ip::address_v4> &query_dns4_servers(const std::string &interface);
const std::vector<uint8_t> &query_dns6_search_blob(const std::string &interface);
const std::vector<boost::asio::ip::address_v6> &query_ntp6_servers(const std::string &interface);
const std::vector<boost::asio::ip::address_v4> &query_ntp4_servers(const std::string &interface);
const std::vector<uint8_t> &query_ntp6_fqdns_blob(const std::string &interface);
const std::vector<boost::asio::ip::address_v6> &query_ntp6_multicasts(const std::string &interface);
const std::vector<boost::asio::ip::address_v4> &query_gateway(const std::string &interface);
const boost::asio::ip::address_v4 &query_subnet(const std::string &interface);
const boost::asio::ip::address_v4 &query_broadcast(const std::string &interface);
const std::pair<boost::asio::ip::address_v4, boost::asio::ip::address_v4>
    &query_dynamic_range(const std::string &interface, uint32_t &dynamic_lifetime);
const std::vector<std::string> &query_dns_search(const std::string &interface);
bool query_use_dynamic_v4(const std::string &interface);
bool query_use_dynamic_v6(const std::string &interface);
size_t bound_interfaces_count();
void bound_interfaces_foreach(std::function<void(const std::string&, bool, bool)> fn);

#endif

