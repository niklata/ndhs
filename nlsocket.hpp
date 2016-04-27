#ifndef NRAD6_NLSOCKET_HPP_
#define NRAD6_NLSOCKET_HPP_
/* nlsocket.hpp - ipv6 netlink ifinfo gathering
 *
 * (c) 2014-2016 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdint.h>
#include <vector>
#include <string>
#include <array>
#include <map>
#include <asio.hpp>
#include "asio_netlink.hpp"
extern "C" {
#include "nl.h"
}

struct netif_addr
{
    enum class Scope {
        Global = RT_SCOPE_UNIVERSE,
        Site = RT_SCOPE_SITE,
        Link = RT_SCOPE_LINK,
        Host = RT_SCOPE_HOST,
        None = RT_SCOPE_NOWHERE,
    };

    std::string if_name;
    int if_index;
    asio::ip::address address;
    asio::ip::address peer_address;
    asio::ip::address broadcast_address;
    asio::ip::address anycast_address;
    unsigned char addr_type;
    unsigned char prefixlen;
    unsigned char flags;
    Scope scope;
};

struct netif_info
{
    std::string name;
    std::string qdisc;
    unsigned char family;
    unsigned short device_type;
    int index;
    unsigned int flags;
    unsigned int change_mask;
    unsigned int mtu;
    int link_type;
    char macaddr[6];
    char macbc[6];
    bool is_active:1;

    std::vector<netif_addr> addrs;
};

class NLSocket
{
public:
    NLSocket(asio::io_service &io_service);
    NLSocket(const NLSocket &) = delete;
    NLSocket &operator=(const NLSocket &) = delete;
    int get_ifindex(const std::string &name) const {
        auto elt = name_to_ifindex_.find(name);
        if (elt == name_to_ifindex_.end())
            throw std::out_of_range("No such interface");
        return elt->second;
    }
    std::map<int, netif_info> interfaces;
private:
    void start_receive();
    void process_receive(std::size_t bytes_xferred,
                         unsigned int seq, unsigned int portid);
    void process_rt_link_msgs(const struct nlmsghdr *nlh);
    void process_rt_addr_msgs(const struct nlmsghdr *nlh);
    void process_nlmsg(const struct nlmsghdr *nlh);
    void request_links();
    void request_addrs();
    void request_addrs(int ifidx);
    asio::basic_raw_socket<nl_protocol> socket_;
    nl_endpoint<nl_protocol> remote_endpoint_;
    std::array<uint8_t, 8192> recv_buffer_;
    std::map<std::string, int> name_to_ifindex_;
    int nlseq_;
    bool initialized_:1;
};

#endif

