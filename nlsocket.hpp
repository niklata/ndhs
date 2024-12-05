// Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_NLSOCKET_HPP_
#define NDHS_NLSOCKET_HPP_
#include <stdint.h>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <nk/sys/posix/handle.hpp>
#include <nk/net/ip_address.hpp>
extern "C" {
#include <net/if.h>
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

    char if_name[IFNAMSIZ];
    int if_index;
    nk::ip_address address;
    nk::ip_address peer_address;
    nk::ip_address broadcast_address;
    nk::ip_address anycast_address;
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
    NLSocket(std::vector<std::string> &&ifnames);
    NLSocket(const NLSocket &) = delete;
    NLSocket &operator=(const NLSocket &) = delete;

    void process_input();
    auto fd() const { return fd_(); }
    [[nodiscard]] std::optional<int> get_ifindex(const std::string &name) {
        auto elt = name_to_ifindex_.find(name);
        if (elt == name_to_ifindex_.end()) return {};
        return elt->second;
    }

    [[nodiscard]] netif_info *get_ifinfo(int ifindex)
    {
        if (auto elt = interfaces_.find(ifindex); elt != interfaces_.end()) {
            return &elt->second;
        }
        return nullptr;
    }
    [[nodiscard]] netif_info *get_ifinfo(const std::string &name)
    {
        auto alt = name_to_ifindex_.find(name);
        if (alt == name_to_ifindex_.end()) return nullptr;
        return get_ifinfo(alt->second);
    }
private:
    void process_receive(const char *buf, size_t bytes_xferred,
                         unsigned seq, unsigned portid);
    void process_rt_link_msgs(const struct nlmsghdr *nlh);
    void process_rt_addr_msgs(const struct nlmsghdr *nlh);
    void process_nlmsg(const struct nlmsghdr *nlh);
    void request_links();
    void request_addrs(int ifidx);
    std::map<std::string, int> name_to_ifindex_;
    std::map<int, netif_info> interfaces_;
    std::vector<std::string> ifnames_;
    std::optional<int> query_ifindex_;
    nk::sys::handle fd_;
    uint32_t nlseq_;
    bool got_newlink_:1;
};

#endif
