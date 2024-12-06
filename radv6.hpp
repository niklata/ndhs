// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_RADV6_HPP_
#define NDHS_RADV6_HPP_

#include <time.h>
#include <nk/sys/posix/handle.hpp>
#include "sbufs.h"
extern "C" {
#include <net/if.h>
}

struct RA6Listener
{
    RA6Listener() {}
    RA6Listener(const RA6Listener &) = delete;
    RA6Listener &operator=(const RA6Listener &) = delete;

    [[nodiscard]] bool init(const char *ifname);
    void process_input();
    int send_periodic_advert();
    auto fd() const { return fd_(); }
    const char *ifname() const { return ifname_; }
private:
    void process_receive(char *buf, size_t buflen,
                         const sockaddr_storage &sai, socklen_t sailen);
    void set_advi_s_max(unsigned v);
    void set_next_advert_ts();
    [[nodiscard]] bool send_advert();
    void attach_bpf(int fd);
    struct timespec advert_ts_;
    char ifname_[IFNAMSIZ];
    nk::sys::handle fd_;
    unsigned advi_s_max_;
    bool using_bpf_:1;
};

#endif
