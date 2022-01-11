#ifndef NRAD6_RADV6_HPP_
#define NRAD6_RADV6_HPP_

#include <string>
#include <chrono>
#include <nk/sys/posix/handle.hpp>
#include "sbufs.h"

class RA6Listener
{
public:
    RA6Listener() {}
    RA6Listener(const RA6Listener &) = delete;
    RA6Listener &operator=(const RA6Listener &) = delete;

    [[nodiscard]] bool init(const std::string &ifname);
    void process_input();
    int send_periodic_advert();
    auto fd() const { return fd_(); }
    auto& ifname() const { return ifname_; }
private:
    void process_receive(char *buf, std::size_t buflen,
                         const sockaddr_storage &sai, socklen_t sailen);
    void set_advi_s_max(unsigned int v);
    void set_next_advert_ts();
    [[nodiscard]] bool send_advert();
    void attach_bpf(int fd);
    std::chrono::steady_clock::time_point advert_ts_;
    std::string ifname_;
    nk::sys::handle fd_;
    unsigned int advi_s_max_;
    bool using_bpf_:1;
};

#endif
