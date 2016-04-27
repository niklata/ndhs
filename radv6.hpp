#ifndef NRAD6_RADV6_HPP_
#define NRAD6_RADV6_HPP_

#include <string>
#include <memory>
#include <boost/asio.hpp>

class RA6Listener
{
public:
    RA6Listener(boost::asio::io_service &io_service,
                const std::string &ifname);
    void set_advi_s_max(unsigned int v);
private:
    void start_periodic_announce();
    void send_advert();
    void start_receive();
    void attach_bpf(int fd);
    boost::asio::deadline_timer timer_;
    boost::asio::ip::icmp::socket socket_;
    boost::asio::ip::icmp::endpoint remote_endpoint_;
    std::string ifname_;
    unsigned int advi_s_max_;
    bool using_bpf_:1;
    boost::asio::streambuf recv_buffer_;
};

#endif
