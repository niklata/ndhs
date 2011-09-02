/* dhcpclient.hpp - dhcp client request handling
 *
 * (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef NK_DHCPCLIENT_H
#define NK_DHCPCLIENT_H

#include <string>
#include <netdb.h>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "dhcp.h"

struct ClientState {
    uint8_t state;
};

class ClientListener
{
public:
    ClientListener(boost::asio::io_service &io_service,
                   const boost::asio::ip::udp::endpoint &endpoint,
                   const std::string &ifname);
private:
    void start_receive(const boost::system::error_code &error,
                       std::size_t bytes_xferred);
    uint64_t getNowTs(void) const;
    void dhcpmsg_init(struct dhcpmsg *dm, char type,
                      const std::string &chaddr) const;
    uint32_t local_ip() const;
    std::string ipStr(uint32_t ip) const;
    void send_reply(struct dhcpmsg *dm);
    void reply_discover(ClientState *cs, const std::string &chaddr);
    void reply_request(ClientState *cs, const std::string &chaddr,
                       bool is_direct);
    void reply_inform(ClientState *cs, const std::string &chaddr);
    void do_release(ClientState *cs, const std::string &chaddr);
    std::string getChaddr(const struct dhcpmsg &dm) const;
    bool validate_dhcp(void) const;
    void handle_receive(const boost::system::error_code &error,
                        std::size_t bytes_xferred);

    boost::asio::ip::udp::socket socket_;
    //boost::asio::ip::udp::socket broadcast_socket_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    boost::array<uint8_t, 1024> recv_buffer_;
    struct dhcpmsg dhcpmsg_;
    boost::asio::ip::address local_ip_;
};

#endif /* NK_DHCPCLIENT_H */
