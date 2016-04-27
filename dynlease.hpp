#ifndef NRAD6_DYNLEASE_HPP_
#define NRAD6_DYNLEASE_HPP_

#include <string>
#include <boost/asio.hpp>

bool dynlease_add(const std::string &interface, const boost::asio::ip::address_v4 &addr,
                  const uint8_t *macaddr, int64_t expire_time);
bool dynlease_add(const std::string &interface, const boost::asio::ip::address_v6 &addr,
                  const std::string &duid, uint32_t iaid, int64_t expire_time);
const boost::asio::ip::address_v4 &
dynlease_query_refresh(const std::string &interface, const uint8_t *macaddr,
                       int64_t expire_time);
const boost::asio::ip::address_v6 &
dynlease_query_refresh(const std::string &interface, const std::string &duid,
                       uint32_t iaid, int64_t expire_time);
bool dynlease_exists(const std::string &interface, const boost::asio::ip::address_v4 &addr,
                     const uint8_t *macaddr);
bool dynlease_exists(const std::string &interface, const boost::asio::ip::address_v6 &addr,
                     const std::string &duid, uint32_t iaid);
bool dynlease_del(const std::string &interface, const boost::asio::ip::address_v4 &addr,
                  const uint8_t *macaddr);
bool dynlease_del(const std::string &interface, const boost::asio::ip::address_v6 &addr,
                  const std::string &duid, uint32_t iaid);
bool dynlease_serialize(const std::string &path);
bool dynlease_deserialize(const std::string &path);

#endif
