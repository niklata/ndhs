#ifndef NRAD6_DYNLEASE_HPP_
#define NRAD6_DYNLEASE_HPP_

#include <string>
#include <asio.hpp>

size_t dynlease4_count(const std::string &interface);
size_t dynlease6_count(const std::string &interface);
bool dynlease_add(const std::string &interface, const asio::ip::address_v4 &addr,
                  const uint8_t *macaddr, int64_t expire_time);
bool dynlease_add(const std::string &interface, const asio::ip::address_v6 &addr,
                  const std::string &duid, uint32_t iaid, int64_t expire_time);
const asio::ip::address_v4 &
dynlease_query_refresh(const std::string &interface, const uint8_t *macaddr,
                       int64_t expire_time);
const asio::ip::address_v6 &
dynlease_query_refresh(const std::string &interface, const std::string &duid,
                       uint32_t iaid, int64_t expire_time);
bool dynlease_exists(const std::string &interface, const asio::ip::address_v4 &addr,
                     const uint8_t *macaddr);
bool dynlease_exists(const std::string &interface, const asio::ip::address_v6 &addr,
                     const std::string &duid, uint32_t iaid);
bool dynlease_del(const std::string &interface, const asio::ip::address_v4 &addr,
                  const uint8_t *macaddr);
bool dynlease_del(const std::string &interface, const asio::ip::address_v6 &addr,
                  const std::string &duid, uint32_t iaid);

bool dynlease_unused_addr(const std::string &interface, const asio::ip::address_v6 &addr);

bool dynlease_serialize(const std::string &path);
bool dynlease_deserialize(const std::string &path);

#endif
