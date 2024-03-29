// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NRAD6_DYNLEASE_HPP_
#define NRAD6_DYNLEASE_HPP_

#include <string>
#include <nk/net/ip_address.hpp>

size_t dynlease4_count(const std::string &interface);
size_t dynlease6_count(const std::string &interface);
void dynlease_gc();
bool dynlease_add(const std::string &interface, const nk::ip_address &addr,
                  const uint8_t *macaddr, int64_t expire_time);
bool dynlease_add(const std::string &interface, const nk::ip_address &addr,
                  const std::string &duid, uint32_t iaid, int64_t expire_time);
const nk::ip_address &
dynlease_query_refresh(const std::string &interface, const uint8_t *macaddr,
                       int64_t expire_time);
const nk::ip_address &
dynlease_query_refresh(const std::string &interface, const std::string &duid,
                       uint32_t iaid, int64_t expire_time);
bool dynlease_exists(const std::string &interface, const nk::ip_address &addr,
                     const uint8_t *macaddr);
bool dynlease_exists(const std::string &interface, const nk::ip_address &addr,
                     const std::string &duid, uint32_t iaid);
bool dynlease_del(const std::string &interface, const nk::ip_address &addr,
                  const uint8_t *macaddr);
bool dynlease_del(const std::string &interface, const nk::ip_address &addr,
                  const std::string &duid, uint32_t iaid);

bool dynlease_unused_addr(const std::string &interface, const nk::ip_address &addr);

bool dynlease_serialize(const std::string &path);
bool dynlease_deserialize(const std::string &path);

#endif
