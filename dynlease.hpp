// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DYNLEASE_HPP_
#define NDHS_DYNLEASE_HPP_

#include <string>
#include <nk/net/ip_address.hpp>

size_t dynlease4_count(const char *interface);
size_t dynlease6_count(const char *interface);
void dynlease_gc();
bool dynlease_add(const char *interface, const nk::ip_address &addr,
                  const uint8_t *macaddr, int64_t expire_time);
bool dynlease_add(const char *interface, const nk::ip_address &addr,
                  const std::string &duid, uint32_t iaid, int64_t expire_time);
const nk::ip_address &
dynlease_query_refresh(const char *interface, const uint8_t *macaddr,
                       int64_t expire_time);
const nk::ip_address &
dynlease_query_refresh(const char *interface, const std::string &duid,
                       uint32_t iaid, int64_t expire_time);
bool dynlease_exists(const char *interface, const nk::ip_address &addr,
                     const uint8_t *macaddr);
bool dynlease_exists(const char *interface, const nk::ip_address &addr,
                     const std::string &duid, uint32_t iaid);
bool dynlease_del(const char *interface, const nk::ip_address &addr,
                  const uint8_t *macaddr);
bool dynlease_del(const char *interface, const nk::ip_address &addr,
                  const std::string &duid, uint32_t iaid);

bool dynlease_unused_addr(const char *interface, const nk::ip_address &addr);

bool dynlease_serialize(const std::string &path);
bool dynlease_deserialize(const std::string &path);

#endif
