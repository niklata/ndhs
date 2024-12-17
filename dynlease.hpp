// Copyright 2016-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DYNLEASE_HPP_
#define NDHS_DYNLEASE_HPP_

#include <ipaddr.h>

size_t dynlease4_count(const char *interface);
size_t dynlease6_count(const char *interface);
void dynlease_gc();
bool dynlease4_add(const char *interface, const in6_addr *addr,
                   const uint8_t *macaddr, int64_t expire_time);
bool dynlease6_add(const char *interface, const in6_addr *addr,
                   const char *duid, size_t duid_len,
                   uint32_t iaid, int64_t expire_time);
in6_addr dynlease4_query_refresh(const char *interface, const uint8_t *macaddr,
                                 int64_t expire_time);
in6_addr dynlease6_query_refresh(const char *interface,
                                 const char *duid, size_t duid_len,
                                 uint32_t iaid, int64_t expire_time);
bool dynlease4_exists(const char *interface, const in6_addr *addr,
                      const uint8_t *macaddr);
bool dynlease6_exists(const char *interface, const in6_addr *addr,
                      const char *duid, size_t duid_len, uint32_t iaid);
bool dynlease4_del(const char *interface, const in6_addr *addr,
                   const uint8_t *macaddr);
bool dynlease6_del(const char *interface, const in6_addr *addr,
                   const char *duid, size_t duid_len, uint32_t iaid);

bool dynlease_unused_addr(const char *interface, const in6_addr *addr);

bool dynlease_serialize(const char *path);
bool dynlease_deserialize(const char *path);

#endif
