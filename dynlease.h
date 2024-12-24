// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_DYNLEASE_H_
#define NDHS_DYNLEASE_H_

#include <ipaddr.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t dynlease6_count(int ifindex);
void dynlease_gc(void);
bool dynlease4_add(int ifindex, const struct in6_addr *addr,
                   const uint8_t *macaddr, int64_t expire_time);
bool dynlease6_add(int ifindex, const struct in6_addr *addr,
                   const char *duid, size_t duid_len,
                   uint32_t iaid, int64_t expire_time);
struct in6_addr dynlease4_query_refresh(int ifindex, const uint8_t *macaddr,
                                        int64_t expire_time);
struct in6_addr dynlease6_query_refresh(int ifindex,
                                        const char *duid, size_t duid_len,
                                        uint32_t iaid, int64_t expire_time);
bool dynlease4_exists(int ifindex, const struct in6_addr *addr,
                      const uint8_t *macaddr);
bool dynlease4_del(int ifindex, const struct in6_addr *addr,
                   const uint8_t *macaddr);
bool dynlease6_del(int ifindex, const struct in6_addr *addr,
                   const char *duid, size_t duid_len, uint32_t iaid);
bool dynlease_serialize(const char *path);
bool dynlease_deserialize(const char *path);

#ifdef __cplusplus
}
#endif

#endif
