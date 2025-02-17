// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef OPTIONS_H_
#define OPTIONS_H_

#include "dhcp.h"

#define DCODE_PADDING      0x00
#define DCODE_SUBNET       0x01
#define DCODE_TIMEZONE     0x02
#define DCODE_ROUTER       0x03
#define DCODE_DNS          0x06
#define DCODE_LPRSVR       0x09
#define DCODE_HOSTNAME     0x0c
#define DCODE_DOMAIN       0x0f
#define DCODE_IPTTL        0x17
#define DCODE_MTU          0x1a
#define DCODE_BROADCAST    0x1c
#define DCODE_NTPSVR       0x2a
#define DCODE_WINS         0x2c
#define DCODE_REQIP        0x32
#define DCODE_LEASET       0x33
#define DCODE_OVERLOAD     0x34
#define DCODE_MSGTYPE      0x35
#define DCODE_SERVER_ID    0x36
#define DCODE_PARAM_REQ    0x37
#define DCODE_MAX_SIZE     0x39
#define DCODE_VENDOR       0x3c
#define DCODE_CLIENT_ID    0x3d
#define DCODE_END          0xff

#define MAX_DOPT_SIZE 500

size_t get_dhcp_opt(const struct dhcpmsg * const packet, uint8_t code,
                    uint8_t *dbuf, size_t dlen);
ssize_t get_end_option_idx(const struct dhcpmsg * const packet);

size_t add_option_string(struct dhcpmsg *packet, uint8_t code,
                         const char *str, size_t slen);
size_t add_u32_option(struct dhcpmsg *packet, uint8_t code, uint32_t data);

size_t add_option_request_list(struct dhcpmsg *packet);
#ifdef NDHS_BUILD
size_t add_option_domain_name(struct dhcpmsg *packet,
                              const char * const dom, size_t domlen);
void add_option_subnet_mask(struct dhcpmsg *packet, uint32_t subnet);
void add_option_broadcast(struct dhcpmsg *packet, uint32_t bc);
void add_option_router(struct dhcpmsg *packet, uint32_t router);
#endif
void add_option_msgtype(struct dhcpmsg *packet, uint8_t type);
void add_option_reqip(struct dhcpmsg *packet, uint32_t ip);
void add_option_serverid(struct dhcpmsg *packet, uint32_t sid);
void add_option_clientid(struct dhcpmsg *packet,
                         const char * const clientid, size_t clen);
#ifndef NDHS_BUILD
void add_option_maxsize(struct dhcpmsg *packet);
void add_option_vendor(struct dhcpmsg *packet, const char * const vendor,
                       size_t vsize);
void add_option_hostname(struct dhcpmsg *packet, const char * const hostname,
                         size_t hsize);
#endif
uint32_t get_option_router(const struct dhcpmsg * const packet);
uint8_t get_option_msgtype(const struct dhcpmsg * const packet);
uint32_t get_option_serverid(const struct dhcpmsg * const packet, int *found);
uint32_t get_option_leasetime(const struct dhcpmsg *const packet);
size_t get_option_clientid(const struct dhcpmsg * const packet,
                           char *cbuf, size_t clen);

#endif
