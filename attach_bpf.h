// Copyright 2016-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_ATTACH_BPF_H_
#define NDHS_ATTACH_BPF_H_
extern bool attach_bpf_icmp6_ra(int fd, const char *ifname);
extern bool attach_bpf_dhcp6_info(int fd, const char *ifname);
#endif
