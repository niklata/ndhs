#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "nk/log.h"

/*
ldb [0]
jne #133, bad
ldb [1]
jne #0, bad
ret #-1
bad: ret #0
*/
static struct sock_filter sf_icmpra[] = {
    { 0x30,  0,  0, 0x00000000 },
    { 0x15,  0,  3, 0x00000085 },
    { 0x30,  0,  0, 0x00000001 },
    { 0x15,  0,  1, 0x00000000 },
    { 0x06,  0,  0, 0xffffffff },
    { 0x06,  0,  0, 0x00000000 },
};

/*
ldh [2]
jne #547, bad
ldh [4]
jlt #12, bad
ldb [8]
jne #11, bad
ret #-1
bad: ret #0
*/
static struct sock_filter sf_dhcp6_info[] = {
    { 0x28,  0,  0, 0x00000002 },
    { 0x15,  0,  5, 0x00000223 },
    { 0x28,  0,  0, 0x00000004 },
    { 0x35,  0,  3, 0x0000000c },
    { 0x30,  0,  0, 0x00000008 },
    { 0x15,  0,  1, 0x0000000b },
    { 0x06,  0,  0, 0xffffffff },
    { 0x06,  0,  0, 0x00000000 },
};

bool attach_bpf_icmp6_ra(int fd, const char *ifname)
{
    static const struct sock_fprog sfp_icmpra = {
        .len = sizeof sf_icmpra / sizeof sf_icmpra[0],
        .filter = (struct sock_filter *)sf_icmpra,
    };
    int r = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sfp_icmpra,
                       sizeof sfp_icmpra);
    if (r >= 0) {
        int tv = 1;
        r = setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &tv, sizeof tv);
        if (r >= 0)
            return true;
        else
            log_warning("%s: Failed to lock BPF for ICMPv6 socket: %s",
                        ifname, strerror(errno));
    } else
        log_warning("%s: Failed to set BPF for ICMPv6 socket: %s",
                    ifname, strerror(errno));
    return false;
}

bool attach_bpf_dhcp6_info(int fd, const char *ifname)
{
    static const struct sock_fprog sfp_dhcp6_info = {
        .len = sizeof sf_dhcp6_info / sizeof sf_dhcp6_info[0],
        .filter = (struct sock_filter *)sf_dhcp6_info,
    };
    int r = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sfp_dhcp6_info,
                       sizeof sfp_dhcp6_info);
    if (r >= 0) {
        int tv = 1;
        r = setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &tv, sizeof tv);
        if (r >= 0)
            return true;
        else
            log_warning("%s: Failed to lock BPF for DHCPv6 socket: %s",
                        ifname, strerror(errno));
    } else
        log_warning("%s: Failed to set BPF for DHCPv6 socket: %s",
                    ifname, strerror(errno));
    return false;
}

