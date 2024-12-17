#ifndef NKLIB_IPADDR_H_
#define NKLIB_IPADDR_H_

#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <windows.h>
#include <ws2tcpip.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// These are helpers to access ip addresses stored in in6_addr
// in6_addr works fine for v4 addresses; they simply map onto the
// IPv4-mapped range in IPv6.

static inline bool ipaddr_from_string(in6_addr *addr, const char *s)
{
    if (inet_pton(AF_INET6, s, addr) != 1) {
        // Automagically try to handle IPv4 addresses as IPV6-mapped.
        char buf[256] = "::ffff:";
        size_t slen = strlen(s);
        if (slen > sizeof buf - 8) return false;
        memcpy(buf + 7, s, slen);
        buf[slen + 7] = 0;
        if (inet_pton(AF_INET6, buf, addr) != 1)
            return false;
    }
    return true;
}

static inline bool ipaddr_is_v4(const in6_addr *addr)
{
    const char *p = (const char *)addr;
    for (size_t i = 0; i < 10; ++i) if (p[i]) return false;
    return (uint8_t)p[10] == 0xff && (uint8_t)p[11] == 0xff;
}

static inline bool ipaddr_to_string(char *buf, size_t buflen, const in6_addr *addr)
{
    if (ipaddr_is_v4(addr)) {
        // So that we don't print v4 with the ::ffff: mapped prefix
        in_addr a4;
        const char *c = (const char *)addr;
        memcpy(&a4, c + 12, 4);
        if (!inet_ntop(AF_INET, &a4, buf, buflen)) return false;
    } else {
        if (!inet_ntop(AF_INET6, addr, buf, buflen)) return false;
    }
    return true;
}

// Check whether the address is v4 first via ipaddr_is_v4()
static inline const char *ipaddr_v4_bytes(const in6_addr *addr)
{
    return (const char *)addr + 12;
}

// For v6, simply memcpy()
static inline void ipaddr_from_v4_bytes(in6_addr *addr, const void *inv)
{
    char *caddr = (char *)addr;
    const char *in = (const char *)inv;
    for (size_t i = 0; i < 10; ++i) caddr[i] = 0;
    caddr[10] = (char)0xff;
    caddr[11] = (char)0xff;
    for (size_t i = 12; i < 16; ++i) caddr[i] = *in++;
}

static inline bool ipaddr_u32_compare_masked(uint32_t a, uint32_t b, unsigned mask)
{
    assert(mask <= 32);
    mask = mask <= 32 ? mask : 32;
    a = htonl(a);
    b = htonl(b);
    const auto m = mask < 32 ? UINT32_MAX >> mask : 0;
    return (a | m) == (b | m);

}

static inline bool ipaddr_compare_masked(const in6_addr *a, const in6_addr *b, unsigned mask)
{
    bool av4 = ipaddr_is_v4(a);
    bool bv4 = ipaddr_is_v4(b);
    if (av4 != bv4) return false;
    if (av4) {
        uint32_t a32, b32;
        memcpy(&a32, ipaddr_v4_bytes(a), sizeof a32);
        memcpy(&b32, ipaddr_v4_bytes(b), sizeof b32);
        mask = mask <= 32 ? mask : 32;
        return ipaddr_u32_compare_masked(a32, b32, mask);
    } else {
        uint32_t a32[4], b32[4];
        memcpy(a32, a, sizeof a32);
        memcpy(b32, b, sizeof b32);
        mask = mask <= 128 ? mask : 128;
        for (size_t i = 0; i < 3; ++i) {
            bool ci = ipaddr_u32_compare_masked(a32[i], b32[i], mask);
            if (mask <= 32) return ci;
            mask -= 32;
            if (!ci) return false;
        }
        return ipaddr_u32_compare_masked(a32[3], b32[3], mask);
    }
}

#ifdef __cplusplus
}
#endif

#endif
