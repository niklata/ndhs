#include <nk/net/ip_address.hpp>
#include <nk/endian.hpp>
#include <limits.h>
#include <assert.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

namespace nk {

ip_address::ip_address(any)
{
    set(in6addr_any);
}

bool ip_address::set(const void * const sas, size_t sslen)
{
    const auto ss = static_cast<const sockaddr_storage *>(sas);
    if (ss->ss_family == AF_INET && sslen == sizeof(sockaddr_in)) {
        const auto s = static_cast<const sockaddr_in *>(sas);
        set(s->sin_addr);
    } else if (ss->ss_family == AF_INET6 && sslen == sizeof(sockaddr_in6)) {
        const auto s = static_cast<const sockaddr_in6 *>(sas);
        set(s->sin6_addr);
    } else return false;
    return true;
}

bool ip_address::from_string(const char *s)
{
    in6_addr addr;
    if (inet_pton(AF_INET6, s, &addr) != 1) {
        // Automagically try to handle IPv4 addresses as IPV6-mapped.
        char buf[256] = "::ffff:";
        size_t slen = strlen(s);
        if (slen > sizeof buf - 8) return false;
        memcpy(buf + 7, s, slen);
        buf[slen + 7] = 0;
        if (inet_pton(AF_INET6, buf, &addr) != 1)
            return false;
    }
    set(addr);
    return true;
}

bool ip_address::to_string(char *buf, size_t buflen) const
{
    if (is_v4()) {
        // So that we don't print v4 with the ::ffff: mapped prefix
        in_addr a4;
        auto c = reinterpret_cast<const char *>(&addr_);
        memcpy(&a4, c + 12, 4);
        if (!inet_ntop(AF_INET, &a4, buf, buflen)) return false;
    } else {
        if (!inet_ntop(AF_INET6, &addr_, buf, buflen)) return false;
    }
    return true;
}

static bool compare_u32_mask(uint32_t a, uint32_t b, unsigned mask)
{
    assert(mask <= 32);
    const auto m = mask < 32 ? UINT32_MAX >> mask : 0;
    return (a | m) == (b | m);
}

static bool compare_u32be_mask(uint32_t a, uint32_t b, unsigned mask)
{
    return compare_u32_mask(nk::big_endian(a), nk::big_endian(b), mask);
}

bool ip_address::compare_mask(const ip_address &o, unsigned mask) const
{
    const auto v4 = is_v4();
    if (v4 != o.is_v4()) return false;
    if (v4) {
        mask = mask <= 32u ? mask : 32u;
        uint32_t a, b;
        if (!raw_v4bytes(&a)) return false;
        if (!o.raw_v4bytes(&b)) return false;
        return compare_u32be_mask(a, b, mask);
    } else {
        mask = mask <= 128u ? mask : 128u;
        uint32_t a[4], b[4];
        raw_v6bytes(a);
        o.raw_v6bytes(b);

        for (size_t i = 0; i < 3; ++i) {
            const auto ci = compare_u32be_mask(a[i], b[i], mask);
            if (mask <= 32)
                return ci;
            mask -= 32;
            if (!ci) return false;
        }
        return compare_u32be_mask(a[3], b[3], mask);
    }
}

bool ip_address::is_v4() const
{
    auto p = reinterpret_cast<const char *>(&addr_);
    for (size_t i = 0; i < 10; ++i)
        if (p[i] != 0) return false;
    if (static_cast<uint8_t>(p[10]) != 0xff) return false;
    if (static_cast<uint8_t>(p[11]) != 0xff) return false;
    return true;
}

bool ip_address::raw_v4bytes(void *out) const
{
    if (!is_v4()) return false;
    auto p = reinterpret_cast<const char *>(&addr_);
    memcpy(out, p + 12, 4);
    return true;
}

void ip_address::raw_v6bytes(void *out) const
{
    auto p = reinterpret_cast<const char *>(&addr_);
    memcpy(out, p, 16);
}

// Translates to an IPv4-in-IPv6 mapped address.
void ip_address::from_v4bytes(const void *in)
{
    in6_addr a6;
    memset(&a6, 0, sizeof a6);

    auto x = reinterpret_cast<char *>(&a6);
    constexpr unsigned char ff[2] = { 0xff, 0xff };
    memcpy(x + 10, ff, 2);
    memcpy(x + 12, in, 4);

    set(a6);
}

void ip_address::from_v6bytes(const void *in)
{
    memcpy(&addr_, in, sizeof addr_);
}

}
