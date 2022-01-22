#ifndef NK_NRAD6_NETBITS_HPP_
#define NK_NRAD6_NETBITS_HPP_

#include <stdint.h>

static inline void encode32be(uint32_t v, void *dest)
{
    auto d = reinterpret_cast<char *>(dest);
    d[0] = v >> 24;
    d[1] = (v >> 16) & 0xff;
    d[2] = (v >> 8) & 0xff;
    d[3] = v & 0xff;
}

static inline void encode16be(uint16_t v, void *dest)
{
    auto d = reinterpret_cast<char *>(dest);
    d[0] = v >> 8;
    d[1] = v & 0xff;
}

static inline uint32_t decode32be(const void *src)
{
    auto s = reinterpret_cast<const char *>(src);
    return (static_cast<uint32_t>(s[0]) << 24)
         | ((static_cast<uint32_t>(s[1]) << 16) & 0xff0000)
         | ((static_cast<uint32_t>(s[2]) << 8) & 0xff00)
         | (static_cast<uint32_t>(s[3]) & 0xff);
}

static inline uint16_t decode16be(const void *src)
{
    auto s = reinterpret_cast<const char *>(src);
    return (static_cast<uint16_t>(s[0]) << 8)
         | (static_cast<uint16_t>(s[1]) & 0xff);
}

static inline void toggle_bit(bool v, void *data, std::size_t arrayidx, uint32_t bitidx)
{
    auto d = reinterpret_cast<char *>(data);
    if (v)
        d[arrayidx] |= bitidx;
    else
        d[arrayidx] &= ~bitidx;
}

#endif

