#ifndef NDHS_NETBITS_H_
#define NDHS_NETBITS_H_

#include <stdint.h>

static inline void encode32be(void *dest, uint32_t v)
{
    char *d = dest;
    d[0] = v >> 24;
    d[1] = (v >> 16) & 0xff;
    d[2] = (v >> 8) & 0xff;
    d[3] = v & 0xff;
}

static inline void encode16be(void *dest, uint16_t v)
{
    char *d = dest;
    d[0] = v >> 8;
    d[1] = v & 0xff;
}

static inline uint32_t decode32be(const void *src)
{
    const char *s = src;
    return ((uint32_t)s[0] << 24)
         | (((uint32_t)s[1] << 16) & 0xff0000)
         | (((uint32_t)s[2] << 8) & 0xff00)
         | ((uint32_t)s[3] & 0xff);
}

static inline uint16_t decode16be(const void *src)
{
    const char *s = src;
    return ((uint16_t)s[0] << 8)
         | ((uint16_t)s[1] & 0xff);
}

#endif

