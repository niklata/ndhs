#ifndef NJK_NDHS_SBUFS_H_
#define NJK_NDHS_SBUFS_H_

#include <cstring>
#include <arpa/inet.h>

struct sbufs {
    char *si;
    char *se;
};

static inline bool sa6_from_string(sockaddr_in6 *sin, const char *str)
{
    memset(sin, 0, sizeof(sockaddr_in6));
    sin->sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, str, &sin->sin6_addr) != 1) {
        fmt::print(stderr, "ra6: inet_pton failed: {}\n", strerror(errno));
        return false;
    }
    return true;
}
static inline bool sa6_to_string(char *buf, size_t buflen, const sockaddr_in6 *sin)
{
    return !!inet_ntop(AF_INET6, &sin->sin6_addr, buf, buflen);
}

#endif
