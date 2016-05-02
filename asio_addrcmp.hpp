#ifndef NK_ASIO_ADDRCMP_HPP_
#define NK_ASIO_ADDRCMP_HPP_

#include <algorithm>
#include <asio.hpp>

namespace asio {

bool port_in_bounds(int port, int lo, int hi)
{
    if (hi < 0)
        hi = lo;
    if (lo >= 0) {
        if (port < lo || port > hi)
            return false;
    }
    return true;
}

bool compare_ipv6(asio::ip::address_v6::bytes_type ip, asio::ip::address_v6::bytes_type mask,
                  unsigned int msize)
{
    if (msize > 128)
        return false;

    auto cm8 = msize / 8;
    auto cm8r = msize % 8;

    for (size_t i = 0; i < cm8; ++i) {
        if (ip[i] != mask[i])
            return false;
    }
    if (cm8r) {
        auto a = ip[cm8] >> (8 - cm8r);
        auto b = mask[cm8] >> (8 - cm8r);
        if (a != b)
            return false;
    }
    return true;
}

bool compare_ip(asio::ip::address ip, asio::ip::address mask, unsigned int msize)
{
    asio::ip::address_v6 ip6(ip.is_v4() ? asio::ip::address_v6::v4_mapped(ip.to_v4())
                                        : ip.to_v6()), mask6;
    if (mask.is_v4()) {
        mask6 = asio::ip::address_v6::v4_mapped(mask.to_v4());
        msize += 96;
    } else
        mask6 = mask.to_v6();
    msize = std::min(msize, 128U);
    return compare_ipv6(ip6.to_bytes(), mask6.to_bytes(), msize);
}

}

#endif
