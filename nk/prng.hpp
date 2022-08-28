#ifndef NCMLIB_RNG_PRNG_HPP_
#define NCMLIB_RNG_PRNG_HPP_

#include <cstdint>
#include <algorithm>
#include <tuple>
#include <limits>
extern "C" {
#include <nk/hwrng.h>
}

namespace nk::rng {

// This is an implementation of David Blackman's GJrand PRNG:
// https://gjrand.sourceforge.net
// It is structurally similar to Bob Jenkin's JSF, but performs more mixing
// and guards against short cycles rigorously by using a Weyl sequence (s_[3]).

namespace detail {
    static constexpr inline uint64_t rotl(const uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }
    template <typename T>
    static inline T nk_get_hwrng_v() {
        T r;
        nk_hwrng_bytes((char *)&r, sizeof r);
        return r;
    }
}

struct gjrand64 final
{
    typedef std::uint64_t result_type;
    constexpr gjrand64(uint64_t a, uint64_t b = 0) noexcept : s_{ a, b, 2000001, 0 } { discard(14); }
    gjrand64() : s_{ detail::nk_get_hwrng_v<uint64_t>(), detail::nk_get_hwrng_v<uint64_t>(), 2000001, 0 } { discard(14); }

    constexpr std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> save() const { return std::make_tuple(s_[0], s_[1], s_[2], s_[3]); }
    constexpr void load(uint64_t a, uint64_t b, uint64_t c, uint64_t d) noexcept { s_[0] = a; s_[1] = b; s_[2] = c; s_[3] = d; }
    constexpr inline uint64_t operator()() noexcept
    {
        s_[1] += s_[2];
        s_[0] = detail::rotl(s_[0], 32);
        s_[2] ^= s_[1];
        s_[3] += 0x55aa96a5;
        s_[0] += s_[1];
        s_[2] = detail::rotl(s_[2], 23);
        s_[1] ^= s_[0];
        s_[0] += s_[2];
        s_[1] = detail::rotl(s_[1], 19);
        s_[2] += s_[0];
        s_[1] += s_[3];
        return s_[0];
    }
    constexpr void discard(size_t z) noexcept { while (z-- > 0) operator()(); }
    static constexpr uint64_t min() noexcept { return std::numeric_limits<uint64_t>::min(); }
    static constexpr uint64_t max() noexcept { return std::numeric_limits<uint64_t>::max(); }
    static constexpr size_t state_size = sizeof(uint64_t) * 4;
    friend constexpr bool operator==(const gjrand64 &a, const gjrand64 &b) noexcept;
    friend constexpr bool operator!=(const gjrand64 &a, const gjrand64 &b) noexcept;
private:
    uint64_t s_[4];
};
inline constexpr bool operator==(const gjrand64 &a, const gjrand64 &b) noexcept {
    return a.s_[0] == b.s_[0] && a.s_[1] == b.s_[1] && a.s_[2] == b.s_[2] && a.s_[3] == b.s_[3];
}
inline constexpr bool operator!=(const gjrand64 &a, const gjrand64 &b) noexcept { return !operator==(a, b); }

using prng = gjrand64;

}

#endif

