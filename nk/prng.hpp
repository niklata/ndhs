#ifndef NCMLIB_RNG_PRNG_HPP_
#define NCMLIB_RNG_PRNG_HPP_

#include <cstdint>
#include <tuple>
#include <limits>
extern "C" {
#include <nk/hwrng.h>
}

namespace nk::rng {

namespace detail {
    static constexpr inline uint64_t rotl(const uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }
    template <typename T>
    static inline T nk_get_hwrng_v() {
        T r;
        nk_hwrng_bytes(&r, sizeof r);
        return r;
    }
}

struct sfc64 final
{
    typedef std::uint64_t result_type;
    constexpr sfc64(uint64_t a) : s_{ a, a, a, 1 } { discard(12); }
    constexpr sfc64(uint64_t a, uint64_t b, uint64_t c) : s_{ a, b, c, 1 } { discard(12); }
    sfc64() : s_{ 0, 0, 0, 1 } { nk_hwrng_bytes(s_, sizeof s_[0] * 3); discard(12); }

    constexpr std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> save() const { return std::make_tuple(s_[0], s_[1], s_[2], s_[3]); }
    constexpr void load(uint64_t a, uint64_t b, uint64_t c, uint64_t d) { s_[0] = a; s_[1] = b; s_[2] = c; s_[3] = d; }
    constexpr inline uint64_t operator()()
    {
        const auto t = s_[0] + s_[1] + s_[3]++;
        s_[0] = s_[1] ^ (s_[1] >> 11);
        s_[1] = s_[2] + (s_[2] << 3);
        s_[2] = detail::rotl(s_[2], 24) + t;
        return t;
    }
    constexpr void discard(size_t z) { while (z-- > 0) operator()(); }
    static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); }
    static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); }
    static constexpr size_t state_size = sizeof(uint64_t) * 4;
    friend constexpr bool operator==(const sfc64 &a, const sfc64 &b);
    friend constexpr bool operator!=(const sfc64 &a, const sfc64 &b);
private:
    uint64_t s_[4];
};
inline constexpr bool operator==(const sfc64 &a, const sfc64 &b) {
    return a.s_[0] == b.s_[0] && a.s_[1] == b.s_[1] && a.s_[2] == b.s_[2] && a.s_[3] == b.s_[3];
}
inline constexpr bool operator!=(const sfc64 &a, const sfc64 &b) { return !operator==(a, b); }

using prng = sfc64;

}

#endif

