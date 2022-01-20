#ifndef NK_ENDIAN_HPP_
#define NK_ENDIAN_HPP_

#include <cstdint>
#include <type_traits>
#include <climits>
#include <utility>
#if _MSC_VER
#include <cstdlib>
#endif

#ifdef _MSC_VER
 #define NK_LITTLE_ENDIAN 1
#elif defined(__BYTE_ORDER__)
 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  #define NK_LITTLE_ENDIAN 1
 #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #define NK_BIG_ENDIAN 1
 #endif
#else
 #include <endian.h>
 #if BYTE_ORDER == LITTLE_ENDIAN
  #define NK_LITTLE_ENDIAN 1
 #elif BYTE_ORDER == BIG_ENDIAN
  #define NK_BIG_ENDIAN 1
 #endif
#endif

#if !defined(NK_LITTLE_ENDIAN) && !defined(NK_BIG_ENDIAN)
#error "Unable to determine endianness."
#endif

namespace nk {
#if _MSC_VER && !__INTEL_COMPILER
#define NK_ENDIAN_FINLINE __forceinline
    // As of MSVC2017 (2018-10-23), MSVC doesn't recognize the idiom below and requires these intrinsics to generate bswap.
    static NK_ENDIAN_FINLINE uint16_t bswap(uint16_t x) { return _byteswap_ushort(x); }
    static NK_ENDIAN_FINLINE uint32_t bswap(uint32_t x) { return _byteswap_ulong(x); }
    static NK_ENDIAN_FINLINE uint64_t bswap(uint64_t x) { return _byteswap_uint64(x); }
#else
#define NK_ENDIAN_FINLINE inline __attribute__((always_inline))
    static NK_ENDIAN_FINLINE uint16_t bswap(uint16_t x) { return __builtin_bswap16(x); }
    static NK_ENDIAN_FINLINE uint32_t bswap(uint32_t x) { return __builtin_bswap32(x); }
    static NK_ENDIAN_FINLINE uint64_t bswap(uint64_t x) { return __builtin_bswap64(x); }
    // These work, but there is also the choice of just using cexpr_bswap() below, which generates these via metaprogramming.
    //static constexpr NK_ENDIAN_FINLINE uint16_t bswap(uint16_t x) { return (x >> 8) | (x << 8); }
    //static constexpr NK_ENDIAN_FINLINE uint32_t bswap(uint32_t x) { return (x >> 24) | (x << 24) | ((x >> 8) & 0x0000ff00u) | ((x << 8) & 0x00ff0000u); }
    //static constexpr NK_ENDIAN_FINLINE uint64_t bswap(uint64_t x) { return (x >> 56) | (x << 56) | ((x >> 40) & 0x000000000000ff00u) | ((x << 40) & 0x00ff000000000000u) | ((x >> 24) & 0x0000000000ff0000u) | ((x << 24) & 0x0000ff0000000000u) | ((x >> 8) & 0x00000000ff000000u) | ((x << 8) & 0x000000ff00000000u); }
#endif
    template <typename T>
    NK_ENDIAN_FINLINE T endian_swap(std::enable_if_t<(sizeof(T) == 8), T> u)
    {
        return static_cast<T>(bswap(static_cast<uint64_t>(u)));
    }
    template <typename T>
    NK_ENDIAN_FINLINE T endian_swap(std::enable_if_t<(sizeof(T) == 4), T> u)
    {
        return static_cast<T>(bswap(static_cast<uint32_t>(u)));
    }
    template <typename T>
    NK_ENDIAN_FINLINE T endian_swap(std::enable_if_t<(sizeof(T) == 2), T> u)
    {
        return static_cast<T>(bswap(static_cast<uint16_t>(u)));
    }
    template <typename T>
    NK_ENDIAN_FINLINE T endian_swap(std::enable_if_t<(sizeof(T) == 1), T> u)
    {
        return u;
    }

#ifdef NK_LITTLE_ENDIAN
    static inline constexpr bool is_little_endian() { return true; }
#else
    static inline constexpr bool is_little_endian() { return false; }
#endif

#ifdef NK_BIG_ENDIAN
    static inline constexpr bool is_big_endian() { return true; }
#else
    static inline constexpr bool is_big_endian() { return false; }
#endif

    template <typename T> NK_ENDIAN_FINLINE T little_endian(T u) {
#ifdef NK_LITTLE_ENDIAN
        return u;
#else
        return endian_swap<T>(u);
#endif
    }
    template <typename T> NK_ENDIAN_FINLINE T big_endian(T u) {
#ifdef NK_BIG_ENDIAN
        return u;
#else
        return endian_swap<T>(u);
#endif
    }

    // MSVC as of 15.6.0 doesn't seem to know how to generate bswap without intrinsics.
    // Were this not the case, this implementation could simply replace the non-constexpr one above.
    template<class T, std::size_t... N>
    constexpr T cexpr_bswap_impl(T i, std::index_sequence<N...>)
    {
        return ((((i >> (N * CHAR_BIT)) & (T)(unsigned char)(-1)) << ((sizeof(T) - 1 - N) * CHAR_BIT)) | ...);
    }
    template<class T, class U = typename std::make_unsigned<T>::type>
    constexpr U cexpr_bswap(T i)
    {
        return cexpr_bswap_impl<U>(i, std::make_index_sequence<sizeof(T)>{});
    }
    template <typename T> constexpr T cexpr_little_endian(T u) {
#ifdef NK_LITTLE_ENDIAN
        return u;
#else
        return cexpr_bswap<T>(u);
#endif
    }
    template <typename T> constexpr T cexpr_big_endian(T u) {
#ifdef NK_BIG_ENDIAN
        return u;
#else
        return cexpr_bswap<T>(u);
#endif
    }

    // Tolerates unaligned loads.
    // These can be optimized to be faster for loads than memcpy/endian_swap on some architectures.
    // MOVBE is still not common on x86 (Atom and very recent CPUs only).
    template <typename T>
    static inline T load_big_endian(const void * const vp)
    {
        static_assert(sizeof(T) == 8 || sizeof(T) == 4 || sizeof(T) == 2 || sizeof(T) == 1, "bad size");
        if constexpr (sizeof(T) == 8 || sizeof(T) == 4 || sizeof(T) == 2 || sizeof(T) == 1) {
            T r;
            memcpy(&r, vp, sizeof(T));
            return endian_swap<T>(r);
        } else return static_cast<T>(*static_cast<const unsigned char *>(vp));
    }
    template <typename T>
    static inline T load_little_endian(const void * const vp)
    {
        static_assert(sizeof(T) == 8 || sizeof(T) == 4 || sizeof(T) == 2 || sizeof(T) == 1, "bad size");
        if constexpr (sizeof(T) == 8 || sizeof(T) == 4 || sizeof(T) == 2 || sizeof(T) == 1) {
            T r;
            memcpy(&r, vp, sizeof(T));
            return r;
        } else return static_cast<T>(*static_cast<const unsigned char *>(vp));
    }

    // Strictly speaking, these are not endian helpers, but they are often
    // useful for endian-specific data.
    static inline constexpr uint16_t u16_unaligned(const void * const vp)
    {
        const auto p = static_cast<const unsigned char *>(vp);
        return static_cast<uint16_t>(p[0])
            | (static_cast<uint16_t>(p[1]) << 8);
    }

    static inline constexpr uint32_t u32_unaligned(const void * const vp)
    {
        const auto p = static_cast<const unsigned char *>(vp);
        return static_cast<uint32_t>(p[0])
            | (static_cast<uint32_t>(p[1]) << 8)
            | (static_cast<uint32_t>(p[2]) << 16)
            | (static_cast<uint32_t>(p[3]) << 24);
    }

    static inline constexpr uint64_t u64_unaligned(const void * const vp)
    {
        const auto p = static_cast<const unsigned char *>(vp);
        return static_cast<uint64_t>(p[0])
            | (static_cast<uint64_t>(p[1]) << 8)
            | (static_cast<uint64_t>(p[2]) << 16)
            | (static_cast<uint64_t>(p[3]) << 24)
            | (static_cast<uint64_t>(p[4]) << 32)
            | (static_cast<uint64_t>(p[5]) << 40)
            | (static_cast<uint64_t>(p[6]) << 48)
            | (static_cast<uint64_t>(p[7]) << 56);
    }
}
#undef NK_ENDIAN_FINLINE

#endif /* NK_ENDIAN_HPP_ */
