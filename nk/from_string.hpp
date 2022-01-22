#ifndef NKLIB_FROM_STRING_HPP_
#define NKLIB_FROM_STRING_HPP_

#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <limits>
#include <type_traits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <optional>
#ifdef _MSC_VER
#include <charconv>
#else
#include <cstring>
#endif

namespace nk {
    namespace detail {
        template <typename T>
        constexpr std::optional<T> str_to_signed_integer(const char *s)
        {
            using ut = typename std::make_unsigned<T>::type;
            constexpr auto maxut = static_cast<typename std::make_unsigned<T>::type>(std::numeric_limits<T>::max());
            ut ret(0), digit(0);
            const bool neg = (*s == '-');
            if (neg) ++s;
            if (!(s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
                do {
                    if (*s < '0' || *s > '9')
                        return {};
                    if (ret > maxut / 10) {
                        ret = std::numeric_limits<ut>::max();
                        break;
                    }
                    digit = static_cast<ut>(*s) - '0';
                    ret = ret * 10u + digit;
                } while (*++s);
            } else {
                s += 2;
                do {
                    if (*s >= '0' && *s <= '9')
                        digit = static_cast<ut>(*s) - '0';
                    else if (*s >= 'A' && *s <= 'F')
                        digit = static_cast<ut>(*s) - 'A' + ut{ 10 };
                    else if (*s >= 'a' && *s <= 'f')
                        digit = static_cast<ut>(*s) - 'a' + ut{ 10 };
                    else
                        return {};
                    if (ret > maxut / 16) {
                        ret = std::numeric_limits<ut>::max();
                        break;
                    }
                    ret = ret * 16u + digit;
                } while (*++s);
            }
            if (ret > maxut + neg)
                return {}; // out of range
            return neg ? -static_cast<T>(ret) : static_cast<T>(ret);
        }
        template <typename T>
        constexpr std::optional<T> str_to_signed_integer(const char *s, size_t c)
        {
            using ut = typename std::make_unsigned<T>::type;
            constexpr auto maxut = static_cast<typename std::make_unsigned<T>::type>(std::numeric_limits<T>::max());
            ut ret(0), digit(0);
            if (c == 0)
                return {};
            const ut neg = (*s == '-');
            if (neg) ++s, c--;
            if (c == 0)
                return {};
            if (!(c > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
                do {
                    if (*s < '0' || *s > '9')
                        return {};
                    if (ret > maxut / 10) {
                        ret = std::numeric_limits<ut>::max();
                        break;
                    }
                    digit = static_cast<ut>(*s) - '0';
                    ret = ret * 10u + digit;
                } while (++s, --c);
            } else {
                s += 2; c -= 2;
                do {
                    if (*s >= '0' && *s <= '9')
                        digit = static_cast<ut>(*s) - '0';
                    else if (*s >= 'A' && *s <= 'F')
                        digit = static_cast<ut>(*s) - 'A' + ut{ 10 };
                    else if (*s >= 'a' && *s <= 'f')
                        digit = static_cast<ut>(*s) - 'a' + ut{ 10 };
                    else
                        return {};
                    if (ret > maxut / 16) {
                        ret = std::numeric_limits<ut>::max();
                        break;
                    }
                    ret = ret * 16u + digit;
                } while (++s, --c);
            }
            if (ret > maxut + neg)
                return {}; // out of range
            return neg ? -static_cast<T>(ret) : static_cast<T>(ret);
        }
        template <typename T>
        constexpr std::optional<T> str_to_unsigned_integer(const char *s)
        {
            T ret(0), digit(0);
            const bool neg = (*s == '-');
            if (neg)
                return {}; // out of range
            if (!(s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
                do {
                    if (*s < '0' || *s > '9')
                        return {};
                    if (ret > std::numeric_limits<T>::max() / 10)
                        return {}; // out of range
                    digit = static_cast<T>(*s) - '0';
                    ret = ret * 10u + digit;
                } while (*++s);
            } else {
                s += 2;
                do {
                    if (*s >= '0' && *s <= '9')
                        digit = static_cast<T>(*s) - '0';
                    else if (*s >= 'A' && *s <= 'F')
                        digit = static_cast<T>(*s) - 'A' + T{ 10 };
                    else if (*s >= 'a' && *s <= 'f')
                        digit = static_cast<T>(*s) - 'a' + T{ 10 };
                    else
                        return {};
                    if (ret > std::numeric_limits<T>::max() / 16)
                        return {}; // out of range
                    ret = ret * 16u + digit;
                } while (*++s);
            }
            return ret;
        }
        template <typename T>
        constexpr std::optional<T> str_to_unsigned_integer(const char *s, size_t c)
        {
            T ret(0), digit(0);
            if (c == 0)
                return {};
            const bool neg = (*s == '-');
            if (neg)
                return {}; // out of range
            if (!(c > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
                do {
                    if (*s < '0' || *s > '9')
                        return {};
                    if (ret > std::numeric_limits<T>::max() / 10)
                        return {}; // out of range
                    digit = static_cast<T>(*s) - '0';
                    ret = ret * 10u + digit;
                } while (++s, --c);
            } else {
                s += 2; c -= 2;
                do {
                    if (*s >= '0' && *s <= '9')
                        digit = static_cast<T>(*s) - '0';
                    else if (*s >= 'A' && *s <= 'F')
                        digit = static_cast<T>(*s) - 'A' + T{ 10 };
                    else if (*s >= 'a' && *s <= 'f')
                        digit = static_cast<T>(*s) - 'a' + T{ 10 };
                    else
                        return {};
                    if (ret > std::numeric_limits<T>::max() / 16)
                        return {}; // out of range
                    ret = ret * 16u + digit;
                } while (++s, --c);
            }
            return ret;
        }

// 2018-10-27: libstdc++ doesn't support std::from_chars with fp types.
#ifdef _MSC_VER
        static inline std::optional<double> str_to_double(const char *s, size_t c)
        {
            double v;
            const auto ret = std::from_chars(s, s + c, v);
            if (ret.ec == std::errc{}) return v;
            return {};
        }
        static inline std::optional<float> str_to_float(const char *s, size_t c)
        {
            float v;
            const auto ret = std::from_chars(s, s + c, v);
            if (ret.ec == std::errc{}) return v;
            return {};
        }
        static inline std::optional<long double> str_to_long_double(const char *s, size_t c)
        {
            long double v;
            const auto ret = std::from_chars(s, s + c, v);
            if (ret.ec == std::errc{}) return v;
            return {};
        }
        static inline std::optional<double> str_to_double(const char *s)
        {
            return str_to_double(s, strlen(s));
        }
        static inline std::optional<float> str_to_float(const char *s)
        {
            return str_to_float(s, strlen(s));
        }
        static inline std::optional<long double> str_to_long_double(const char *s)
        {
            return str_to_long_double(s, strlen(s));
        }
#else
        static inline std::optional<double> str_to_double(const char *s, size_t c)
        {
            if (c == 0)
                return {};
            char buf[128];
            const auto slen = std::min(c, sizeof buf) - 1;
            memcpy(buf, s, slen);
            buf[slen] = 0;

            char *endptr;
            const auto ret = std::strtod(buf, &endptr);
            if (endptr == buf)
                return {};
            if ((ret == HUGE_VAL || ret == -HUGE_VAL || ret == 0.) && errno == ERANGE)
                return {}; // out of range
            return ret;
        }
        static inline std::optional<float> str_to_float(const char *s, size_t c)
        {
            if (c == 0)
                return {};
            char buf[128];
            const auto slen = std::min(c, sizeof buf) - 1;
            memcpy(buf, s, slen);
            buf[slen] = 0;

            char *endptr;
            const auto ret = std::strtof(buf, &endptr);
            if (endptr == buf)
                return {};
            if ((ret == HUGE_VALF || ret == -HUGE_VALF || ret == 0.f) && errno == ERANGE)
                return {}; // out of range
            return ret;
        }
        static inline std::optional<long double> str_to_long_double(const char *s, size_t c)
        {
            if (c == 0)
                return {};
            char buf[128];
            const auto slen = std::min(c, sizeof buf) - 1;
            memcpy(buf, s, slen);
            buf[slen] = 0;

            char *endptr;
            const auto ret = std::strtold(buf, &endptr);
            if (endptr == buf)
                return {};
            if ((ret == HUGE_VALL || ret == -HUGE_VALL || ret == 0.l) && errno == ERANGE)
                return {}; // out of range
            return ret;
        }
        static inline std::optional<double> str_to_double(const char *s)
        {
            char *endptr;
            const auto ret = std::strtod(s, &endptr);
            if (endptr == s)
                return {};
            if ((ret == HUGE_VAL || ret == -HUGE_VAL || ret == 0.) && errno == ERANGE)
                return {}; // out of range
            return ret;
        }
        static inline std::optional<float> str_to_float(const char *s)
        {
            char *endptr;
            const auto ret = std::strtof(s, &endptr);
            if (endptr == s)
                return {};
            if ((ret == HUGE_VALF || ret == -HUGE_VALF || ret == 0.f) && errno == ERANGE)
                return {}; // out of range
            return ret;
        }
        static inline std::optional<long double> str_to_long_double(const char *s)
        {
            char *endptr;
            const auto ret = std::strtold(s, &endptr);
            if (endptr == s)
                return {};
            if ((ret == HUGE_VALL || ret == -HUGE_VALL || ret == 0.l) && errno == ERANGE)
                return {}; // out of range
            return ret;
        }
#endif

        template <typename T>
        std::optional<T> do_from_string(const char *s)
        {
            static_assert(std::is_integral_v<T> || std::is_floating_point_v<T>, "T must be integer or floating point type");
            if constexpr (std::is_integral_v<T>) {
                if constexpr (std::is_signed_v<T>) {
                    return detail::str_to_signed_integer<T>(s);
                } else {
                    return detail::str_to_unsigned_integer<T>(s);
                }
            } else if constexpr (std::is_floating_point_v<T>) {
                if constexpr (std::is_same_v<typename std::remove_cv<T>::type, double>) {
                    return str_to_double(s);
                } else if constexpr (std::is_same_v<typename std::remove_cv<T>::type, float>) {
                    return str_to_float(s);
                } else if constexpr (std::is_same_v<typename std::remove_cv<T>::type, long double>) {
                    return str_to_long_double(s);
                }
            }
        }
        template <typename T>
        std::optional<T> do_from_string(const char *s, size_t c)
        {
            static_assert(std::is_integral_v<T> || std::is_floating_point_v<T>, "T must be integer or floating point type");
            if constexpr (std::is_integral_v<T>) {
                if constexpr (std::is_signed_v<T>) {
                    return detail::str_to_signed_integer<T>(s, c);
                } else {
                    return detail::str_to_unsigned_integer<T>(s, c);
                }
            } else if constexpr (std::is_floating_point_v<T>) {
                if constexpr (std::is_same_v<typename std::remove_cv<T>::type, double>) {
                    return str_to_double(s, c);
                } else if constexpr (std::is_same_v<typename std::remove_cv<T>::type, float>) {
                    return str_to_float(s, c);
                } else if constexpr (std::is_same_v<typename std::remove_cv<T>::type, long double>) {
                    return str_to_long_double(s, c);
                }
            }
        }
    }

    template <typename Target>
    [[nodiscard]] std::optional<Target> from_string(const char *s)
    {
        return detail::do_from_string<Target>(s);
    }
    template <typename Target>
    [[nodiscard]] std::optional<Target> from_string(const char *s, size_t c)
    {
        return detail::do_from_string<Target>(s, c);
    }
    template <typename Target>
    [[nodiscard]] std::optional<Target> from_string(const std::string &s)
    {
        return detail::do_from_string<Target>(s.data(), s.size());
    }
    template <typename Target>
    [[nodiscard]] std::optional<Target> from_string(std::string_view s)
    {
        return detail::do_from_string<Target>(s.data(), s.size());
    }
}
#endif

