#ifndef NKLIB_NET_IP_ADDRESS_HPP_
#define NKLIB_NET_IP_ADDRESS_HPP_

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#ifdef _WIN32
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

namespace nk {

// Portable abstraction for in6_addr.
struct ip_address {
    enum class any{};
    inline ip_address() { ::memset(&addr_, 0, sizeof addr_); }

    ip_address(any);
    inline ip_address(const in6_addr &addr) { set(addr); };
    inline ip_address(const in_addr &addr) { set(addr); };

    inline bool operator==(const ip_address &o) const { return spaceship_op(o) == 0; }
    inline bool operator<(const ip_address &o) const { return spaceship_op(o) < 0; }
    inline bool operator>(const ip_address &o) const { return spaceship_op(o) > 0; }
    inline bool operator!=(const ip_address &o) const { return spaceship_op(o) != 0; }
    inline bool operator>=(const ip_address &o) const { return spaceship_op(o) >= 0; };
    inline bool operator<=(const ip_address &o) const { return spaceship_op(o) <= 0; };

    [[nodiscard]] bool set(const void * const sas, size_t sslen);
    inline void set(const in6_addr &addr) { from_v6bytes(&addr); }
    inline void set(const in_addr &addr) { from_v4bytes(&addr); }
    [[nodiscard]] bool from_string(std::string_view s);
    std::string to_string() const;
    size_t addrlen() const { return sizeof addr_; }

    bool compare_mask(const ip_address &o, unsigned mask) const;

    // All v4 addresses are valid v6 addresses, so is_v6 would always be true.
    bool is_v4() const;

    // out must be at least 4 or 16 bytes, respectively
    [[nodiscard]] bool raw_v4bytes(void *out) const;
    void raw_v6bytes(void *out) const;

    // in must be at least 4 or 16 bytes, respectively
    void from_v4bytes(const void *in);
    void from_v6bytes(const void *in);

    constexpr auto &native_type() const { return addr_; }
private:
    inline int spaceship_op(const ip_address &o) const
    {
        return ::memcmp(&addr_, &o.addr_, sizeof addr_);
    }

    in6_addr addr_;
};

}

#endif
