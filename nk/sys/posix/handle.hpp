#ifndef NKLIB_SYS_POSIX_HANDLE_HPP_
#define NKLIB_SYS_POSIX_HANDLE_HPP_

#include <unistd.h>

namespace nk::sys {

using native_handle_type = int;
struct handle {
    constexpr handle() : handle_{ -1 } {}
    constexpr handle(native_handle_type s) : handle_{ s } {}
    constexpr handle(const handle &) = delete;
    constexpr handle &operator=(const handle &) = delete;
    constexpr handle(handle &&o) noexcept : handle_{ -1 } { swap(*this, o); }
    constexpr handle &operator=(handle &&o) noexcept { swap(*this, o); return *this; }
    ~handle() { close(); }

    friend constexpr void swap(handle &a, handle &b) {
        // std::swap(int, int) isn't constexpr for some reason (C++17/2020)
        auto t = b.handle_;
        b.handle_ = a.handle_;
        a.handle_ = t;
    }
    constexpr auto operator()() const { return handle_; }
    constexpr explicit operator bool() const { return handle_ >= 0; }
    constexpr native_handle_type release() { auto r = handle_; handle_ = -1; return r; }
    void close()
    {
        if (handle_ < 0) return;
        ::close(handle_);
        handle_ = -1;
    }

private:
    native_handle_type handle_;
};

}

#endif
