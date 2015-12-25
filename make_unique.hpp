#ifndef NKLIB_MAKE_UNIQUE_HPP__
#define NKLIB_MAKE_UNIQUE_HPP__

// STL's implementation from N3656.  Part of C++14.

#include <memory>
#include <type_traits>
#include <utility>

namespace nk {

template <typename T, typename... Args>
std::unique_ptr<T> make_unique_helper(std::false_type, Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template <typename T, typename... Args>
std::unique_ptr<T> make_unique_helper(std::true_type, Args&&... args)
{
    static_assert(std::extent<T>::value == 0,
                  "make_unique<T[N]>() is forbidden, please use make_unique<T[]>().");
    typedef typename std::remove_extent<T>::type U;
    return std::unique_ptr<T>(new U[sizeof...(Args)]{std::forward<Args>(args)...});
}

template <typename T, typename... Args> std::unique_ptr<T>
make_unique(Args&&... args)
{
    return make_unique_helper<T>(std::is_array<T>(), std::forward<Args>(args)...);
}

}

#endif /* NKLIB_MAKE_UNIQUE_HPP__ */
