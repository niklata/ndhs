// Copyright 2020-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHS_RNG_HPP_
#define NDHS_RNG_HPP_

#include <cstdint>

uint64_t random_u64();

struct random_u64_wrapper
{
    using result_type = uint64_t;
    inline uint64_t operator()() { return random_u64(); }
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return ~result_type{0}; }
};

#endif
