#include "rng.hpp"
#include <nk/prng.hpp>

static nk::rng::prng random_prng;

uint64_t random_u64() {
    return random_prng();
}

