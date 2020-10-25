#include "rng.hpp"
#include <nk/prng.hpp>
#include <mutex>

static std::mutex mtx;
static nk::rng::prng random_prng;

uint64_t random_u64() {
    std::lock_guard<std::mutex> ml(mtx);
    return random_prng();
}

