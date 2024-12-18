#ifndef NDHS_RNG_H_
#define NDHS_RNG_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
uint64_t nk_random_u64();
}
#else
uint64_t nk_random_u64(void);
#endif

#endif
