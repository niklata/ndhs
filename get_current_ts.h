#ifndef NDHS_GET_CURRENT_TS_H_
#define NDHS_GET_CURRENT_TS_H_

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static inline int64_t get_current_ts(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts)) abort();
    return ts.tv_sec;
}

#endif
