/* Mbed TLS MS_TIME_ALT: monotonic milliseconds without clock_gettime (iOS 10+). */
#include <stdint.h>
#include <mach/mach_time.h>
#include <pthread.h>
static mach_timebase_info_data_t ml_timebase;
static pthread_once_t ml_time_once = PTHREAD_ONCE_INIT;
static void ml_init_time(void) { mach_timebase_info(&ml_timebase); }
int64_t mbedtls_ms_time(void) {
    pthread_once(&ml_time_once, ml_init_time);
    return (int64_t)((long double)mach_absolute_time() * ml_timebase.numer /
                     ml_timebase.denom / 1000000.0L);
}
