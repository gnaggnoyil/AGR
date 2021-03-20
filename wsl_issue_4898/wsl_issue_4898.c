#include <time.h>
#include <unistd.h>

// This restores the old behaviour of nanosleep() to use CLOCK_MONOTONIC.
//
// "POSIX.1 specifies that nanosleep() should measure time against the
// CLOCK_REALTIME clock. However, Linux measures the time using the
// CLOCK_MONOTONIC clock.  This probably does not matter [...]"
//
// # gcc -shared -fPIC -o /usr/local/lib/libnanosleep.so nanosleep.c
// # echo /usr/local/lib/libnanosleep.so >> /etc/ld.so.preload
//
int nanosleep(const struct timespec *req, struct timespec *rem)
{
    return clock_nanosleep(CLOCK_MONOTONIC, 0, req, rem);
}

int usleep(useconds_t usec)
{
    struct timespec req = {
        .tv_sec     = (usec / 1000000),
        .tv_nsec    = (usec % 1000000) * 1000,
    };
    return nanosleep(&req, NULL);
}

