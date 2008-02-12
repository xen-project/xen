#ifndef _POSIX_TIME_H
#define _POSIX_TIME_H

#include <sys/time.h>
#define CLOCK_MONOTONIC	2
#include_next <time.h>

int nanosleep(const struct timespec *req, struct timespec *rem);

#endif /* _POSIX_TIME_H */
