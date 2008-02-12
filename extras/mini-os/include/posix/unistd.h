#ifndef _POSIX_UNISTD_H
#define _POSIX_UNISTD_H

#include_next <unistd.h>
#include <sys/select.h>
#include <arch_limits.h>

#define getpagesize() __PAGE_SIZE

int ftruncate(int fd, off_t length);

#endif /* _POSIX_UNISTD_H */
