#ifndef _POSIX_UNISTD_H
#define _POSIX_UNISTD_H

#include_next <unistd.h>

size_t getpagesize(void);
int ftruncate(int fd, off_t length);

#endif /* _POSIX_UNISTD_H */
