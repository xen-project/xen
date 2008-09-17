#ifndef _POSIX_UNISTD_H
#define _POSIX_UNISTD_H

#include_next <unistd.h>

size_t getpagesize(void);
int ftruncate(int fd, off_t length);
int lockf(int fd, int cmd, off_t len);

#endif /* _POSIX_UNISTD_H */
