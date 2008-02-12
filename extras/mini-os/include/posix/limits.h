#ifndef _POSIX_LIMITS_H
#define _POSIX_LIMITS_H

#include_next <limits.h>
#include <arch_limits.h>

#define PATH_MAX __PAGE_SIZE

#endif /* _POSIX_LIMITS_H */
