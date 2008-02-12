#ifndef _POSIX_STRINGS_H
#define _POSIX_STRINGS_H

#include <string.h>

#define bzero(ptr, size) (memset((ptr), '\0', (size)), (void) 0)

#endif /* _POSIX_STRINGS_H */
