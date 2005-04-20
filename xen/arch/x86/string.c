/******************************************************************************
 * string.c
 * 
 * These provide something for compiler-emitted string operations to link
 * against.
 */

#include <xen/config.h>
#include <xen/lib.h>

#undef memmove
void *memmove(void *dest, const void *src, size_t count)
{
    return __memmove(dest, src, count);
}

#undef memcpy
void *memcpy(void *dest, const void *src, size_t count)
{
    return __memcpy(dest, src, count);
}

#undef memset
void *memset(void *s, int c, size_t count)
{
    return __memset(s, c, count);
}
