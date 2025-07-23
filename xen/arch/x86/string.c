/******************************************************************************
 * string.c
 *
 * These provide something for compiler-emitted string operations to link
 * against.
 */

#include <xen/lib.h>

void *(memmove)(void *dest, const void *src, size_t n)
{
    long d0, d1, d2;

    if ( unlikely(!n) )
        return dest;

    if ( dest < src )
        /* Depends on Xen's implementation operating forwards. */
        return (memcpy)(dest, src, n);

    asm volatile (
        "   std         ; "
        "   rep movsb   ; "
        "   cld           "
        : "=&c" (d0), "=&S" (d1), "=&D" (d2)
        : "0" (n), "1" (n-1+(const char *)src), "2" (n-1+(char *)dest)
        : "memory");

    return dest;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
