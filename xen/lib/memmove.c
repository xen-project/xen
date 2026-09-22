/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * memmove - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @n: The size of the area.
 *
 * Unlike memcpy(), memmove() copes with overlapping areas.
 */
void *(memmove)(void *dest, const void *src, size_t n)
{
    char *tmp;
    const char *s;

    if ( dest <= src )
    {
        tmp = dest;
        s = src;
        while ( n-- )
            *tmp++ = *s++;
    }
    else
    {
        tmp = dest + n;
        s = src + n;
        while ( n-- )
            *--tmp = *--s;
    }

    return dest;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
