/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * strncmp - Compare two length-limited strings
 * @cs: One string
 * @ct: Another string
 * @count: The maximum number of bytes to compare
 */
int (strncmp)(const char *cs, const char *ct, size_t count)
{
    const unsigned char *csu = (const void *)cs;
    const unsigned char *ctu = (const void *)ct;
    int res = 0;

    while ( count )
    {
        if ( (res = *csu - *ctu++) != 0 || !*csu++ )
            break;
        count--;
    }

    return res;
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
