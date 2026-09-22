/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * strcmp - Compare two strings
 * @cs: One string
 * @ct: Another string
 */
int (strcmp)(const char *cs, const char *ct)
{
    const unsigned char *csu = (const void *)cs;
    const unsigned char *ctu = (const void *)ct;
    int res;

    for ( ; ; )
        if ( (res = *csu - *ctu++) != 0 || !*csu++ )
            break;

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
