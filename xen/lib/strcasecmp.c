/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>
#include <xen/ctype.h>

int (strcasecmp)(const char *s1, const char *s2)
{
    int c1, c2;

    do
    {
        c1 = tolower(*s1++);
        c2 = tolower(*s2++);
    } while ( c1 == c2 && c1 != 0 );

    return c1 - c2;
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
