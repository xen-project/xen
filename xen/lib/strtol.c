/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/lib.h>

/**
 * simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long simple_strtol(const char *cp, const char **endp, unsigned int base)
{
    if ( *cp == '-' )
        return -simple_strtoul(cp + 1, endp, base);
    return simple_strtoul(cp, endp, base);
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
