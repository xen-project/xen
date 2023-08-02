/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/ctype.h>
#include <xen/lib.h>

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long long simple_strtoull(
    const char *cp, const char **endp, unsigned int base)
{
    unsigned long long result = 0, value;

    if ( !base )
    {
        base = 10;
        if ( *cp == '0' )
        {
            base = 8;
            cp++;
            if ( (toupper(*cp) == 'X') && isxdigit(cp[1]) )
            {
                cp++;
                base = 16;
            }
        }
    }
    else if ( base == 16 )
    {
        if ( cp[0] == '0' && toupper(cp[1]) == 'X' )
            cp += 2;
    }

    while ( isxdigit(*cp) &&
            (value = isdigit(*cp) ? *cp - '0'
                                  : (islower(*cp) ? toupper(*cp)
                                                  : *cp) - 'A' + 10) < base )
    {
        result = result * base + value;
        cp++;
    }

    if ( endp )
        *endp = cp;

    return result;
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
