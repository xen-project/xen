#include <xen/lib.h>

unsigned long long parse_size_and_unit(const char *s, const char **ps)
{
    unsigned long long ret;
    const char *s1;

    ret = simple_strtoull(s, &s1, 0);

    switch ( *s1 )
    {
    case 'T': case 't':
        ret <<= 10;
        /* fallthrough */
    case 'G': case 'g':
        ret <<= 10;
        /* fallthrough */
    case 'M': case 'm':
        ret <<= 10;
        /* fallthrough */
    case 'K': case 'k':
        ret <<= 10;
        /* fallthrough */
    case 'B': case 'b':
        s1++;
        break;
    case '%':
        if ( ps )
            break;
        /* fallthrough */
    default:
        ret <<= 10; /* default to kB */
        break;
    }

    if ( ps != NULL )
        *ps = s1;

    return ret;
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
