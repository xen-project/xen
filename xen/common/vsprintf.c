/*
 *  linux/lib/vsprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/* vsprintf.c -- Lars Wirzenius & Linus Torvalds. */
/*
 * Wirzenius wrote this portably, Torvalds fucked it up :-)
 */

/* 
 * Fri Jul 13 2001 Crutcher Dunnavant <crutcher+kernel@datastacks.com>
 * - changed to provide snprintf and vsnprintf functions
 * So Feb  1 16:51:32 CET 2004 Juergen Quade <quade@hsnr.de>
 * - scnprintf and vscnprintf
 */

#include <xen/ctype.h>
#include <xen/symbols.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/livepatch.h>
#include <asm/div64.h>
#include <asm/page.h>

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long simple_strtoul(
    const char *cp, const char **endp, unsigned int base)
{
    unsigned long result = 0,value;

    if (!base) {
        base = 10;
        if (*cp == '0') {
            base = 8;
            cp++;
            if ((toupper(*cp) == 'X') && isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    } else if (base == 16) {
        if (cp[0] == '0' && toupper(cp[1]) == 'X')
            cp += 2;
    }
    while (isxdigit(*cp) &&
           (value = isdigit(*cp) ? *cp-'0' : toupper(*cp)-'A'+10) < base) {
        result = result*base + value;
        cp++;
    }
    if (endp)
        *endp = cp;
    return result;
}

EXPORT_SYMBOL(simple_strtoul);

/**
 * simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long simple_strtol(const char *cp, const char **endp, unsigned int base)
{
    if(*cp=='-')
        return -simple_strtoul(cp+1,endp,base);
    return simple_strtoul(cp,endp,base);
}

EXPORT_SYMBOL(simple_strtol);

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long long simple_strtoull(
    const char *cp, const char **endp, unsigned int base)
{
    unsigned long long result = 0,value;

    if (!base) {
        base = 10;
        if (*cp == '0') {
            base = 8;
            cp++;
            if ((toupper(*cp) == 'X') && isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    } else if (base == 16) {
        if (cp[0] == '0' && toupper(cp[1]) == 'X')
            cp += 2;
    }
    while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
                                                               ? toupper(*cp) : *cp)-'A'+10) < base) {
        result = result*base + value;
        cp++;
    }
    if (endp)
        *endp = cp;
    return result;
}

EXPORT_SYMBOL(simple_strtoull);

/**
 * simple_strtoll - convert a string to a signed long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long long simple_strtoll(const char *cp,const char **endp,unsigned int base)
{
    if(*cp=='-')
        return -simple_strtoull(cp+1,endp,base);
    return simple_strtoull(cp,endp,base);
}

static int skip_atoi(const char **s)
{
    int i=0;

    while (isdigit(**s))
        i = i*10 + *((*s)++) - '0';
    return i;
}

#define ZEROPAD 1               /* pad with zero */
#define SIGN    2               /* unsigned/signed long */
#define PLUS    4               /* show plus */
#define SPACE   8               /* space if plus */
#define LEFT    16              /* left justified */
#define SPECIAL 32              /* 0x */
#define LARGE   64              /* use 'ABCDEF' instead of 'abcdef' */

static char *number(
    char *buf, const char *end, unsigned long long num,
    int base, int size, int precision, int type)
{
    char c,sign,tmp[66];
    const char *digits;
    static const char small_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    static const char large_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int i;

    ASSERT(base >= 2 && base <= 36);

    digits = (type & LARGE) ? large_digits : small_digits;
    if (type & LEFT)
        type &= ~ZEROPAD;
    c = (type & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & SIGN) {
        if ((signed long long) num < 0) {
            sign = '-';
            num = - (signed long long) num;
            size--;
        } else if (type & PLUS) {
            sign = '+';
            size--;
        } else if (type & SPACE) {
            sign = ' ';
            size--;
        }
    }
    if (type & SPECIAL) {
        if (num == 0)
            type &= ~SPECIAL;
        else if (base == 16)
            size -= 2;
        else if (base == 8)
            size--;
        else
            type &= ~SPECIAL;
    }
    i = 0;
    if (num == 0)
        tmp[i++]='0';
    else while (num != 0)
        tmp[i++] = digits[do_div(num,base)];
    if (i > precision)
        precision = i;
    size -= precision;
    if (!(type&(ZEROPAD+LEFT))) {
        while(size-->0) {
            if (buf < end)
                *buf = ' ';
            ++buf;
        }
    }
    if (sign) {
        if (buf < end)
            *buf = sign;
        ++buf;
    }
    if (type & SPECIAL) {
        if (buf < end)
            *buf = '0';
        ++buf;
        if (base == 16) {
            if (buf < end)
                *buf = digits[33];
            ++buf;
        }
    }
    if (!(type & LEFT)) {
        while (size-- > 0) {
            if (buf < end)
                *buf = c;
            ++buf;
        }
    }
    while (i < precision--) {
        if (buf < end)
            *buf = '0';
        ++buf;
    }
    while (i-- > 0) {
        if (buf < end)
            *buf = tmp[i];
        ++buf;
    }
    while (size-- > 0) {
        if (buf < end)
            *buf = ' ';
        ++buf;
    }
    return buf;
}

static char *string(char *str, const char *end, const char *s,
                    int field_width, int precision, int flags)
{
    int i, len = (precision < 0) ? strlen(s) : strnlen(s, precision);

    if (!(flags & LEFT)) {
        while (len < field_width--) {
            if (str < end)
                *str = ' ';
            ++str;
        }
    }
    for (i = 0; i < len; ++i) {
        if (str < end)
            *str = *s;
        ++str; ++s;
    }
    while (len < field_width--) {
        if (str < end)
            *str = ' ';
        ++str;
    }

    return str;
}

/* Print a bitmap as '0-3,6-15' */
static char *print_bitmap_list(char *str, const char *end,
                               const unsigned long *bitmap,
                               unsigned int nr_bits)
{
    /* current bit is 'cur', most recently seen range is [rbot, rtop] */
    unsigned int cur, rbot, rtop;
    bool first = true;

    rbot = cur = find_first_bit(bitmap, nr_bits);
    while ( cur < nr_bits )
    {
        rtop = cur;
        cur = find_next_bit(bitmap, nr_bits, cur + 1);

        if ( cur < nr_bits && cur <= rtop + 1 )
            continue;

        if ( !first )
        {
            if ( str < end )
                *str = ',';
            str++;
        }
        first = false;

        str = number(str, end, rbot, 10, -1, -1, 0);
        if ( rbot < rtop )
        {
            if ( str < end )
                *str = '-';
            str++;

            str = number(str, end, rtop, 10, -1, -1, 0);
        }

        rbot = cur;
    }

    return str;
}

/* Print a bitmap as a comma separated hex string. */
static char *print_bitmap_string(char *str, const char *end,
                                 const unsigned long *bitmap,
                                 unsigned int nr_bits)
{
    const unsigned int CHUNKSZ = 32;
    unsigned int chunksz;
    int i;
    bool first = true;

    chunksz = nr_bits & (CHUNKSZ - 1);
    if ( chunksz == 0 )
        chunksz = CHUNKSZ;

    /*
     * First iteration copes with the trailing partial word if nr_bits isn't a
     * round multiple of CHUNKSZ.  All subsequent iterations work on a
     * complete CHUNKSZ block.
     */
    for ( i = ROUNDUP(nr_bits, CHUNKSZ) - CHUNKSZ; i >= 0; i -= CHUNKSZ )
    {
        unsigned int chunkmask = (1ull << chunksz) - 1;
        unsigned int word      = i / BITS_PER_LONG;
        unsigned int offset    = i % BITS_PER_LONG;
        unsigned long val      = (bitmap[word] >> offset) & chunkmask;

        if ( !first )
        {
            if ( str < end )
                *str = ',';
            str++;
        }
        first = false;

        str = number(str, end, val, 16, DIV_ROUND_UP(chunksz, 4), -1, ZEROPAD);

        chunksz = CHUNKSZ;
    }

    return str;
}

/* Print a domain id, using names for system domains.  (e.g. d0 or d[IDLE]) */
static char *print_domain(char *str, const char *end, const struct domain *d)
{
    const char *name = NULL;

    /* Some debugging may have an optionally-NULL pointer. */
    if ( unlikely(!d) )
        return string(str, end, "NULL", -1, -1, 0);

    switch ( d->domain_id )
    {
    case DOMID_IO:   name = "[IO]";   break;
    case DOMID_XEN:  name = "[XEN]";  break;
    case DOMID_COW:  name = "[COW]";  break;
    case DOMID_IDLE: name = "[IDLE]"; break;
        /*
         * In principle, we could ASSERT_UNREACHABLE() in the default case.
         * However, this path is used to print out crash information, which
         * risks recursing infinitely and not printing any useful information.
         */
    }

    if ( str < end )
        *str = 'd';

    if ( name )
        return string(str + 1, end, name, -1, -1, 0);
    else
        return number(str + 1, end, d->domain_id, 10, -1, -1, 0);
}

/* Print a vcpu id.  (e.g. d0v1 or d[IDLE]v0) */
static char *print_vcpu(char *str, const char *end, const struct vcpu *v)
{
    /* Some debugging may have an optionally-NULL pointer. */
    if ( unlikely(!v) )
        return string(str, end, "NULL", -1, -1, 0);

    str = print_domain(str, end, v->domain);

    if ( str < end )
        *str = 'v';

    return number(str + 1, end, v->vcpu_id, 10, -1, -1, 0);
}

static char *print_pci_addr(char *str, const char *end, const pci_sbdf_t *sbdf)
{
    str = number(str, end, sbdf->seg, 16, 4, -1, ZEROPAD);
    if ( str < end )
        *str = ':';
    str = number(str + 1, end, sbdf->bus, 16, 2, -1, ZEROPAD);
    if ( str < end )
        *str = ':';
    str = number(str + 1, end, sbdf->dev, 16, 2, -1, ZEROPAD);
    if ( str < end )
        *str = '.';
    return number(str + 1, end, sbdf->fn, 8, -1, -1, 0);
}

static char *pointer(char *str, const char *end, const char **fmt_ptr,
                     const void *arg, int field_width, int precision,
                     int flags)
{
    const char *fmt = *fmt_ptr, *s;

    /* Custom %p suffixes. See XEN_ROOT/docs/misc/printk-formats.txt */
    switch ( fmt[1] )
    {
    case 'b': /* Bitmap as hex, or list */
        ++*fmt_ptr;

        if ( field_width < 0 )
            return str;

        if ( fmt[2] == 'l' )
        {
            ++*fmt_ptr;

            return print_bitmap_list(str, end, arg, field_width);
        }

        return print_bitmap_string(str, end, arg, field_width);

    case 'd': /* Domain ID from a struct domain *. */
        ++*fmt_ptr;
        return print_domain(str, end, arg);

    case 'h': /* Raw buffer as hex string. */
    {
        const uint8_t *hex_buffer = arg;
        char sep = ' '; /* Separator character. */
        unsigned int i;

        /* Consumed 'h' from the format string. */
        ++*fmt_ptr;

        /* Bound user count from %* to between 0 and 64 bytes. */
        if ( field_width <= 0 )
            return str;
        if ( field_width > 64 )
            field_width = 64;

        /*
         * Peek ahead in the format string to see if a recognised separator
         * modifier is present.
         */
        switch ( fmt[2] )
        {
        case 'C': /* Colons. */
            ++*fmt_ptr;
            sep = ':';
            break;

        case 'D': /* Dashes. */
            ++*fmt_ptr;
            sep = '-';
            break;

        case 'N': /* No separator. */
            ++*fmt_ptr;
            sep = 0;
            break;
        }

        for ( i = 0; ; )
        {
            /* Each byte: 2 chars, 0-padded, base 16, no hex prefix. */
            str = number(str, end, hex_buffer[i], 16, 2, -1, ZEROPAD);

            if ( ++i == field_width )
                return str;

            if ( sep )
            {
                if ( str < end )
                    *str = sep;
                ++str;
            }
        }
    }

    case 'p': /* PCI SBDF. */
        ++*fmt_ptr;
        return print_pci_addr(str, end, arg);

    case 's': /* Symbol name with offset and size (iff offset != 0) */
    case 'S': /* Symbol name unconditionally with offset and size */
    {
        unsigned long sym_size, sym_offset;
        char namebuf[KSYM_NAME_LEN+1];

        /* Advance parents fmt string, as we have consumed 's' or 'S' */
        ++*fmt_ptr;

        s = symbols_lookup((unsigned long)arg, &sym_size, &sym_offset, namebuf);

        /* If the symbol is not found, fall back to printing the address */
        if ( !s )
            break;

        /* Print symbol name */
        str = string(str, end, s, -1, -1, 0);

        if ( fmt[1] == 'S' || sym_offset != 0 )
        {
            /* Print '+<offset>/<len>' */
            str = number(str, end, sym_offset, 16, -1, -1, SPECIAL|SIGN|PLUS);
            if ( str < end )
                *str = '/';
            ++str;
            str = number(str, end, sym_size, 16, -1, -1, SPECIAL);
        }

        /*
         * namebuf contents and s for core hypervisor are same but for Live Patch
         * payloads they differ (namebuf contains the name of the payload).
         */
        if ( namebuf != s )
        {
            str = string(str, end, " [", -1, -1, 0);
            str = string(str, end, namebuf, -1, -1, 0);
            str = string(str, end, "]", -1, -1, 0);
        }

        return str;
    }

    case 'v': /* d<domain-id>v<vcpu-id> from a struct vcpu */
        ++*fmt_ptr;
        return print_vcpu(str, end, arg);
    }

    if ( field_width == -1 )
    {
        field_width = 2 * sizeof(void *);
        flags |= ZEROPAD;
    }

    return number(str, end, (unsigned long)arg,
                  16, field_width, precision, flags);
}

/**
 * vsnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf. If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 *
 * Call this function if you are already dealing with a va_list.
 * You probably want snprintf instead.
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    unsigned long long num;
    int base;
    char *str, *end, c;
    const char *s;

    int flags;          /* flags to number() */

    int field_width;    /* width of output field */
    int precision;              /* min. # of digits for integers; max
                                   number of chars for from string */
    int qualifier;              /* 'h', 'l', or 'L' for integer fields */
                                /* 'z' support added 23/7/1999 S.H.    */
                                /* 'z' changed to 'Z' --davidm 1/25/99 */

    /* Reject out-of-range values early */
    BUG_ON(((int)size < 0) || ((unsigned int)size != size));

    str = buf;
    end = buf + size;

    if (end < buf) {
        end = ((void *) -1);
        size = end - buf;
    }

    for (; *fmt ; ++fmt) {
        if (*fmt != '%') {
            if (str < end)
                *str = *fmt;
            ++str;
            continue;
        }

        /* process flags */
        flags = 0;
    repeat:
        ++fmt;          /* this also skips first '%' */
        switch (*fmt) {
        case '-': flags |= LEFT; goto repeat;
        case '+': flags |= PLUS; goto repeat;
        case ' ': flags |= SPACE; goto repeat;
        case '#': flags |= SPECIAL; goto repeat;
        case '0': flags |= ZEROPAD; goto repeat;
        }

        /* get field width */
        field_width = -1;
        if (isdigit(*fmt))
            field_width = skip_atoi(&fmt);
        else if (*fmt == '*') {
            ++fmt;
            /* it's the next argument */
            field_width = va_arg(args, int);
            if (field_width < 0) {
                field_width = -field_width;
                flags |= LEFT;
            }
        }

        /* get the precision */
        precision = -1;
        if (*fmt == '.') {
            ++fmt;
            if (isdigit(*fmt))
                precision = skip_atoi(&fmt);
            else if (*fmt == '*') {
                ++fmt;
                          /* it's the next argument */
                precision = va_arg(args, int);
            }
            if (precision < 0)
                precision = 0;
        }

        /* get the conversion qualifier */
        qualifier = -1;
        if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' ||
            *fmt =='Z' || *fmt == 'z') {
            qualifier = *fmt;
            ++fmt;
            if (qualifier == 'l' && *fmt == 'l') {
                qualifier = 'L';
                ++fmt;
            }
        }

        /* default base */
        base = 10;

        switch (*fmt) {
        case 'c':
            if (!(flags & LEFT)) {
                while (--field_width > 0) {
                    if (str < end)
                        *str = ' ';
                    ++str;
                }
            }
            c = (unsigned char) va_arg(args, int);
            if (str < end)
                *str = c;
            ++str;
            while (--field_width > 0) {
                if (str < end)
                    *str = ' ';
                ++str;
            }
            continue;

        case 's':
            s = va_arg(args, char *);
            if ((unsigned long)s < PAGE_SIZE)
                s = "<NULL>";

            str = string(str, end, s, field_width, precision, flags);
            continue;

        case 'p':
            /* pointer() might advance fmt (%pS for example) */
            str = pointer(str, end, &fmt, va_arg(args, const void *),
                          field_width, precision, flags);
            continue;


        case 'n':
            if (qualifier == 'l') {
                long * ip = va_arg(args, long *);
                *ip = (str - buf);
            } else if (qualifier == 'Z' || qualifier == 'z') {
                size_t * ip = va_arg(args, size_t *);
                *ip = (str - buf);
            } else {
                int * ip = va_arg(args, int *);
                *ip = (str - buf);
            }
            continue;

        case '%':
            if (str < end)
                *str = '%';
            ++str;
            continue;

            /* integer number formats - set up the flags and "break" */
        case 'o':
            base = 8;
            break;

        case 'X':
            flags |= LARGE;
        case 'x':
            base = 16;
            break;

        case 'd':
        case 'i':
            flags |= SIGN;
        case 'u':
            break;

        default:
            if (str < end)
                *str = '%';
            ++str;
            if (*fmt) {
                if (str < end)
                    *str = *fmt;
                ++str;
            } else {
                --fmt;
            }
            continue;
        }
        if (qualifier == 'L')
            num = va_arg(args, long long);
        else if (qualifier == 'l') {
            num = va_arg(args, unsigned long);
            if (flags & SIGN)
                num = (signed long) num;
        } else if (qualifier == 'Z' || qualifier == 'z') {
            num = va_arg(args, size_t);
        } else if (qualifier == 'h') {
            num = (unsigned short) va_arg(args, int);
            if (flags & SIGN)
                num = (signed short) num;
        } else {
            num = va_arg(args, unsigned int);
            if (flags & SIGN)
                num = (signed int) num;
        }

        str = number(str, end, num, base,
                     field_width, precision, flags);
    }

    /* don't write out a null byte if the buf size is zero */
    if (size > 0) {
        if (str < end)
            *str = '\0';
        else
            end[-1] = '\0';
    }
    /* the trailing null byte doesn't count towards the total
     * ++str;
     */
    return str-buf;
}

EXPORT_SYMBOL(vsnprintf);

/**
 * vscnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The return value is the number of characters which have been written into
 * the @buf not including the trailing '\0'. If @size is <= 0 the function
 * returns 0.
 *
 * Call this function if you are already dealing with a va_list.
 * You probably want scnprintf instead.
 */
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    int i;

    i = vsnprintf(buf,size,fmt,args);
    if (i >= size)
        i = size - 1;
    return (i > 0) ? i : 0;
}

EXPORT_SYMBOL(vscnprintf);

/**
 * snprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters which would be
 * generated for the given input, excluding the trailing null,
 * as per ISO C99.  If the return is greater than or equal to
 * @size, the resulting string is truncated.
 */
int snprintf(char * buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int i;

    va_start(args, fmt);
    i=vsnprintf(buf,size,fmt,args);
    va_end(args);
    return i;
}

EXPORT_SYMBOL(snprintf);

/**
 * scnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters written into @buf not including
 * the trailing '\0'. If @size is <= 0 the function returns 0. If the return is
 * greater than or equal to @size, the resulting string is truncated.
 */

int scnprintf(char * buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int i;

    va_start(args, fmt);
    i = vsnprintf(buf, size, fmt, args);
    va_end(args);
    if (i >= size)
        i = size - 1;
    return (i > 0) ? i : 0;
}
EXPORT_SYMBOL(scnprintf);

/**
 * vasprintf - Format a string and allocate a buffer to place it in
 *
 * @bufp: Pointer to a pointer to receive the allocated buffer
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * -ENOMEM is returned on failure and @bufp is not touched.
 * On success, 0 is returned. The buffer passed back is
 * guaranteed to be null terminated. The memory is allocated
 * from xenheap, so the buffer should be freed with xfree().
 */
int vasprintf(char **bufp, const char *fmt, va_list args)
{
    va_list args_copy;
    size_t size;
    char *buf;

    va_copy(args_copy, args);
    size = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    buf = xmalloc_array(char, ++size);
    if ( !buf )
        return -ENOMEM;

    (void) vsnprintf(buf, size, fmt, args);

    *bufp = buf;
    return 0;
}

/**
 * asprintf - Format a string and place it in a buffer
 * @bufp: Pointer to a pointer to receive the allocated buffer
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * -ENOMEM is returned on failure and @bufp is not touched.
 * On success, 0 is returned. The buffer passed back is
 * guaranteed to be null terminated. The memory is allocated
 * from xenheap, so the buffer should be freed with xfree().
 */
int asprintf(char **bufp, const char *fmt, ...)
{
    va_list args;
    int i;

    va_start(args, fmt);
    i=vasprintf(bufp,fmt,args);
    va_end(args);
    return i;
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
