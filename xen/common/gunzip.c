#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>

#define HEAPORDER 3

static unsigned char *__initdata window;
#define memptr long
static memptr __initdata free_mem_ptr;
static memptr __initdata free_mem_end_ptr;

#define WSIZE           0x80000000

static unsigned char *__initdata inbuf;
static unsigned __initdata insize;

/* Index of next byte to be processed in inbuf: */
static unsigned __initdata inptr;

/* Bytes in output buffer: */
static unsigned __initdata outcnt;

#define OF(args)        args
#define STATIC          static

#define memzero(s, n)   memset((s), 0, (n))

typedef unsigned char   uch;
typedef unsigned short  ush;
typedef unsigned long   ulg;

#define INIT            __init
#define INITDATA        __initdata

#define get_byte()      (inptr < insize ? inbuf[inptr++] : fill_inbuf())

/* Diagnostic functions */
#ifdef DEBUG
#  define Assert(cond, msg) do { if (!(cond)) error(msg); } while (0)
#  define Trace(x)      do { fprintf x; } while (0)
#  define Tracev(x)     do { if (verbose) fprintf x ; } while (0)
#  define Tracevv(x)    do { if (verbose > 1) fprintf x ; } while (0)
#  define Tracec(c, x)  do { if (verbose && (c)) fprintf x ; } while (0)
#  define Tracecv(c, x) do { if (verbose > 1 && (c)) fprintf x ; } while (0)
#else
#  define Assert(cond, msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c, x)
#  define Tracecv(c, x)
#endif

static long __initdata bytes_out;
static void flush_window(void);

static __init void error(char *x)
{
    panic("%s", x);
}

static __init int fill_inbuf(void)
{
        error("ran out of input data");
        return 0;
}


#include "inflate.c"

static __init void flush_window(void)
{
    /*
     * The window is equal to the output buffer therefore only need to
     * compute the crc.
     */
    unsigned long c = crc;
    unsigned n;
    unsigned char *in, ch;

    in = window;
    for ( n = 0; n < outcnt; n++ )
    {
        ch = *in++;
        c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
    }
    crc = c;

    bytes_out += (unsigned long)outcnt;
    outcnt = 0;
}

__init int gzip_check(char *image, unsigned long image_len)
{
    unsigned char magic0, magic1;

    if ( image_len < 2 )
        return 0;

    magic0 = (unsigned char)image[0];
    magic1 = (unsigned char)image[1];

    return (magic0 == 0x1f) && ((magic1 == 0x8b) || (magic1 == 0x9e));
}

__init int perform_gunzip(char *output, char *image, unsigned long image_len)
{
    int rc;

    if ( !gzip_check(image, image_len) )
        return 1;

    window = (unsigned char *)output;

    free_mem_ptr = (unsigned long)alloc_xenheap_pages(HEAPORDER, 0);
    free_mem_end_ptr = free_mem_ptr + (PAGE_SIZE << HEAPORDER);

    inbuf = (unsigned char *)image;
    insize = image_len;
    inptr = 0;

    makecrc();

    if ( gunzip() < 0 )
    {
        rc = -EINVAL;
    }
    else
    {
        rc = 0;
    }

    free_xenheap_pages((void *)free_mem_ptr, HEAPORDER);

    return rc;
}
