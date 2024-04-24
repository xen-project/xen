#include <xen/errno.h>
#include <xen/gunzip.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>

#define WSIZE           0x80000000U

struct gunzip_state {
    unsigned char *window;

    /* window position */
    unsigned int wp;

    unsigned char *inbuf;
    unsigned int insize;
    /* Index of next byte to be processed in inbuf: */
    unsigned int inptr;

    unsigned long bytes_out;

    unsigned long bb;      /* bit buffer */
    unsigned int  bk;      /* bits in bit buffer */

    uint32_t crc_32_tab[256];
    uint32_t crc;
};

#define malloc(a)       xmalloc_bytes(a)
#define free(a)         xfree(a)
#define memzero(s, n)   memset((s), 0, (n))

typedef unsigned char   uch;
typedef unsigned short  ush;
typedef unsigned long   ulg;

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

static void flush_window(struct gunzip_state *s);

static __init void error(const char *x)
{
    panic("%s\n", x);
}

static __init int get_byte(struct gunzip_state *s)
{
    if ( s->inptr >= s->insize )
    {
        error("ran out of input data");
        return -1;
    }

    return s->inbuf[s->inptr++];
}

#include "inflate.c"

static __init void flush_window(struct gunzip_state *s)
{
    /*
     * The window is equal to the output buffer therefore only need to
     * compute the crc.
     */
    uint32_t c = ~s->crc;
    unsigned int n;
    unsigned char *in, ch;

    in = s->window;
    for ( n = 0; n < s->wp; n++ )
    {
        ch = *in++;
        c = s->crc_32_tab[(c ^ ch) & 0xff] ^ (c >> 8);
    }
    s->crc = ~c;

    s->bytes_out += s->wp;
    s->wp = 0;
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
    struct gunzip_state *s;
    int rc;

    if ( !gzip_check(image, image_len) )
        return 1;

    s = malloc(sizeof(struct gunzip_state));
    if ( !s )
        return -ENOMEM;

    s->window = (unsigned char *)output;
    s->inbuf = (unsigned char *)image;
    s->insize = image_len;
    s->inptr = 0;
    s->bytes_out = 0;

    makecrc(s);

    if ( gunzip(s) < 0 )
    {
        rc = -EINVAL;
    }
    else
    {
        rc = 0;
    }

    free(s);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
