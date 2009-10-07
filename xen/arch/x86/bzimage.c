#include <xen/cache.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/string.h>
#include <xen/types.h>
#include <asm/bzimage.h>

#define HEAPORDER 3

static unsigned char *window;
#define memptr long
static memptr free_mem_ptr;
static memptr free_mem_end_ptr;

#define WSIZE           0x80000000

static unsigned char    *inbuf;
static unsigned         insize;

/* Index of next byte to be processed in inbuf: */
static unsigned         inptr;

/* Bytes in output buffer: */
static unsigned         outcnt;

#define OF(args)        args
#define STATIC          static

#define memzero(s, n)   memset((s), 0, (n))

typedef unsigned char   uch;
typedef unsigned short  ush;
typedef unsigned long   ulg;

#define INIT __init

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

static long bytes_out;
static void flush_window(void);

static __init void error(char *x)
{
    panic("%s\n", x);
}

static __init int fill_inbuf(void)
{
        error("ran out of input data");
        return 0;
}


#include "../../common/inflate.c"

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

static __init int gzip_length(char *image, unsigned long image_len)
{
    return *(uint32_t *)&image[image_len - 4];
}

static  __init int perform_gunzip(char *output, char **_image_start, unsigned long *image_len)
{
    char *image = *_image_start;
    int rc;
    unsigned char magic0 = (unsigned char)image[0];
    unsigned char magic1 = (unsigned char)image[1];

    if ( magic0 != 0x1f || ( (magic1 != 0x8b) && (magic1 != 0x9e) ) )
        return 0;

    window = (unsigned char *)output;

    free_mem_ptr = (unsigned long)alloc_xenheap_pages(HEAPORDER, 0);
    free_mem_end_ptr = free_mem_ptr + (PAGE_SIZE << HEAPORDER);

    inbuf = (unsigned char *)image;
    insize = *image_len;
    inptr = 0;

    makecrc();

    if ( gunzip() < 0 )
    {
        rc = -EINVAL;
    }
    else
    {
        *_image_start = (char *)window;
        *image_len = gzip_length(image, *image_len);
        rc = 0;
    }

    free_xenheap_pages((void *)free_mem_ptr, HEAPORDER);

    return rc;
}

struct setup_header {
        uint8_t         _pad0[0x1f1];           /* skip uninteresting stuff */
        uint8_t         setup_sects;
        uint16_t        root_flags;
        uint32_t        syssize;
        uint16_t        ram_size;
        uint16_t        vid_mode;
        uint16_t        root_dev;
        uint16_t        boot_flag;
        uint16_t        jump;
        uint32_t        header;
#define HDR_MAGIC               "HdrS"
#define HDR_MAGIC_SZ    4
        uint16_t        version;
#define VERSION(h,l)    (((h)<<8) | (l))
        uint32_t        realmode_swtch;
        uint16_t        start_sys;
        uint16_t        kernel_version;
        uint8_t         type_of_loader;
        uint8_t         loadflags;
        uint16_t        setup_move_size;
        uint32_t        code32_start;
        uint32_t        ramdisk_image;
        uint32_t        ramdisk_size;
        uint32_t        bootsect_kludge;
        uint16_t        heap_end_ptr;
        uint16_t        _pad1;
        uint32_t        cmd_line_ptr;
        uint32_t        initrd_addr_max;
        uint32_t        kernel_alignment;
        uint8_t         relocatable_kernel;
        uint8_t         _pad2[3];
        uint32_t        cmdline_size;
        uint32_t        hardware_subarch;
        uint64_t        hardware_subarch_data;
        uint32_t        payload_offset;
        uint32_t        payload_length;
    } __attribute__((packed));

static __init int bzimage_check(struct setup_header *hdr, unsigned long len)
{
    if ( len < sizeof(struct setup_header) )
        return 0;

    if ( memcmp(&hdr->header, HDR_MAGIC, HDR_MAGIC_SZ) != 0 )
        return 0;

    if ( hdr->version < VERSION(2,8) ) {
        printk("Cannot load bzImage v%d.%02d at least v2.08 is required\n",
           hdr->version >> 8, hdr->version & 0xff);
        return -EINVAL;
    }
    return 1;
}

int __init bzimage_headroom(char *image_start, unsigned long image_length)
{
    struct setup_header *hdr = (struct setup_header *)image_start;
    char *img;
    int err, headroom;

    err = bzimage_check(hdr, image_length);
    if (err < 1)
        return 0;

    img = image_start + (hdr->setup_sects+1) * 512;
    img += hdr->payload_offset;

    headroom = gzip_length(img, hdr->payload_length);
    headroom += headroom >> 12; /* Add 8 bytes for every 32K input block */
    headroom += (32768 + 18); /* Add 32K + 18 bytes of extra headroom */
    headroom = (headroom + 4095) & ~4095;

    return headroom;
}

int __init bzimage_parse(char *image_base, char **image_start, unsigned long *image_len)
{
    struct setup_header *hdr = (struct setup_header *)(*image_start);
    int err = bzimage_check(hdr, *image_len);

    if (err < 1)
        return err;

    BUG_ON(!(image_base < *image_start));

    *image_start += (hdr->setup_sects+1) * 512;
    *image_start += hdr->payload_offset;
    *image_len = hdr->payload_length;

    if ( (err = perform_gunzip(image_base, image_start, image_len)) < 0 )
        return err;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
