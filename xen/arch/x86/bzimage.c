#include <xen/cache.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/decompress.h>
#include <xen/libelf.h>
#include <asm/bzimage.h>

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

static __init unsigned long output_length(char *image, unsigned long image_len)
{
    return *(uint32_t *)&image[image_len - 4];
}

static __init int gzip_check(char *image, unsigned long image_len)
{
    unsigned char magic0, magic1;

    if ( image_len < 2 )
        return 0;

    magic0 = (unsigned char)image[0];
    magic1 = (unsigned char)image[1];

    return (magic0 == 0x1f) && ((magic1 == 0x8b) || (magic1 == 0x9e));
}

static __init int perform_gunzip(char *output, char *image, unsigned long image_len)
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

struct __packed setup_header {
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
    };

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

static unsigned long __initdata orig_image_len;

unsigned long __init bzimage_headroom(char *image_start,
                                      unsigned long image_length)
{
    struct setup_header *hdr = (struct setup_header *)image_start;
    int err;
    unsigned long headroom;

    err = bzimage_check(hdr, image_length);
    if ( err < 0 )
        return 0;

    if ( err > 0 )
    {
        image_start += (hdr->setup_sects + 1) * 512 + hdr->payload_offset;
        image_length = hdr->payload_length;
    }

    if ( elf_is_elfbinary(image_start, image_length) )
        return 0;

    orig_image_len = image_length;
    headroom = output_length(image_start, image_length);
    if (gzip_check(image_start, image_length))
    {
        headroom += headroom >> 12; /* Add 8 bytes for every 32K input block */
        headroom += (32768 + 18); /* Add 32K + 18 bytes of extra headroom */
    } else
        headroom += image_length;
    headroom = (headroom + 4095) & ~4095;

    return headroom;
}

int __init bzimage_parse(char *image_base, char **image_start, unsigned long *image_len)
{
    struct setup_header *hdr = (struct setup_header *)(*image_start);
    int err = bzimage_check(hdr, *image_len);
    unsigned long output_len;

    if ( err < 0 )
        return err;

    if ( err > 0 )
    {
        *image_start += (hdr->setup_sects + 1) * 512 + hdr->payload_offset;
        *image_len = hdr->payload_length;
    }

    if ( elf_is_elfbinary(*image_start, *image_len) )
        return 0;

    BUG_ON(!(image_base < *image_start));

    output_len = output_length(*image_start, orig_image_len);

    if ( (err = perform_gunzip(image_base, *image_start, orig_image_len)) > 0 )
        err = decompress(*image_start, orig_image_len, image_base);

    if ( !err )
    {
        *image_start = image_base;
        *image_len = output_len;
    }

    return err > 0 ? 0 : err;
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
