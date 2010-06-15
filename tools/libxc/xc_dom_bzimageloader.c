/*
 * Xen domain builder -- bzImage bits
 *
 * Parse and load bzImage kernel images.
 *
 * This relies on version 2.08 of the boot protocol, which contains an
 * ELF file embedded in the bzImage.  The loader extracts this ELF
 * image and passes it off to the standard ELF loader.
 *
 * This code is licenced under the GPL.
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 * written 2007 by Jeremy Fitzhardinge <jeremy@xensource.com>
 * written 2008 by Ian Campbell <ijc@hellion.org.uk>
 * written 2009 by Chris Lalancette <clalance@redhat.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom.h"

#if defined(HAVE_BZLIB)

#include <bzlib.h>

static int xc_try_bzip2_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    bz_stream stream;
    int ret;
    char *out_buf;
    char *tmp_buf;
    int retval = -1;
    int outsize;
    uint64_t total;

    stream.bzalloc = NULL;
    stream.bzfree = NULL;
    stream.opaque = NULL;

    ret = BZ2_bzDecompressInit(&stream, 0, 0);
    if ( ret != BZ_OK )
    {
        DOMPRINTF("BZIP2: Error initting stream");
        return -1;
    }

    /* sigh.  We don't know up-front how much memory we are going to need
     * for the output buffer.  Allocate the output buffer to be equal
     * the input buffer to start, and we'll realloc as needed.
     */
    outsize = dom->kernel_size;
    out_buf = malloc(outsize);
    if ( out_buf == NULL )
    {
        DOMPRINTF("BZIP2: Failed to alloc memory");
        goto bzip2_cleanup;
    }

    stream.next_in = dom->kernel_blob;
    stream.avail_in = dom->kernel_size;

    stream.next_out = out_buf;
    stream.avail_out = dom->kernel_size;

    for ( ; ; )
    {
        ret = BZ2_bzDecompress(&stream);
        if ( (stream.avail_out == 0) || (ret != BZ_OK) )
        {
            tmp_buf = realloc(out_buf, outsize * 2);
            if ( tmp_buf == NULL )
            {
                DOMPRINTF("BZIP2: Failed to realloc memory");
                free(out_buf);
                goto bzip2_cleanup;
            }
            out_buf = tmp_buf;

            stream.next_out = out_buf + outsize;
            stream.avail_out = (outsize * 2) - outsize;
            outsize *= 2;
        }

        if ( ret != BZ_OK )
        {
            if ( ret == BZ_STREAM_END )
            {
                DOMPRINTF("BZIP2: Saw data stream end");
                retval = 0;
                break;
            }
            DOMPRINTF("BZIP2: error");
        }
    }

    total = (((uint64_t)stream.total_out_hi32) << 32) | stream.total_out_lo32;

    DOMPRINTF("%s: BZIP2 decompress OK, 0x%zx -> 0x%lx",
              __FUNCTION__, *size, (long unsigned int) total);

    *blob = out_buf;
    *size = total;

 bzip2_cleanup:
    BZ2_bzDecompressEnd(&stream);

    return retval;
}

#else /* !defined(HAVE_BZLIB) */

static int xc_try_bzip2_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    DOMPRINTF("%s: BZIP2 decompress support unavailable",
              __FUNCTION__);
    return -1;
}

#endif

#if defined(HAVE_LZMA)

#include <lzma.h>

static uint64_t physmem(void)
{
    uint64_t ret = 0;
    const long pagesize = sysconf(_SC_PAGESIZE);
    const long pages = sysconf(_SC_PHYS_PAGES);

    if ( (pagesize != -1) || (pages != -1) )
    {
        /*
         * According to docs, pagesize * pages can overflow.
         * Simple case is 32-bit box with 4 GiB or more RAM,
         * which may report exactly 4 GiB of RAM, and "long"
         * being 32-bit will overflow. Casting to uint64_t
         * hopefully avoids overflows in the near future.
         */
        ret = (uint64_t)(pagesize) * (uint64_t)(pages);
    }

    return ret;
}

static int xc_try_lzma_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret ret;
    lzma_action action = LZMA_RUN;
    unsigned char *out_buf;
    unsigned char *tmp_buf;
    int retval = -1;
    int outsize;
    const char *msg;

    ret = lzma_alone_decoder(&stream, physmem() / 3);
    if ( ret != LZMA_OK )
    {
        DOMPRINTF("LZMA: Failed to init stream decoder");
        return -1;
    }

    /* sigh.  We don't know up-front how much memory we are going to need
     * for the output buffer.  Allocate the output buffer to be equal
     * the input buffer to start, and we'll realloc as needed.
     */
    outsize = dom->kernel_size;
    out_buf = malloc(outsize);
    if ( out_buf == NULL )
    {
        DOMPRINTF("LZMA: Failed to alloc memory");
        goto lzma_cleanup;
    }

    stream.next_in = dom->kernel_blob;
    stream.avail_in = dom->kernel_size;

    stream.next_out = out_buf;
    stream.avail_out = dom->kernel_size;

    for ( ; ; )
    {
        ret = lzma_code(&stream, action);
        if ( (stream.avail_out == 0) || (ret != LZMA_OK) )
        {
            tmp_buf = realloc(out_buf, outsize * 2);
            if ( tmp_buf == NULL )
            {
                DOMPRINTF("LZMA: Failed to realloc memory");
                free(out_buf);
                goto lzma_cleanup;
            }
            out_buf = tmp_buf;

            stream.next_out = out_buf + outsize;
            stream.avail_out = (outsize * 2) - outsize;
            outsize *= 2;
        }

        if ( ret != LZMA_OK )
        {
            if ( ret == LZMA_STREAM_END )
            {
                DOMPRINTF("LZMA: Saw data stream end");
                retval = 0;
                break;
            }

            switch ( ret )
            {
            case LZMA_MEM_ERROR:
                msg = strerror(ENOMEM);
                break;

            case LZMA_MEMLIMIT_ERROR:
                msg = "Memory usage limit reached";
                break;

            case LZMA_FORMAT_ERROR:
                msg = "File format not recognized";
                break;

            case LZMA_OPTIONS_ERROR:
                // FIXME: Better message?
                msg = "Unsupported compression options";
                break;

            case LZMA_DATA_ERROR:
                msg = "File is corrupt";
                break;

            case LZMA_BUF_ERROR:
                msg = "Unexpected end of input";
                break;

            default:
                msg = "Internal program error (bug)";
                break;
            }
            DOMPRINTF("%s: LZMA decompression error %s",
                      __FUNCTION__, msg);
            break;
        }
    }

    DOMPRINTF("%s: LZMA decompress OK, 0x%zx -> 0x%zx",
              __FUNCTION__, *size, (size_t)stream.total_out);

    *blob = out_buf;
    *size = stream.total_out;

 lzma_cleanup:
    lzma_end(&stream);

    return retval;
}

#else /* !defined(HAVE_LZMA) */

static int xc_try_lzma_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    DOMPRINTF("%s: LZMA decompress support unavailable",
              __FUNCTION__);
    return -1;
}

#endif

#if defined(HAVE_LZO1X)

#include <lzo/lzo1x.h>

#define LZOP_HEADER_HAS_FILTER 0x00000800
#define LZOP_MAX_BLOCK_SIZE (64*1024*1024)

static inline uint_fast16_t lzo_read_16(const unsigned char *buf)
{
    return buf[1] | (buf[0] << 8);
}

static inline uint_fast32_t lzo_read_32(const unsigned char *buf)
{
    return lzo_read_16(buf + 2) | ((uint32_t)lzo_read_16(buf) << 16);
}

static int xc_try_lzo1x_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    int ret;
    const unsigned char *cur = dom->kernel_blob;
    unsigned char *out_buf = NULL;
    size_t left = dom->kernel_size;
    const char *msg;
    unsigned version;
    static const unsigned char magic[] = {
        0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a
    };

    ret = lzo_init();
    if ( ret != LZO_E_OK )
    {
        DOMPRINTF("LZO1x: Failed to init library (%d)\n", ret);
        return -1;
    }

    if ( left < 16 || memcmp(cur, magic, 9) )
    {
        DOMPRINTF("LZO1x: Unrecognized magic\n");
        return -1;
    }

    /* get version (2bytes), skip library version (2),
     * 'need to be extracted' version (2) and method (1) */
    version = lzo_read_16(cur + 9);
    cur += 16;
    left -= 16;

    if ( version >= 0x0940 )
    {
        /* skip level */
        ++cur;
        if ( left )
            --left;
    }

    if ( left >= 4 && (lzo_read_32(cur) & LZOP_HEADER_HAS_FILTER) )
        ret = 8; /* flags + filter info */
    else
        ret = 4; /* flags */

    /* skip mode and mtime_low */
    ret += 8;
    if ( version >= 0x0940 )
        ret += 4; /* skip mtime_high */

    /* don't care about the file name, and skip checksum */
    if ( left > ret )
        ret += 1 + cur[ret] + 4;

    if ( left < ret )
    {
        DOMPRINTF("LZO1x: Incomplete header\n");
        return -1;
    }
    cur += ret;
    left -= ret;

    for ( *size = 0; ; )
    {
        lzo_uint src_len, dst_len, out_len;
        unsigned char *tmp_buf;

        msg = "Short input";
        if ( left < 4 )
            break;

        dst_len = lzo_read_32(cur);
        if ( !dst_len )
            return 0;

        if ( dst_len > LZOP_MAX_BLOCK_SIZE )
        {
            msg = "Block size too large";
            break;
        }

        if ( left < 12 )
            break;

        src_len = lzo_read_32(cur + 4);
        cur += 12; /* also skip block checksum info */
        left -= 12;

        msg = "Bad source length";
        if ( src_len <= 0 || src_len > dst_len || src_len > left )
            break;

        msg = "Failed to (re)alloc memory";
        tmp_buf = realloc(out_buf, *size + dst_len);
        if ( tmp_buf == NULL )
            break;

        out_buf = tmp_buf;
        out_len = dst_len;

        ret = lzo1x_decompress_safe(cur, src_len,
                                    out_buf + *size, &out_len, NULL);
        switch ( ret )
        {
        case LZO_E_OK:
            msg = "Input underrun";
            if ( out_len != dst_len )
                break;

            *blob = out_buf;
            *size += out_len;
            cur += src_len;
            left -= src_len;
            continue;

        case LZO_E_INPUT_NOT_CONSUMED:
            msg = "Unconsumed input";
            break;

        case LZO_E_OUTPUT_OVERRUN:
            msg = "Output overrun";
            break;

        case LZO_E_INPUT_OVERRUN:
            msg = "Input overrun";
            break;

        case LZO_E_LOOKBEHIND_OVERRUN:
            msg = "Look-behind overrun";
            break;

        case LZO_E_EOF_NOT_FOUND:
            msg = "No EOF marker";
            break;

        case LZO_E_ERROR:
            msg = "General error";
            break;

        default:
            msg = "Internal program error (bug)";
            break;
        }

        break;
    }

    free(out_buf);
    DOMPRINTF("LZO1x decompression error: %s\n", msg);

    return -1;
}

#else /* !defined(HAVE_LZO1X) */

static int xc_try_lzo1x_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    DOMPRINTF("%s: LZO1x decompress support unavailable\n",
                  __FUNCTION__);
    return -1;
}

#endif

struct setup_header {
    uint8_t  _pad0[0x1f1];  /* skip uninteresting stuff */
    uint8_t  setup_sects;
    uint16_t root_flags;
    uint32_t syssize;
    uint16_t ram_size;
    uint16_t vid_mode;
    uint16_t root_dev;
    uint16_t boot_flag;
    uint16_t jump;
    uint32_t header;
#define HDR_MAGIC  "HdrS"
#define HDR_MAGIC_SZ 4
    uint16_t version;
#define VERSION(h,l) (((h)<<8) | (l))
    uint32_t realmode_swtch;
    uint16_t start_sys;
    uint16_t kernel_version;
    uint8_t  type_of_loader;
    uint8_t  loadflags;
    uint16_t setup_move_size;
    uint32_t code32_start;
    uint32_t ramdisk_image;
    uint32_t ramdisk_size;
    uint32_t bootsect_kludge;
    uint16_t heap_end_ptr;
    uint16_t _pad1;
    uint32_t cmd_line_ptr;
    uint32_t initrd_addr_max;
    uint32_t kernel_alignment;
    uint8_t  relocatable_kernel;
    uint8_t  _pad2[3];
    uint32_t cmdline_size;
    uint32_t hardware_subarch;
    uint64_t hardware_subarch_data;
    uint32_t payload_offset;
    uint32_t payload_length;
} __attribute__((packed));

extern struct xc_dom_loader elf_loader;

static unsigned int payload_offset(struct setup_header *hdr)
{
    unsigned int off;

    off = (hdr->setup_sects + 1) * 512;
    off += hdr->payload_offset;
    return off;
}

static int xc_dom_probe_bzimage_kernel(struct xc_dom_image *dom)
{
    struct setup_header *hdr;
    int ret;

    if ( dom->kernel_blob == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: no kernel image loaded", __FUNCTION__);
        return -EINVAL;
    }

    if ( dom->kernel_size < sizeof(struct setup_header) )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: kernel image too small", __FUNCTION__);
        return -EINVAL;
    }

    hdr = dom->kernel_blob;

    if ( memcmp(&hdr->header, HDR_MAGIC, HDR_MAGIC_SZ) != 0 )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                     "%s: kernel is not a bzImage", __FUNCTION__);
        return -EINVAL;
    }

    if ( hdr->version < VERSION(2,8) )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL, "%s: boot protocol"
                     " too old (%04x)", __FUNCTION__, hdr->version);
        return -EINVAL;
    }

    dom->kernel_blob = dom->kernel_blob + payload_offset(hdr);
    dom->kernel_size = hdr->payload_length;

    if ( memcmp(dom->kernel_blob, "\037\213", 2) == 0 )
    {
        ret = xc_dom_try_gunzip(dom, &dom->kernel_blob, &dom->kernel_size);
        if ( ret == -1 )
        {
            xc_dom_panic(dom->xch, XC_INVALID_KERNEL, "%s: unable to"
                         " gzip decompress kernel", __FUNCTION__);
            return -EINVAL;
        }
    }
    else if ( memcmp(dom->kernel_blob, "\102\132\150", 3) == 0 )
    {
        ret = xc_try_bzip2_decode(dom, &dom->kernel_blob, &dom->kernel_size);
        if ( ret < 0 )
        {
            xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                         "%s unable to BZIP2 decompress kernel",
                         __FUNCTION__);
            return -EINVAL;
        }
    }
    else if ( memcmp(dom->kernel_blob, "\135\000", 2) == 0 )
    {
        ret = xc_try_lzma_decode(dom, &dom->kernel_blob, &dom->kernel_size);
        if ( ret < 0 )
        {
            xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                         "%s unable to LZMA decompress kernel",
                         __FUNCTION__);
            return -EINVAL;
        }
    }
    else if ( memcmp(dom->kernel_blob, "\x89LZO", 5) == 0 )
    {
        ret = xc_try_lzo1x_decode(dom, &dom->kernel_blob, &dom->kernel_size);
        if ( ret < 0 )
        {
            xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                         "%s unable to LZO decompress kernel\n",
                         __FUNCTION__);
            return -EINVAL;
        }
    }
    else
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                     "%s: unknown compression format", __FUNCTION__);
        return -EINVAL;
    }

    return elf_loader.probe(dom);
}

static int xc_dom_parse_bzimage_kernel(struct xc_dom_image *dom)
{
    return elf_loader.parser(dom);
}

static int xc_dom_load_bzimage_kernel(struct xc_dom_image *dom)
{
    return elf_loader.loader(dom);
}

static struct xc_dom_loader bzimage_loader = {
    .name = "Linux bzImage",
    .probe = xc_dom_probe_bzimage_kernel,
    .parser = xc_dom_parse_bzimage_kernel,
    .loader = xc_dom_load_bzimage_kernel,
};

static void __init register_loader(void)
{
    xc_dom_register_loader(&bzimage_loader);
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
