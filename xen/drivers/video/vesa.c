/******************************************************************************
 * vesa.c
 *
 * VESA linear frame buffer handling.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/xmalloc.h>
#include <xen/kernel.h>
#include <xen/vga.h>
#include <asm/io.h>
#include <asm/page.h>
#include "font.h"
#include "lfb.h"

#define vlfb_info    vga_console_info.u.vesa_lfb

static void lfb_flush(void);

static unsigned char *lfb;
static const struct font_desc *font;
static bool_t vga_compat;

static unsigned int vram_total;
integer_param("vesa-ram", vram_total);

static unsigned int vram_remap;
integer_param("vesa-map", vram_remap);

static int font_height;
static int __init parse_font_height(const char *s)
{
    if ( simple_strtoul(s, &s, 10) == 8 && (*s++ == 'x') )
        font_height = simple_strtoul(s, &s, 10);
    if ( *s != '\0' )
        font_height = 0;

    return 0;
}
custom_param("font", parse_font_height);

static inline paddr_t lfb_base(void)
{
    return ((paddr_t)vlfb_info.ext_lfb_base << 32) | vlfb_info.lfb_base;
}

void __init vesa_early_init(void)
{
    unsigned int vram_vmode;

    vga_compat = !(vga_console_info.u.vesa_lfb.gbl_caps & 2);

    if ( (vlfb_info.bits_per_pixel < 8) || (vlfb_info.bits_per_pixel > 32) )
        return;

    if ( font_height == 0 ) /* choose a sensible default */
        font = ((vlfb_info.height <= 600) ? &font_vga_8x8 :
                (vlfb_info.height <= 768) ? &font_vga_8x14 : &font_vga_8x16);
    else if ( font_height <= 8 )
        font = &font_vga_8x8;
    else if ( font_height <= 14 )
        font = &font_vga_8x14;
    else
        font = &font_vga_8x16;

    /*   vram_vmode -- that is the amount of memory needed for the
     *                 used video mode, i.e. the minimum amount of
     *                 memory we need. */
    vram_vmode = vlfb_info.height * vlfb_info.bytes_per_line;

    /*   vram_total -- all video memory we have. Used for mtrr
     *                 entries. */
    vram_total = vram_total ? (vram_total << 20) : (vlfb_info.lfb_size << 16);
    vram_total = max_t(unsigned int, vram_total, vram_vmode);

    /*   vram_remap -- the amount of video memory we are going to
     *                 use for vesafb.  With modern cards it is no
     *                 option to simply use vram_total as that
     *                 wastes plenty of kernel address space. */
    vram_remap = (vram_remap ?
                  (vram_remap << 20) :
                  ((vram_vmode + (1 << L2_PAGETABLE_SHIFT) - 1) &
                   ~((1 << L2_PAGETABLE_SHIFT) - 1)));
    vram_remap = max_t(unsigned int, vram_remap, vram_vmode);
    vram_remap = min_t(unsigned int, vram_remap, vram_total);
}

void __init vesa_init(void)
{
    struct lfb_prop lfbp;

    if ( !font )
        return;

    lfbp.font = font;
    lfbp.bits_per_pixel = vlfb_info.bits_per_pixel;
    lfbp.bytes_per_line = vlfb_info.bytes_per_line;
    lfbp.width = vlfb_info.width;
    lfbp.height = vlfb_info.height;
    lfbp.flush = lfb_flush;
    lfbp.text_columns = vlfb_info.width / font->width;
    lfbp.text_rows = vlfb_info.height / font->height;

    lfbp.lfb = lfb = ioremap(lfb_base(), vram_remap);
    if ( !lfb )
        return;

    memset(lfb, 0, vram_remap);

    printk(XENLOG_INFO "vesafb: framebuffer at 0x%" PRIpaddr ", mapped to 0x%p, using %uk, total %uk\n",
           lfb_base(), lfb,
           vram_remap >> 10, vram_total >> 10);
    printk(XENLOG_INFO "vesafb: mode is %dx%dx%u, linelength=%d, font %ux%u\n",
           vlfb_info.width, vlfb_info.height,
           vlfb_info.bits_per_pixel, vlfb_info.bytes_per_line,
           font->width, font->height);
    printk(XENLOG_INFO "vesafb: %scolor: size=%d:%d:%d:%d, "
           "shift=%d:%d:%d:%d\n",
           vlfb_info.bits_per_pixel > 8 ? "True" :
           vga_compat ? "Pseudo" : "Static Pseudo",
           vlfb_info.rsvd_size, vlfb_info.red_size,
           vlfb_info.green_size, vlfb_info.blue_size,
           vlfb_info.rsvd_pos, vlfb_info.red_pos,
           vlfb_info.green_pos, vlfb_info.blue_pos);

    if ( vlfb_info.bits_per_pixel > 8 )
    {
        /* Light grey in truecolor. */
        unsigned int grey = 0xaaaaaaaa;
        lfbp.pixel_on =
            ((grey >> (32 - vlfb_info.  red_size)) << vlfb_info.  red_pos) |
            ((grey >> (32 - vlfb_info.green_size)) << vlfb_info.green_pos) |
            ((grey >> (32 - vlfb_info. blue_size)) << vlfb_info. blue_pos);
    }
    else
    {
        /* White(ish) in default pseudocolor palette. */
        lfbp.pixel_on = 7;
    }

    if ( lfb_init(&lfbp) < 0 )
        return;
    video_puts = lfb_redraw_puts;
}

#include <asm/mtrr.h>

static unsigned int vesa_mtrr;
integer_param("vesa-mtrr", vesa_mtrr);

void __init vesa_mtrr_init(void)
{
    static const int mtrr_types[] = {
        0, MTRR_TYPE_UNCACHABLE, MTRR_TYPE_WRBACK,
        MTRR_TYPE_WRCOMB, MTRR_TYPE_WRTHROUGH };
    unsigned int size_total;
    int rc, type;

    if ( !lfb || (vesa_mtrr == 0) || (vesa_mtrr >= ARRAY_SIZE(mtrr_types)) )
        return;

    type = mtrr_types[vesa_mtrr];
    if ( !type )
        return;

    /* Find the largest power-of-two */
    size_total = vram_total;
    while ( size_total & (size_total - 1) )
        size_total &= size_total - 1;

    /* Try and find a power of two to add */
    do {
        rc = mtrr_add(lfb_base(), size_total, type, 1);
        size_total >>= 1;
    } while ( (size_total >= PAGE_SIZE) && (rc == -EINVAL) );
}

static void lfb_flush(void)
{
    if ( vesa_mtrr == 3 )
        __asm__ __volatile__ ("sfence" : : : "memory");
}

void __init vesa_endboot(bool_t keep)
{
    if ( keep )
    {
        video_puts = lfb_scroll_puts;
        lfb_carriage_return();
    }
    else
    {
        unsigned int i, bpp = (vlfb_info.bits_per_pixel + 7) >> 3;
        for ( i = 0; i < vlfb_info.height; i++ )
            memset(lfb + i * vlfb_info.bytes_per_line, 0,
                   vlfb_info.width * bpp);
        lfb_flush();
        lfb_free();
    }
}
