/******************************************************************************
 * vesa.c
 *
 * VESA linear frame buffer handling.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/xmalloc.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/vga.h>
#include <asm/io.h>
#include "font.h"
#include "lfb.h"

#define vlfb_info    vga_console_info.u.vesa_lfb

static void cf_check lfb_flush(void);

static unsigned char *__read_mostly lfb;
static const struct font_desc *__initdata font;
static bool __initdata vga_compat;

static unsigned int __initdata vram_total;
integer_param("vesa-ram", vram_total);

static unsigned int __initdata vram_remap;

static unsigned int __initdata font_height;
static int __init cf_check parse_font_height(const char *s)
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

    vga_compat = !(vlfb_info.gbl_caps & 2);

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
    vram_remap = ROUNDUP(vram_vmode, 1 << L2_PAGETABLE_SHIFT);
    vram_remap = min(vram_remap, vram_total);
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

    lfbp.lfb = lfb = ioremap_wc(lfb_base(), vram_remap);
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
        unsigned int grey = 0xaaaaaaaaU;
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

static void cf_check lfb_flush(void)
{
    __asm__ __volatile__ ("sfence" : : : "memory");
}

void __init vesa_endboot(bool keep)
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
        iounmap(lfb);
        lfb = ZERO_BLOCK_PTR;
    }
}
