/******************************************************************************
 * vesa.c
 *
 * VESA linear frame buffer handling.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/xmalloc.h>
#include <xen/kernel.h>
#include <xen/vga.h>
#include <asm/page.h>
#include "font.h"

#define vlfb_info    vga_console_info.u.vesa_lfb
#define text_columns (vlfb_info.width / font->width)
#define text_rows    (vlfb_info.height / font->height)

static void vesa_redraw_puts(const char *s);
static void vesa_scroll_puts(const char *s);

static unsigned char *lfb, *lbuf, *text_buf;
static unsigned int *__initdata line_len;
static const struct font_desc *font;
static bool_t vga_compat;
static unsigned int pixel_on;
static unsigned int xpos, ypos;

static unsigned int vram_total;
integer_param("vesa-ram", vram_total);

static unsigned int vram_remap;
integer_param("vesa-map", vram_remap);

static int font_height;
static void __init parse_font_height(const char *s)
{
    if ( simple_strtoul(s, &s, 10) == 8 && (*s++ == 'x') )
        font_height = simple_strtoul(s, &s, 10);
    if ( *s != '\0' )
        font_height = 0;
}
custom_param("font", parse_font_height);

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
    if ( !font )
        goto fail;

    lbuf = xmalloc_bytes(vlfb_info.bytes_per_line);
    if ( !lbuf )
        goto fail;

    text_buf = xzalloc_bytes(text_columns * text_rows);
    if ( !text_buf )
        goto fail;

    line_len = xzalloc_array(unsigned int, text_columns);
    if ( !line_len )
        goto fail;

    if ( map_pages_to_xen(IOREMAP_VIRT_START,
                          vlfb_info.lfb_base >> PAGE_SHIFT,
                          vram_remap >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_NOCACHE) )
        goto fail;

    lfb = memset((void *)IOREMAP_VIRT_START, 0, vram_remap);

    vga_puts = vesa_redraw_puts;

    printk(XENLOG_INFO "vesafb: framebuffer at 0x%x, mapped to 0x%p, "
           "using %uk, total %uk\n",
           vlfb_info.lfb_base, lfb,
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
        pixel_on = 
            ((grey >> (32 - vlfb_info.  red_size)) << vlfb_info.  red_pos) |
            ((grey >> (32 - vlfb_info.green_size)) << vlfb_info.green_pos) |
            ((grey >> (32 - vlfb_info. blue_size)) << vlfb_info. blue_pos);
    }
    else
    {
        /* White(ish) in default pseudocolor palette. */
        pixel_on = 7;
    }

    return;

 fail:
    xfree(lbuf);
    xfree(text_buf);
    xfree(line_len);
}

#if defined(CONFIG_X86)

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
        rc = mtrr_add(vlfb_info.lfb_base, size_total, type, 1);
        size_total >>= 1;
    } while ( (size_total >= PAGE_SIZE) && (rc == -EINVAL) );
}

static void lfb_flush(void)
{
    if ( vesa_mtrr == 3 )
        __asm__ __volatile__ ("sfence" : : : "memory");
}

#else /* !defined(CONFIG_X86) */

#define lfb_flush() ((void)0)

#endif

void __init vesa_endboot(bool_t keep)
{
    if ( keep )
    {
        xpos = 0;
        vga_puts = vesa_scroll_puts;
    }
    else
    {
        unsigned int i, bpp = (vlfb_info.bits_per_pixel + 7) >> 3;
        for ( i = 0; i < vlfb_info.height; i++ )
            memset(lfb + i * vlfb_info.bytes_per_line, 0,
                   vlfb_info.width * bpp);
        lfb_flush();
    }

    xfree(line_len);
}

/* Render one line of text to given linear framebuffer line. */
static void vesa_show_line(
    const unsigned char *text_line,
    unsigned char *video_line,
    unsigned int nr_chars,
    unsigned int nr_cells)
{
    unsigned int i, j, b, bpp, pixel;

    bpp = (vlfb_info.bits_per_pixel + 7) >> 3;

    for ( i = 0; i < font->height; i++ )
    {
        unsigned char *ptr = lbuf;

        for ( j = 0; j < nr_chars; j++ )
        {
            const unsigned char *bits = font->data;
            bits += ((text_line[j] * font->height + i) *
                     ((font->width + 7) >> 3));
            for ( b = font->width; b--; )
            {
                pixel = (*bits & (1u<<b)) ? pixel_on : 0;
                memcpy(ptr, &pixel, bpp);
                ptr += bpp;
            }
        }

        memset(ptr, 0, (vlfb_info.width - nr_chars * font->width) * bpp);
        memcpy(video_line, lbuf, nr_cells * font->width * bpp);
        video_line += vlfb_info.bytes_per_line;
    }
}

/* Fast mode which redraws all modified parts of a 2D text buffer. */
static void __init vesa_redraw_puts(const char *s)
{
    unsigned int i, min_redraw_y = ypos;
    char c;

    /* Paste characters into text buffer. */
    while ( (c = *s++) != '\0' )
    {
        if ( (c == '\n') || (xpos >= text_columns) )
        {
            if ( ++ypos >= text_rows )
            {
                min_redraw_y = 0;
                ypos = text_rows - 1;
                memmove(text_buf, text_buf + text_columns,
                        ypos * text_columns);
                memset(text_buf + ypos * text_columns, 0, xpos);
            }
            xpos = 0;
        }

        if ( c != '\n' )
            text_buf[xpos++ + ypos * text_columns] = c;
    }

    /* Render modified section of text buffer to VESA linear framebuffer. */
    for ( i = min_redraw_y; i <= ypos; i++ )
    {
        const unsigned char *line = text_buf + i * text_columns;
        unsigned int width;

        for ( width = text_columns; width; --width )
            if ( line[width - 1] )
                 break;
        vesa_show_line(line,
                       lfb + i * font->height * vlfb_info.bytes_per_line,
                       width, max(line_len[i], width));
        line_len[i] = width;
    }

    lfb_flush();
}

/* Slower line-based scroll mode which interacts better with dom0. */
static void vesa_scroll_puts(const char *s)
{
    unsigned int i;
    char c;

    while ( (c = *s++) != '\0' )
    {
        if ( (c == '\n') || (xpos >= text_columns) )
        {
            unsigned int bytes = (vlfb_info.width *
                                  ((vlfb_info.bits_per_pixel + 7) >> 3));
            unsigned char *src = lfb + font->height * vlfb_info.bytes_per_line;
            unsigned char *dst = lfb;
            
            /* New line: scroll all previous rows up one line. */
            for ( i = font->height; i < vlfb_info.height; i++ )
            {
                memcpy(dst, src, bytes);
                src += vlfb_info.bytes_per_line;
                dst += vlfb_info.bytes_per_line;
            }

            /* Render new line. */
            vesa_show_line(
                text_buf,
                lfb + (text_rows-1) * font->height * vlfb_info.bytes_per_line,
                xpos, text_columns);

            xpos = 0;
        }

        if ( c != '\n' )
            text_buf[xpos++] = c;
    }

    lfb_flush();
}
