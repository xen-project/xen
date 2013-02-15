/******************************************************************************
 * lfb.c
 *
 * linear frame buffer handling.
 */

#include <xen/config.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include "lfb.h"
#include "font.h"

#define MAX_XRES 1900
#define MAX_YRES 1200
#define MAX_BPP 4
#define MAX_FONT_W 8
#define MAX_FONT_H 16

struct lfb_status {
    struct lfb_prop lfbp;

    unsigned char *lbuf, *text_buf;
    unsigned int *line_len;
    unsigned int xpos, ypos;
};
static struct lfb_status lfb;

static void lfb_show_line(
    const unsigned char *text_line,
    unsigned char *video_line,
    unsigned int nr_chars,
    unsigned int nr_cells)
{
    unsigned int i, j, b, bpp, pixel;

    bpp = (lfb.lfbp.bits_per_pixel + 7) >> 3;

    for ( i = 0; i < lfb.lfbp.font->height; i++ )
    {
        unsigned char *ptr = lfb.lbuf;

        for ( j = 0; j < nr_chars; j++ )
        {
            const unsigned char *bits = lfb.lfbp.font->data;
            bits += ((text_line[j] * lfb.lfbp.font->height + i) *
                     ((lfb.lfbp.font->width + 7) >> 3));
            for ( b = lfb.lfbp.font->width; b--; )
            {
                pixel = (*bits & (1u<<b)) ? lfb.lfbp.pixel_on : 0;
                memcpy(ptr, &pixel, bpp);
                ptr += bpp;
            }
        }

        memset(ptr, 0, (lfb.lfbp.width - nr_chars * lfb.lfbp.font->width) * bpp);
        memcpy(video_line, lfb.lbuf, nr_cells * lfb.lfbp.font->width * bpp);
        video_line += lfb.lfbp.bytes_per_line;
    }
}

/* Fast mode which redraws all modified parts of a 2D text buffer. */
void lfb_redraw_puts(const char *s)
{
    unsigned int i, min_redraw_y = lfb.ypos;
    char c;

    /* Paste characters into text buffer. */
    while ( (c = *s++) != '\0' )
    {
        if ( (c == '\n') || (lfb.xpos >= lfb.lfbp.text_columns) )
        {
            if ( ++lfb.ypos >= lfb.lfbp.text_rows )
            {
                min_redraw_y = 0;
                lfb.ypos = lfb.lfbp.text_rows - 1;
                memmove(lfb.text_buf, lfb.text_buf + lfb.lfbp.text_columns,
                        lfb.ypos * lfb.lfbp.text_columns);
                memset(lfb.text_buf + lfb.ypos * lfb.lfbp.text_columns, 0, lfb.xpos);
            }
            lfb.xpos = 0;
        }

        if ( c != '\n' )
            lfb.text_buf[lfb.xpos++ + lfb.ypos * lfb.lfbp.text_columns] = c;
    }

    /* Render modified section of text buffer to VESA linear framebuffer. */
    for ( i = min_redraw_y; i <= lfb.ypos; i++ )
    {
        const unsigned char *line = lfb.text_buf + i * lfb.lfbp.text_columns;
        unsigned int width;

        for ( width = lfb.lfbp.text_columns; width; --width )
            if ( line[width - 1] )
                 break;
        lfb_show_line(line,
                       lfb.lfbp.lfb + i * lfb.lfbp.font->height * lfb.lfbp.bytes_per_line,
                       width, max(lfb.line_len[i], width));
        lfb.line_len[i] = width;
    }

    lfb.lfbp.flush();
}

/* Slower line-based scroll mode which interacts better with dom0. */
void lfb_scroll_puts(const char *s)
{
    unsigned int i;
    char c;

    while ( (c = *s++) != '\0' )
    {
        if ( (c == '\n') || (lfb.xpos >= lfb.lfbp.text_columns) )
        {
            unsigned int bytes = (lfb.lfbp.width *
                                  ((lfb.lfbp.bits_per_pixel + 7) >> 3));
            unsigned char *src = lfb.lfbp.lfb + lfb.lfbp.font->height * lfb.lfbp.bytes_per_line;
            unsigned char *dst = lfb.lfbp.lfb;

            /* New line: scroll all previous rows up one line. */
            for ( i = lfb.lfbp.font->height; i < lfb.lfbp.height; i++ )
            {
                memcpy(dst, src, bytes);
                src += lfb.lfbp.bytes_per_line;
                dst += lfb.lfbp.bytes_per_line;
            }

            /* Render new line. */
            lfb_show_line(
                lfb.text_buf,
                lfb.lfbp.lfb + (lfb.lfbp.text_rows-1) * lfb.lfbp.font->height *
                lfb.lfbp.bytes_per_line,
                lfb.xpos, lfb.lfbp.text_columns);

            lfb.xpos = 0;
        }

        if ( c != '\n' )
            lfb.text_buf[lfb.xpos++] = c;
    }

    lfb.lfbp.flush();
}

void lfb_carriage_return(void)
{
    lfb.xpos = 0;
}

int __init lfb_init(struct lfb_prop *lfbp)
{
    if ( lfbp->width > MAX_XRES || lfbp->height > MAX_YRES )
    {
        printk(XENLOG_WARNING "Couldn't initialize a %ux%u framebuffer early.\n",
               lfbp->width, lfbp->height);
        return -EINVAL;
    }

    lfb.lfbp = *lfbp;

    lfb.lbuf = xmalloc_bytes(lfb.lfbp.bytes_per_line);
    lfb.text_buf = xzalloc_bytes(lfb.lfbp.text_columns * lfb.lfbp.text_rows);
    lfb.line_len = xzalloc_array(unsigned int, lfb.lfbp.text_columns);

    if ( !lfb.lbuf || !lfb.text_buf || !lfb.line_len )
        goto fail;

    return 0;

fail:
    printk(XENLOG_ERR "Couldn't allocate enough memory to drive the framebuffer\n");
    lfb_free();

    return -ENOMEM;
}

void lfb_free(void)
{
    xfree(lfb.lbuf);
    xfree(lfb.text_buf);
    xfree(lfb.line_len);
}
