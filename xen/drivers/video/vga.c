/******************************************************************************
 * vga.c
 * 
 * VGA support routines.
 */

#include <xen/config.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/console.h>
#include <xen/vga.h>
#include <asm/io.h>
#include "font.h"

/* Filled in by arch boot code. */
struct xen_vga_console_info vga_console_info;

static int vgacon_enabled = 0;
static int vgacon_keep    = 0;
/*static const struct font_desc *font;*/

static int xpos, ypos;
static unsigned char *video;

/*
 * 'vga=<mode-specifier>[,keep]' where <mode-specifier> is one of:
 * 
 *   'vga=ask':
 *      display a vga menu of available modes
 * 
 *   'vga=text-80x<rows>':
 *      text mode, where <rows> is one of {25,28,30,34,43,50,60}
 * 
 *   'vga=gfx-<width>x<height>x<depth>':
 *      graphics mode, e.g., vga=gfx-1024x768x16
 * 
 *   'vga=mode-<mode>:
 *      specifies a mode as specified in 'vga=ask' menu
 *      (NB. menu modes are displayed in hex, so mode numbers here must
 *           be prefixed with '0x' (e.g., 'vga=mode-0x0318'))
 * 
 * The option 'keep' causes Xen to continue to print to the VGA console even 
 * after domain 0 starts to boot. The default behaviour is to relinquish
 * control of the console to domain 0.
 */
static char opt_vga[30] = "";
string_param("vga", opt_vga);

/* VGA text-mode definitions. */
#define COLUMNS vga_console_info.u.text_mode_3.columns
#define LINES   vga_console_info.u.text_mode_3.rows
#define ATTRIBUTE   7
#define VIDEO_SIZE  (COLUMNS * LINES * 2)

void __init vga_init(void)
{
    char *p;

    /* Look for 'keep' in comma-separated options. */
    for ( p = opt_vga; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( strncmp(p, "keep", 4) == 0 )
            vgacon_keep = 1;
    }

    switch ( vga_console_info.video_type )
    {
    case XEN_VGATYPE_TEXT_MODE_3:
        if ( memory_is_conventional_ram(0xB8000) )
            return;
        video = ioremap(0xB8000, 0x8000);
        if ( video == NULL )
            return;
        /* Disable cursor. */
        outw(0x200a, 0x3d4);
        memset(video, 0, VIDEO_SIZE);
        break;
    case XEN_VGATYPE_VESA_LFB:
#if 0
        /* XXX Implement me! */
        video = ioremap(vga_console_info.u.vesa_lfb.lfb_base,
                        vga_console_info.u.vesa_lfb.lfb_size);
        if ( video == NULL )
            return;
        memset(video, 0, vga_console_info.u.vesa_lfb.lfb_size);
        break;
#else
        return;
#endif
    default:
        memset(&vga_console_info, 0, sizeof(vga_console_info));
        return;
    }

    vgacon_enabled = 1;
}

void __init vga_endboot(void)
{
    if ( !vgacon_enabled )
        return;

    printk("Xen is %s VGA console.\n",
           vgacon_keep ? "keeping" : "relinquishing");

    vgacon_enabled = vgacon_keep;
}


static void put_newline(void)
{
    xpos = 0;
    ypos++;

    if ( ypos >= LINES )
    {
        ypos = LINES-1;
        memmove((char*)video, 
                (char*)video + 2*COLUMNS, (LINES-1)*2*COLUMNS);
        memset((char*)video + (LINES-1)*2*COLUMNS, 0, 2*COLUMNS);
    }
}

void vga_putchar(int c)
{
    if ( !vgacon_enabled )
        return;

    if ( c == '\n' )
    {
        put_newline();
    }
    else
    {
        if ( xpos >= COLUMNS )
            put_newline();
        video[(xpos + ypos * COLUMNS) * 2]     = c & 0xFF;
        video[(xpos + ypos * COLUMNS) * 2 + 1] = ATTRIBUTE;
        ++xpos;
    }
}

int __init fill_console_start_info(struct dom0_vga_console_info *ci)
{
    memcpy(ci, &vga_console_info, sizeof(*ci));
    return 1;
}
