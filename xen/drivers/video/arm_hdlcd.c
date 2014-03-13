/*
 * xen/drivers/video/arm_hdlcd.c
 *
 * Driver for ARM HDLCD Controller
 *
 * Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 * Copyright (c) 2013 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/delay.h>
#include <asm/types.h>
#include <asm/platforms/vexpress.h>
#include <xen/config.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/init.h>
#include <xen/mm.h>
#include "font.h"
#include "lfb.h"
#include "modelines.h"

#define HDLCD ((volatile uint32_t *) FIXMAP_ADDR(FIXMAP_MISC))

#define HDLCD_INTMASK       (0x18/4)
#define HDLCD_FBBASE        (0x100/4)
#define HDLCD_LINELENGTH    (0x104/4)
#define HDLCD_LINECOUNT     (0x108/4)
#define HDLCD_LINEPITCH     (0x10C/4)
#define HDLCD_BUS           (0x110/4)
#define HDLCD_VSYNC         (0x200/4)
#define HDLCD_VBACK         (0x204/4)
#define HDLCD_VDATA         (0x208/4)
#define HDLCD_VFRONT        (0x20C/4)
#define HDLCD_HSYNC         (0x210/4)
#define HDLCD_HBACK         (0x214/4)
#define HDLCD_HDATA         (0x218/4)
#define HDLCD_HFRONT        (0x21C/4)
#define HDLCD_POLARITIES    (0x220/4)
#define HDLCD_COMMAND       (0x230/4)
#define HDLCD_PF            (0x240/4)
#define HDLCD_RED           (0x244/4)
#define HDLCD_GREEN         (0x248/4)
#define HDLCD_BLUE          (0x24C/4)

struct color_masks {
    int red_shift;
    int red_size;
    int green_shift;
    int green_size;
    int blue_shift;
    int blue_size;
};

struct pixel_colors {
    const char* bpp;
    struct color_masks colors;
};

struct pixel_colors __initdata colors[] = {
    { "16", { 0, 5, 11, 5, 6, 5 } },
    { "24", { 0, 8, 16, 8, 8, 8 } },
    { "32", { 0, 8, 16, 8, 8, 8 } },
};

static void vga_noop_puts(const char *s) {}
void (*video_puts)(const char *) = vga_noop_puts;

static void hdlcd_flush(void)
{
    dsb(sy);
}

static int __init get_color_masks(const char* bpp, struct color_masks **masks)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(colors); i++ )
    {
        if ( !strncmp(colors[i].bpp, bpp, 2) )
        {
            *masks = &colors[i].colors;
            return 0;
        }
    }
    return -1;
}

static void __init set_pixclock(uint32_t pixclock)
{
    if ( dt_find_compatible_node(NULL, NULL, "arm,vexpress") )
            vexpress_syscfg(1, V2M_SYS_CFG_OSC_FUNC,
                            V2M_SYS_CFG_OSC5, &pixclock);
}

void __init video_init(void)
{
    struct lfb_prop lfbp;
    unsigned char *lfb;
    paddr_t hdlcd_start, hdlcd_size;
    paddr_t framebuffer_start, framebuffer_size;
    const char *mode_string;
    char _mode_string[16];
    int bytes_per_pixel = 4;
    struct color_masks *c = NULL;
    struct modeline *videomode = NULL;
    int i;
    const struct dt_device_node *dev;
    const __be32 *cells;
    u32 lenp;
    int res;

    dev = dt_find_compatible_node(NULL, NULL, "arm,hdlcd");

    if ( !dev )
    {
        printk("HDLCD: Cannot find node compatible with \"arm,hdcld\"\n");
        return;
    }

    res = dt_device_get_address(dev, 0, &hdlcd_start, &hdlcd_size);
    if ( !res )
    {
        printk("HDLCD: Unable to retrieve MMIO base address\n");
        return;
    }

    cells = dt_get_property(dev, "framebuffer", &lenp);
    if ( !cells )
    {
        printk("HDLCD: Unable to retrieve framebuffer property\n");
        return;
    }

    framebuffer_start = dt_next_cell(dt_n_addr_cells(dev), &cells);
    framebuffer_size = dt_next_cell(dt_n_size_cells(dev), &cells);

    if ( !hdlcd_start )
    {
        printk(KERN_ERR "HDLCD: address missing from device tree, disabling driver\n");
        return;
    }

    if ( !framebuffer_start )
    {
        printk(KERN_ERR "HDLCD: framebuffer address missing from device tree, disabling driver\n");
        return;
    }

    res = dt_property_read_string(dev, "mode", &mode_string);
    if ( res )
    {
        get_color_masks("32", &c);
        memcpy(_mode_string, "1280x1024@60", strlen("1280x1024@60") + 1);
        bytes_per_pixel = 4;
    }
    else if ( strlen(mode_string) < strlen("800x600@60") ||
            strlen(mode_string) > sizeof(_mode_string) - 1 )
    {
        printk(KERN_ERR "HDLCD: invalid modeline=%s\n", mode_string);
        return;
    } else {
        char *s = strchr(mode_string, '-');
        if ( !s )
        {
            printk(KERN_INFO "HDLCD: bpp not found in modeline %s, assume 32 bpp\n",
                         mode_string);
            get_color_masks("32", &c);
            memcpy(_mode_string, mode_string, strlen(mode_string) + 1);
            bytes_per_pixel = 4;
        } else {
            if ( strlen(s) < 6 )
            {
                printk(KERN_ERR "HDLCD: invalid mode %s\n", mode_string);
                return;
            }
            s++;
            if ( get_color_masks(s, &c) < 0 )
            {
                printk(KERN_WARNING "HDLCD: unsupported bpp %s\n", s);
                return;
            }
            bytes_per_pixel = simple_strtoll(s, NULL, 10) / 8;
        }
        i = s - mode_string - 1;
        memcpy(_mode_string, mode_string, i);
        memcpy(_mode_string + i, mode_string + i + 3, 4);
    }

    for ( i = 0; i < ARRAY_SIZE(videomodes); i++ ) {
        if ( !strcmp(_mode_string, videomodes[i].mode) )
        {
            videomode = &videomodes[i];
            break;
        }
    }
    if ( !videomode )
    {
        printk(KERN_WARNING "HDLCD: unsupported videomode %s\n",
               _mode_string);
        return;
    }

    if ( framebuffer_size < bytes_per_pixel * videomode->xres * videomode->yres )
    {
        printk(KERN_ERR "HDLCD: the framebuffer is too small, disabling the HDLCD driver\n");
        return;
    }

    printk(KERN_INFO "Initializing HDLCD driver\n");

    lfb = ioremap_wc(framebuffer_start, framebuffer_size);
    if ( !lfb )
    {
        printk(KERN_ERR "Couldn't map the framebuffer\n");
        return;
    }
    memset(lfb, 0x00, bytes_per_pixel * videomode->xres * videomode->yres);

    /* uses FIXMAP_MISC */
    set_pixclock(videomode->pixclock);

    set_fixmap(FIXMAP_MISC, hdlcd_start >> PAGE_SHIFT, DEV_SHARED);
    HDLCD[HDLCD_COMMAND] = 0;

    HDLCD[HDLCD_LINELENGTH] = videomode->xres * bytes_per_pixel;
    HDLCD[HDLCD_LINECOUNT] = videomode->yres - 1;
    HDLCD[HDLCD_LINEPITCH] = videomode->xres * bytes_per_pixel;
    HDLCD[HDLCD_PF] = ((bytes_per_pixel - 1) << 3);
    HDLCD[HDLCD_INTMASK] = 0;
    HDLCD[HDLCD_FBBASE] = framebuffer_start;
    HDLCD[HDLCD_BUS] = 0xf00 | (1 << 4);
    HDLCD[HDLCD_VBACK] = videomode->vback - 1;
    HDLCD[HDLCD_VSYNC] = videomode->vsync - 1;
    HDLCD[HDLCD_VDATA] = videomode->yres - 1;
    HDLCD[HDLCD_VFRONT] = videomode->vfront - 1;
    HDLCD[HDLCD_HBACK] = videomode->hback - 1;
    HDLCD[HDLCD_HSYNC] = videomode->hsync - 1;
    HDLCD[HDLCD_HDATA] = videomode->xres - 1;
    HDLCD[HDLCD_HFRONT] = videomode->hfront - 1;
    HDLCD[HDLCD_POLARITIES] = (1 << 2) | (1 << 3);
    HDLCD[HDLCD_RED] = (c->red_size << 8) | c->red_shift;
    HDLCD[HDLCD_GREEN] = (c->green_size << 8) | c->green_shift;
    HDLCD[HDLCD_BLUE] = (c->blue_size << 8) | c->blue_shift;
    HDLCD[HDLCD_COMMAND] = 1;
    clear_fixmap(FIXMAP_MISC);

    lfbp.pixel_on = (((1 << c->red_size) - 1) << c->red_shift) |
        (((1 << c->green_size) - 1) << c->green_shift) |
        (((1 << c->blue_size) - 1) << c->blue_shift);
    lfbp.lfb = lfb;
    lfbp.font = &font_vga_8x16;
    lfbp.bits_per_pixel = bytes_per_pixel*8;
    lfbp.bytes_per_line = bytes_per_pixel*videomode->xres;
    lfbp.width = videomode->xres;
    lfbp.height = videomode->yres;
    lfbp.flush = hdlcd_flush;
    lfbp.text_columns = videomode->xres / 8;
    lfbp.text_rows = videomode->yres / 16;
    if ( lfb_init(&lfbp) < 0 )
            return;
    video_puts = lfb_scroll_puts;
}

void __init video_endboot(void) { }

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
