/*
 * xen/drivers/video/lfb.h
 *
 * Cross-platform framebuffer library
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

#ifndef _XEN_LFB_H
#define _XEN_LFB_H

#include <xen/init.h>

struct lfb_prop {
    const struct font_desc *font;
    unsigned char *lfb;
    unsigned int pixel_on;
    uint16_t width, height;
    uint16_t bytes_per_line;
    uint16_t bits_per_pixel;
    void (*flush)(void);

    unsigned int text_columns;
    unsigned int text_rows;
};

void lfb_redraw_puts(const char *s, size_t nr);
void lfb_scroll_puts(const char *s, size_t nr);
void lfb_carriage_return(void);
void lfb_free(void);

/* initialize the framebuffer */
int lfb_init(struct lfb_prop *lfbp);

#endif
