/*
 *  font.h -- `Soft' font definitions
 *
 *  Created 1995 by Geert Uytterhoeven
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef _XEN_FONT_H
#define _XEN_FONT_H

struct font_desc {
    const char *name;
    unsigned width, height, count;
    const void *data;
};

extern const struct font_desc font_vga_8x8, font_vga_8x14, font_vga_8x16;

#endif /* _XEN_FONT_H */
