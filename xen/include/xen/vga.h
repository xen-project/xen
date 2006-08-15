/*
 *  vga.h
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef _XEN_VGA_H
#define _XEN_VGA_H

struct font_desc;

int detect_vga(void);
void *setup_vga(void);
void vga_cursor_off(void);
int vga_load_font(const struct font_desc *, unsigned rows);

#endif /* _XEN_VGA_H */
