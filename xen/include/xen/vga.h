/*
 *  vga.h
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef _XEN_VGA_H
#define _XEN_VGA_H

#include <xen/config.h>

#ifdef CONFIG_VGA
void vga_init(void);
void vga_endboot(void);
void vga_putchar(int c);
#else
#define vga_init()     ((void)0)
#define vga_endboot()  ((void)0)
#define vga_putchar(c) ((void)0)
#endif

#endif /* _XEN_VGA_H */
