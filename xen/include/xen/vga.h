/*
 *  vga.h
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef _XEN_VGA_H
#define _XEN_VGA_H

#include <xen/video.h>

#ifdef CONFIG_VGA
extern struct xen_vga_console_info vga_console_info;
int fill_console_start_info(struct dom0_vga_console_info *ci);
void vesa_init(void);
void vesa_early_init(void);
void vesa_endboot(bool keep);
#else
static inline void vesa_init(void) {}
#endif

#endif /* _XEN_VGA_H */
