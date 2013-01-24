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
#endif

#endif /* _XEN_VGA_H */
