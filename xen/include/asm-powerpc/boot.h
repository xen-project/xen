/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_BOOT_H
#define _ASM_BOOT_H

/* a collection of interfaces used during boot. */

extern void boot_of_init(ulong, ulong);
extern void *boot_of_devtree(void);
extern void boot_of_serial(void *);
extern void boot_of_finish(void);
extern int boot_of_mem_avail(int pos, ulong *startpage, ulong *endpage);

extern void parse_multiboot(ulong tags_addr);

extern void memory_init(void);

extern char *xen_cmdline;
extern ulong dom0_addr;
extern ulong dom0_len;
extern char *dom0_cmdline;
extern ulong initrd_start;
extern ulong initrd_len;

/* From linker script. */
extern char builtin_cmdline[];

#endif
