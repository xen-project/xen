/******************************************************************************
 * memory.c
 * 
 * Copyright (c) 2002-2004 K A Fraser
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
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>

/* Frame table and its size in pages. */
struct pfn_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;

void __init init_frametable(void *frametable_vstart, unsigned long nr_pages)
{
    max_page = nr_pages;
    frame_table_size = nr_pages * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;
    frame_table = frametable_vstart;

    if ( (__pa(frame_table) + frame_table_size) > (max_page << PAGE_SHIFT) )
        panic("Not enough memory for frame table - reduce Xen heap size?\n");

    memset(frame_table, 0, frame_table_size);
}
