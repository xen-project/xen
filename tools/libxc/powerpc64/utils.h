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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright IBM Corporation 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */

extern int get_rma_page_array(int xc_handle, int domid, xen_pfn_t **page_array,
			      unsigned long nr_pages);
extern int install_image(int xc_handle, int domid, xen_pfn_t *page_array,
			 void *image, unsigned long paddr, unsigned long size);
extern void *load_file(const char *path, unsigned long *filesize);
extern int load_elf_kernel(int xc_handle, int domid,  const char *kernel_path,
			   struct domain_setup_info *dsi,
			   xen_pfn_t *page_array);

#define ALIGN_UP(addr,size) (((addr)+((size)-1))&(~((size)-1)))

#define max(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x > _y ? _x : _y; })
