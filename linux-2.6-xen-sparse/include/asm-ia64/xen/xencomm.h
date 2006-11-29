/*
 * Copyright (C) 2006 Hollis Blanchard <hollisb@us.ibm.com>, IBM Corporation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef _LINUX_XENCOMM_H_
#define _LINUX_XENCOMM_H_

#include <xen/interface/xencomm.h>

#define XENCOMM_MINI_ADDRS 3
struct xencomm_mini {
	struct xencomm_desc _desc;
	uint64_t address[XENCOMM_MINI_ADDRS];
};

/* Must be called before any hypercall.  */
extern void xencomm_init (void);

/* To avoid additionnal virt to phys conversion, an opaque structure is
   presented.  */
struct xencomm_handle;

extern int xencomm_create(void *buffer, unsigned long bytes,
                          struct xencomm_handle **desc, gfp_t type);
extern void xencomm_free(struct xencomm_handle *desc);

extern int xencomm_create_mini(struct xencomm_mini *area, int *nbr_area,
                               void *buffer, unsigned long bytes,
                               struct xencomm_handle **ret);

/* Translate virtual address to physical address.  */
extern unsigned long xencomm_vaddr_to_paddr(unsigned long vaddr);

/* Inline version.  To be used only on linear space (kernel space).  */
static inline struct xencomm_handle *
xencomm_create_inline(void *buffer)
{
	unsigned long paddr;

	paddr = xencomm_vaddr_to_paddr((unsigned long)buffer);
	return (struct xencomm_handle *)(paddr | XENCOMM_INLINE_FLAG);
}

#define xen_guest_handle(hnd)  ((hnd).p)

#endif /* _LINUX_XENCOMM_H_ */
