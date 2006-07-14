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

#ifndef _XEN_XENCOMM_H_
#define _XEN_XENCOMM_H_

/* A xencomm descriptor is a scatter/gather list containing physical
 * addresses corresponding to a virtually contiguous memory area. The
 * hypervisor translates these physical addresses to machine addresses to copy
 * to and from the virtually contiguous area.
 */

#define XENCOMM_MAGIC 0x58434F4D /* 'XCOM' */
#define XENCOMM_INVALID (~0UL)

struct xencomm_desc {
    uint32_t magic;
    uint32_t nr_addrs; /* the number of entries in address[] */
    uint64_t address[0];
};

#endif /* _XEN_XENCOMM_H_ */
