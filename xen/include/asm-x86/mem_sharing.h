/******************************************************************************
 * include/asm-x86/mem_sharing.h
 *
 * Memory sharing support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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
#ifndef __MEM_SHARING_H__
#define __MEM_SHARING_H__

#ifdef __x86_64__

#define sharing_supported(_d) \
    (is_hvm_domain(_d) && paging_mode_hap(_d)) 

typedef uint64_t shr_handle_t; 

unsigned int mem_sharing_get_nr_saved_mfns(void);
int mem_sharing_nominate_page(struct domain *d, 
                              unsigned long gfn,
                              int expected_refcnt,
                              shr_handle_t *phandle);
#define MEM_SHARING_MUST_SUCCEED      (1<<0)
#define MEM_SHARING_DESTROY_GFN       (1<<1)
int mem_sharing_unshare_page(struct domain *d, 
                             unsigned long gfn, 
                             uint16_t flags);
int mem_sharing_sharing_resume(struct domain *d);
int mem_sharing_cache_resize(struct domain *d, int new_size);
int mem_sharing_domctl(struct domain *d, 
                       xen_domctl_mem_sharing_op_t *mec);
void mem_sharing_init(void);

#else 

#define mem_sharing_init()  do { } while (0)

#endif /* __x86_64__ */

#endif /* __MEM_SHARING_H__ */
