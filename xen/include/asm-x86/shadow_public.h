/******************************************************************************
 * include/asm-x86/shadow_public.h
 * 
 * Copyright (c) 2005 Michael A Fetterman
 * Based on an earlier implementation by Ian Pratt et al
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

#ifndef _XEN_SHADOW_PUBLIC_H
#define _XEN_SHADOW_PUBLIC_H
#if CONFIG_PAGING_LEVELS >= 3
#define MFN_PINNED(_x) (mfn_to_page(_x)->u.inuse.type_info & PGT_pinned)

extern int alloc_p2m_table(struct domain *d);

extern void shadow_sync_and_drop_references(
      struct domain *d, struct page_info *page);
extern void shadow_drop_references(
      struct domain *d, struct page_info *page);

extern int shadow_set_guest_paging_levels(struct domain *d, int levels);

extern void release_out_of_sync_entry(
    struct domain *d, struct out_of_sync_entry *entry);

struct shadow_ops {
    unsigned long guest_paging_levels; /* guest paging levels */
    void (*invlpg)(struct vcpu *v, unsigned long va);
    int  (*fault)(unsigned long va, struct cpu_user_regs *regs);
    void (*update_pagetables)(struct vcpu *v);
    void (*sync_all)(struct domain *d);
    int  (*remove_all_write_access)(struct domain *d,
             unsigned long readonly_gpfn, unsigned long readonly_gmfn);
    int  (*do_update_va_mapping)(unsigned long va, l1_pgentry_t val, struct vcpu *v);
    struct out_of_sync_entry *
         (*mark_mfn_out_of_sync)(struct vcpu *v, unsigned long gpfn,
                              unsigned long mfn);
    int  (*is_out_of_sync)(struct vcpu *v, unsigned long va);
    unsigned long (*gva_to_gpa)(unsigned long gva);
};
#endif

#if CONFIG_PAGING_LEVELS >= 4
extern void shadow_l4_normal_pt_update(struct domain *d,
                                       unsigned long pa, l4_pgentry_t l4e,
                                       struct domain_mmap_cache *cache);
#endif

#endif
