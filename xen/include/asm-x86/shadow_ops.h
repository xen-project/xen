/******************************************************************************
 * include/asm-x86/shadow_ops.h
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

#ifndef _XEN_SHADOW_OPS_H
#define _XEN_SHADOW_OPS_H

#define PAGING_L4      4UL
#define PAGING_L3      3UL
#define PAGING_L2      2UL
#define PAGING_L1      1UL

#define PAE_CR3_ALIGN       5
#define PAE_CR3_IDX_MASK    0x7f

#if defined( GUEST_PGENTRY_32 )

#define GUEST_L1_PAGETABLE_ENTRIES     L1_PAGETABLE_ENTRIES_32
#define GUEST_L2_PAGETABLE_ENTRIES     L2_PAGETABLE_ENTRIES_32
#define GUEST_ROOT_PAGETABLE_ENTRIES   ROOT_PAGETABLE_ENTRIES_32
#define GUEST_L2_PAGETABLE_SHIFT       L2_PAGETABLE_SHIFT_32

#define guest_l1_pgentry_t      l1_pgentry_32_t
#define guest_l2_pgentry_t      l2_pgentry_32_t
#define guest_root_pgentry_t    l2_pgentry_32_t

#define guest_l1e_get_paddr     l1e_get_paddr_32
#define guest_l2e_get_paddr     l2e_get_paddr_32

#define guest_get_pte_flags     get_pte_flags_32
#define guest_put_pte_flags     put_pte_flags_32

#define guest_l1e_get_flags     l1e_get_flags_32
#define guest_l2e_get_flags     l2e_get_flags_32
#define guest_root_get_flags          l2e_get_flags_32
#define guest_root_get_intpte         l2e_get_intpte

#define guest_l1e_empty         l1e_empty_32
#define guest_l2e_empty         l2e_empty_32

#define guest_l1e_from_pfn      l1e_from_pfn_32
#define guest_l2e_from_pfn      l2e_from_pfn_32

#define guest_l1e_from_paddr    l1e_from_paddr_32
#define guest_l2e_from_paddr    l2e_from_paddr_32

#define guest_l1e_from_page     l1e_from_page_32
#define guest_l2e_from_page     l2e_from_page_32

#define guest_l1e_add_flags     l1e_add_flags_32
#define guest_l2e_add_flags     l2e_add_flags_32

#define guest_l1e_remove_flag   l1e_remove_flags_32
#define guest_l2e_remove_flag   l2e_remove_flags_32

#define guest_l1e_has_changed   l1e_has_changed_32
#define guest_l2e_has_changed   l2e_has_changed_32
#define root_entry_has_changed  l2e_has_changed_32

#define guest_l1_table_offset   l1_table_offset_32
#define guest_l2_table_offset   l2_table_offset_32

#define guest_linear_l1_table   linear_pg_table_32
#define guest_linear_l2_table   linear_l2_table_32

#define guest_va_to_l1mfn       va_to_l1mfn_32

#else

#define GUEST_L1_PAGETABLE_ENTRIES      L1_PAGETABLE_ENTRIES
#define GUEST_L2_PAGETABLE_ENTRIES      L2_PAGETABLE_ENTRIES
#define GUEST_ROOT_PAGETABLE_ENTRIES    ROOT_PAGETABLE_ENTRIES
#define GUEST_L2_PAGETABLE_SHIFT        L2_PAGETABLE_SHIFT

#define guest_l1_pgentry_t      l1_pgentry_t
#define guest_l2_pgentry_t      l2_pgentry_t
#define guest_root_pgentry_t    l4_pgentry_t

#define guest_l1e_get_paddr     l1e_get_paddr
#define guest_l2e_get_paddr     l2e_get_paddr

#define guest_get_pte_flags     get_pte_flags
#define guest_put_pte_flags     put_pte_flags

#define guest_l1e_get_flags     l1e_get_flags
#define guest_l2e_get_flags     l2e_get_flags
#define guest_root_get_flags    l4e_get_flags
#define guest_root_get_intpte   l4e_get_intpte

#define guest_l1e_empty         l1e_empty
#define guest_l2e_empty         l2e_empty

#define guest_l1e_from_pfn      l1e_from_pfn
#define guest_l2e_from_pfn      l2e_from_pfn

#define guest_l1e_from_paddr    l1e_from_paddr
#define guest_l2e_from_paddr    l2e_from_paddr

#define guest_l1e_from_page     l1e_from_page
#define guest_l2e_from_page     l2e_from_page

#define guest_l1e_add_flags     l1e_add_flags
#define guest_l2e_add_flags     l2e_add_flags

#define guest_l1e_remove_flag   l1e_remove_flags
#define guest_l2e_remove_flag   l2e_remove_flags

#define guest_l1e_has_changed   l1e_has_changed
#define guest_l2e_has_changed   l2e_has_changed
#define root_entry_has_changed  l4e_has_changed

#define guest_l1_table_offset   l1_table_offset
#define guest_l2_table_offset   l2_table_offset

#define guest_linear_l1_table   linear_pg_table
#define guest_linear_l2_table   linear_l2_table

#define guest_va_to_l1mfn       va_to_l1mfn
#endif

#endif /* _XEN_SHADOW_OPS_H */
