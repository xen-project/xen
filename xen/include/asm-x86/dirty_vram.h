/****************************************************************************
 * include/asm-x86/dirty_vram.h
 *
 * Interface for tracking dirty VRAM pages
 *
 * Copyright (c) 2012 Citrix Systems, Inc. (Robert Phillips)
 * Parts of this code are Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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

#ifndef _DIRTY_VRAM_H
#define _DIRTY_VRAM_H

/*
 * In shadow mode we need to bookkeep all the L1 page table entries that
 * map a frame buffer page.  Struct dv_paddr_link does this by
 * recording the address of a L1 page table entry for some frame buffer page.
 * Also has a link to additional pl entries if the frame buffer page
 * has multiple mappings.
 * In practice very few pages have multiple mappings.
 * But to rule out some pathological situation, we limit the number of
 * mappings we're willing to bookkeep.
 */

#define DV_ADDR_LINK_LIST_LIMIT 64

typedef struct dv_paddr_link {
    paddr_t sl1ma;
    struct dv_paddr_link *pl_next;
} dv_paddr_link_t;

typedef struct dv_pl_entry {
    dv_paddr_link_t mapping;
    bool_t stuck_dirty;
} dv_pl_entry_t;

/*
 * This defines an extension page of pl entries for FB pages with multiple
 * mappings. All such pages (of a domain) are linked together.
 */
typedef struct dv_paddr_link_ext {
    struct list_head ext_link;
    dv_paddr_link_t entries[ ( PAGE_SIZE - sizeof( struct list_head ) ) /
                             sizeof( dv_paddr_link_t ) ];
} dv_paddr_link_ext_t;

/*
 * This defines a single frame buffer range.  It bookkeeps all the
 * level 1 PTEs that map guest pages within that range.
 * All such ranges (of a domain) are linked together.
 */
typedef struct dv_range {
    struct list_head range_link; /* the several ranges form a linked list */
    unsigned long begin_pfn;
    unsigned long end_pfn;
    dv_pl_entry_t *pl_tab; /* table has 1 pl entry per pfn in range */
    int nr_mappings;  /* total number of mappings in this range */
    int mappings_hwm; /* high water mark of max mapping count */
    unsigned int dirty_count;
} dv_range_t;

/*
 * This contains all the data structures required by a domain to
 * bookkeep the dirty pages within its frame buffers.
 */
typedef struct dv_dirty_vram {
    struct list_head range_head; /* head of the linked list of ranges */
    struct list_head ext_head; /* head of list of extension pages */
    dv_paddr_link_t *pl_free; /* free list of pl's within extension pages */
    int nr_ranges; /* bookkeeps number of ranges */
    int ranges_hwm; /* high water mark of max number of ranges */
} dv_dirty_vram_t;

/* Allocates domain's dirty_vram structure */
dv_dirty_vram_t *
dirty_vram_alloc(struct domain *d);

/*
 * Returns domain's dirty_vram structure,
 * allocating it if necessary
 */
dv_dirty_vram_t *
dirty_vram_find_or_alloc(struct domain *d);

/* Frees domain's dirty_vram structure */
void dirty_vram_free(struct domain *d);

/* Returns dirty vram range containing gfn, NULL if none */
struct dv_range *
dirty_vram_range_find_gfn(struct domain *d,
                          unsigned long gfn);

/*
 * Returns dirty vram range matching [ begin_pfn .. begin_pfn+nr ),
 * NULL if none
 */
dv_range_t *
dirty_vram_range_find(struct domain *d,
                      unsigned long begin_pfn,
                      unsigned long nr);

/*
 * Allocate dirty vram range containing [ begin_pfn .. begin_pfn+nr ),
 * freeing any existing range that overlaps the new range.
 */
dv_range_t *
dirty_vram_range_alloc(struct domain *d,
                       unsigned long begin_pfn,
                       unsigned long nr);

/*
 * Returns dirty vram range matching [ begin_pfn .. begin_pfn+nr ),
 * creating a range if none already exists and
 * freeing any existing range that overlaps the new range.
 */
dv_range_t *
dirty_vram_range_find_or_alloc(struct domain *d,
                               unsigned long begin_pfn,
                               unsigned long nr);

void dirty_vram_range_free(struct domain *d,
                           dv_range_t *range);

/* Bookkeep PTE address of a frame buffer page */
int dirty_vram_range_update(struct domain *d,
                            unsigned long gfn,
                            paddr_t sl1ma,
                            int set);

/*
 * smfn is no longer a shadow page.  Remove it from any
 * dirty vram range mapping.
 */
void
dirty_vram_delete_shadow(struct vcpu *v,
                         unsigned long gfn,
                         unsigned int shadow_type,
                         mfn_t smfn);


/*
 * Scan all the L1 tables looking for VRAM mappings.
 * Record them in the domain's dv_dirty_vram structure
 */
void sh_find_all_vram_mappings(struct vcpu *v,
                               dv_range_t *range);

/*
 * Free a paddr_link struct, given address of its
 * predecessor in singly-linked list
 */
dv_paddr_link_t *
free_paddr_link(struct domain *d,
                dv_paddr_link_t **ppl,
                dv_paddr_link_t *pl);


/* Enable VRAM dirty tracking. */
int
shadow_track_dirty_vram(struct domain *d,
                        unsigned long first_pfn,
                        unsigned long nr,
                        XEN_GUEST_HANDLE_64(uint8) dirty_bitmap);

int
hap_track_dirty_vram(struct domain *d,
                     unsigned long begin_pfn,
                     unsigned long nr,
                     XEN_GUEST_HANDLE_64(uint8) dirty_bitmap);

void
hap_clean_vram_tracking_range(struct domain *d,
                              unsigned long begin_pfn,
                              unsigned long nr,
                              uint8_t *dirty_bitmap);

#endif /* _DIRTY_VRAM_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
