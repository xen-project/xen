/******************************************************************************
 * include/asm-x86/paging.h
 *
 * physical-to-machine mappings for automatically-translated domains.
 *
 * Copyright (c) 2011 GridCentric Inc. (Andres Lagar-Cavilla)
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
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

#ifndef _XEN_P2M_H
#define _XEN_P2M_H

#include <xen/config.h>
#include <xen/paging.h>
#include <asm/mem_sharing.h>
#include <asm/page.h>    /* for pagetable_t */

extern bool_t opt_hap_1gb, opt_hap_2mb;

/*
 * The phys_to_machine_mapping maps guest physical frame numbers 
 * to machine frame numbers.  It only exists for paging_mode_translate 
 * guests. It is organised in page-table format, which:
 *
 * (1) allows us to use it directly as the second pagetable in hardware-
 *     assisted paging and (hopefully) iommu support; and 
 * (2) lets us map it directly into the guest vcpus' virtual address space 
 *     as a linear pagetable, so we can read and write it easily.
 *
 * For (2) we steal the address space that would have normally been used
 * by the read-only MPT map in a non-translated guest.  (For 
 * paging_mode_external() guests this mapping is in the monitor table.)
 */
#define phys_to_machine_mapping ((l1_pgentry_t *)RO_MPT_VIRT_START)

/*
 * The upper levels of the p2m pagetable always contain full rights; all 
 * variation in the access control bits is made in the level-1 PTEs.
 * 
 * In addition to the phys-to-machine translation, each p2m PTE contains
 * *type* information about the gfn it translates, helping Xen to decide
 * on the correct course of action when handling a page-fault to that
 * guest frame.  We store the type in the "available" bits of the PTEs
 * in the table, which gives us 8 possible types on 32-bit systems.
 * Further expansions of the type system will only be supported on
 * 64-bit Xen.
 */

/*
 * AMD IOMMU: When we share p2m table with iommu, bit 52 -bit 58 in pte 
 * cannot be non-zero, otherwise, hardware generates io page faults when 
 * device access those pages. Therefore, p2m_ram_rw has to be defined as 0.
 */
typedef enum {
    p2m_ram_rw = 0,             /* Normal read/write guest RAM */
    p2m_invalid = 1,            /* Nothing mapped here */
    p2m_ram_logdirty = 2,       /* Temporarily read-only for log-dirty */
    p2m_ram_ro = 3,             /* Read-only; writes are silently dropped */
    p2m_mmio_dm = 4,            /* Reads and write go to the device model */
    p2m_mmio_direct = 5,        /* Read/write mapping of genuine MMIO area */
    p2m_populate_on_demand = 6, /* Place-holder for empty memory */

    /* Although these are defined in all builds, they can only
     * be used in 64-bit builds */
    p2m_grant_map_rw = 7,         /* Read/write grant mapping */
    p2m_grant_map_ro = 8,         /* Read-only grant mapping */
    p2m_ram_paging_out = 9,       /* Memory that is being paged out */
    p2m_ram_paged = 10,           /* Memory that has been paged out */
    p2m_ram_paging_in = 11,       /* Memory that is being paged in */
    p2m_ram_shared = 12,          /* Shared or sharable memory */
    p2m_ram_broken = 13,          /* Broken page, access cause domain crash */
} p2m_type_t;

/*
 * Additional access types, which are used to further restrict
 * the permissions given my the p2m_type_t memory type.  Violations
 * caused by p2m_access_t restrictions are sent to the mem_event
 * interface.
 *
 * The access permissions are soft state: when any ambigious change of page
 * type or use occurs, or when pages are flushed, swapped, or at any other
 * convenient type, the access permissions can get reset to the p2m_domain
 * default.
 */
typedef enum {
    p2m_access_n     = 0, /* No access permissions allowed */
    p2m_access_r     = 1,
    p2m_access_w     = 2, 
    p2m_access_rw    = 3,
    p2m_access_x     = 4, 
    p2m_access_rx    = 5,
    p2m_access_wx    = 6, 
    p2m_access_rwx   = 7,
    p2m_access_rx2rw = 8, /* Special: page goes from RX to RW on write */
    p2m_access_n2rwx = 9, /* Special: page goes from N to RWX on access, *
                           * generates an event but does not pause the
                           * vcpu */

    /* NOTE: Assumed to be only 4 bits right now */
} p2m_access_t;

/* Modifiers to the query */
typedef unsigned int p2m_query_t;
#define P2M_ALLOC    (1u<<0)   /* Populate PoD and paged-out entries */
#define P2M_UNSHARE  (1u<<1)   /* Break CoW sharing */

/* We use bitmaps and maks to handle groups of types */
#define p2m_to_mask(_t) (1UL << (_t))

/* RAM types, which map to real machine frames */
#define P2M_RAM_TYPES (p2m_to_mask(p2m_ram_rw)                \
                       | p2m_to_mask(p2m_ram_logdirty)        \
                       | p2m_to_mask(p2m_ram_ro)              \
                       | p2m_to_mask(p2m_ram_paging_out)      \
                       | p2m_to_mask(p2m_ram_paged)           \
                       | p2m_to_mask(p2m_ram_paging_in)       \
                       | p2m_to_mask(p2m_ram_shared))

/* Grant mapping types, which map to a real machine frame in another
 * VM */
#define P2M_GRANT_TYPES (p2m_to_mask(p2m_grant_map_rw)  \
                         | p2m_to_mask(p2m_grant_map_ro) )

/* MMIO types, which don't have to map to anything in the frametable */
#define P2M_MMIO_TYPES (p2m_to_mask(p2m_mmio_dm)        \
                        | p2m_to_mask(p2m_mmio_direct))

/* Read-only types, which must have the _PAGE_RW bit clear in their PTEs */
#define P2M_RO_TYPES (p2m_to_mask(p2m_ram_logdirty)     \
                      | p2m_to_mask(p2m_ram_ro)         \
                      | p2m_to_mask(p2m_grant_map_ro)   \
                      | p2m_to_mask(p2m_ram_shared) )

#define P2M_MAGIC_TYPES (p2m_to_mask(p2m_populate_on_demand))

/* Pageable types */
#define P2M_PAGEABLE_TYPES (p2m_to_mask(p2m_ram_rw) \
                            | p2m_to_mask(p2m_ram_logdirty) )

#define P2M_PAGING_TYPES (p2m_to_mask(p2m_ram_paging_out)        \
                          | p2m_to_mask(p2m_ram_paged)           \
                          | p2m_to_mask(p2m_ram_paging_in))

#define P2M_PAGED_TYPES (p2m_to_mask(p2m_ram_paged))

/* Shared types */
/* XXX: Sharable types could include p2m_ram_ro too, but we would need to
 * reinit the type correctly after fault */
#define P2M_SHARABLE_TYPES (p2m_to_mask(p2m_ram_rw) \
                            | p2m_to_mask(p2m_ram_logdirty) )
#define P2M_SHARED_TYPES   (p2m_to_mask(p2m_ram_shared))

/* Broken type: the frame backing this pfn has failed in hardware
 * and must not be touched. */
#define P2M_BROKEN_TYPES (p2m_to_mask(p2m_ram_broken))

/* Useful predicates */
#define p2m_is_ram(_t) (p2m_to_mask(_t) & P2M_RAM_TYPES)
#define p2m_is_mmio(_t) (p2m_to_mask(_t) & P2M_MMIO_TYPES)
#define p2m_is_readonly(_t) (p2m_to_mask(_t) & P2M_RO_TYPES)
#define p2m_is_magic(_t) (p2m_to_mask(_t) & P2M_MAGIC_TYPES)
#define p2m_is_grant(_t) (p2m_to_mask(_t) & P2M_GRANT_TYPES)
/* Grant types are *not* considered valid, because they can be
   unmapped at any time and, unless you happen to be the shadow or p2m
   implementations, there's no way of synchronising against that. */
#define p2m_is_valid(_t) (p2m_to_mask(_t) & (P2M_RAM_TYPES | P2M_MMIO_TYPES))
#define p2m_has_emt(_t)  (p2m_to_mask(_t) & (P2M_RAM_TYPES | p2m_to_mask(p2m_mmio_direct)))
#define p2m_is_pageable(_t) (p2m_to_mask(_t) & P2M_PAGEABLE_TYPES)
#define p2m_is_paging(_t)   (p2m_to_mask(_t) & P2M_PAGING_TYPES)
#define p2m_is_paged(_t)    (p2m_to_mask(_t) & P2M_PAGED_TYPES)
#define p2m_is_sharable(_t) (p2m_to_mask(_t) & P2M_SHARABLE_TYPES)
#define p2m_is_shared(_t)   (p2m_to_mask(_t) & P2M_SHARED_TYPES)
#define p2m_is_broken(_t)   (p2m_to_mask(_t) & P2M_BROKEN_TYPES)

/* Per-p2m-table state */
struct p2m_domain {
    /* Lock that protects updates to the p2m */
    mm_rwlock_t           lock;

    /* Shadow translated domain: p2m mapping */
    pagetable_t        phys_table;

    /* Same as domain_dirty_cpumask but limited to
     * this p2m and those physical cpus whose vcpu's are in
     * guestmode.
     */
    cpumask_var_t      dirty_cpumask;

    struct domain     *domain;   /* back pointer to domain */

    /* Nested p2ms only: nested-CR3 value that this p2m shadows. 
     * This can be cleared to CR3_EADDR under the per-p2m lock but
     * needs both the per-p2m lock and the per-domain nestedp2m lock
     * to set it to any other value. */
#define CR3_EADDR     (~0ULL)
    uint64_t           cr3;

    /* Nested p2ms: linked list of n2pms allocated to this domain. 
     * The host p2m hasolds the head of the list and the np2ms are 
     * threaded on in LRU order. */
    struct list_head np2m_list; 


    /* Host p2m: when this flag is set, don't flush all the nested-p2m 
     * tables on every host-p2m change.  The setter of this flag 
     * is responsible for performing the full flush before releasing the
     * host p2m's lock. */
    int                defer_nested_flush;

    /* Pages used to construct the p2m */
    struct page_list_head pages;

    int                (*set_entry   )(struct p2m_domain *p2m,
                                       unsigned long gfn,
                                       mfn_t mfn, unsigned int page_order,
                                       p2m_type_t p2mt,
                                       p2m_access_t p2ma);
    mfn_t              (*get_entry   )(struct p2m_domain *p2m,
                                       unsigned long gfn,
                                       p2m_type_t *p2mt,
                                       p2m_access_t *p2ma,
                                       p2m_query_t q,
                                       unsigned int *page_order);
    void               (*change_entry_type_global)(struct p2m_domain *p2m,
                                                   p2m_type_t ot,
                                                   p2m_type_t nt);
    
    void               (*write_p2m_entry)(struct p2m_domain *p2m,
                                          unsigned long gfn, l1_pgentry_t *p,
                                          mfn_t table_mfn, l1_pgentry_t new,
                                          unsigned int level);
    long               (*audit_p2m)(struct p2m_domain *p2m);

    /* Default P2M access type for each page in the the domain: new pages,
     * swapped in pages, cleared pages, and pages that are ambiquously
     * retyped get this access type.  See definition of p2m_access_t. */
    p2m_access_t default_access;

    /* If true, and an access fault comes in and there is no mem_event listener, 
     * pause domain.  Otherwise, remove access restrictions. */
    bool_t       access_required;

    /* Highest guest frame that's ever been mapped in the p2m */
    unsigned long max_mapped_pfn;

    /* When releasing shared gfn's in a preemptible manner, recall where
     * to resume the search */
    unsigned long next_shared_gfn_to_relinquish;

    /* Populate-on-demand variables
     * All variables are protected with the pod lock. We cannot rely on
     * the p2m lock if it's turned into a fine-grained lock.
     * We only use the domain page_alloc lock for additions and 
     * deletions to the domain's page list. Because we use it nested
     * within the PoD lock, we enforce it's ordering (by remembering
     * the unlock level in the arch_domain sub struct). */
    struct {
        struct page_list_head super,   /* List of superpages                */
                         single;       /* Non-super lists                   */
        int              count,        /* # of pages in cache lists         */
                         entry_count;  /* # of pages in p2m marked pod      */
        unsigned         reclaim_super; /* Last gpfn of a scan */
        unsigned         reclaim_single; /* Last gpfn of a scan */
        unsigned         max_guest;    /* gpfn of max guest demand-populate */
        mm_lock_t        lock;         /* Locking of private pod structs,   *
                                        * not relying on the p2m lock.      */
    } pod;
};

/* get host p2m table */
#define p2m_get_hostp2m(d)      ((d)->arch.p2m)

/* Get p2m table (re)usable for specified cr3.
 * Automatically destroys and re-initializes a p2m if none found.
 * If cr3 == 0 then v->arch.hvm_vcpu.guest_cr[3] is used.
 */
struct p2m_domain *p2m_get_nestedp2m(struct vcpu *v, uint64_t cr3);

/* If vcpu is in host mode then behaviour matches p2m_get_hostp2m().
 * If vcpu is in guest mode then behaviour matches p2m_get_nestedp2m().
 */
struct p2m_domain *p2m_get_p2m(struct vcpu *v);

#define p2m_is_nestedp2m(p2m)   ((p2m) != p2m_get_hostp2m((p2m->domain)))

#define p2m_get_pagetable(p2m)  ((p2m)->phys_table)

/**** p2m query accessors. They lock p2m_lock, and thus serialize
 * lookups wrt modifications. They _do not_ release the lock on exit.
 * After calling any of the variants below, caller needs to use
 * put_gfn. ****/

mfn_t __get_gfn_type_access(struct p2m_domain *p2m, unsigned long gfn,
                    p2m_type_t *t, p2m_access_t *a, p2m_query_t q,
                    unsigned int *page_order, bool_t locked);

/* Read a particular P2M table, mapping pages as we go.  Most callers
 * should _not_ call this directly; use the other get_gfn* functions
 * below unless you know you want to walk a p2m that isn't a domain's
 * main one.
 * If the lookup succeeds, the return value is != INVALID_MFN and 
 * *page_order is filled in with the order of the superpage (if any) that
 * the entry was found in.  */
#define get_gfn_type_access(p, g, t, a, q, o)   \
        __get_gfn_type_access((p), (g), (t), (a), (q), (o), 1)

/* General conversion function from gfn to mfn */
static inline mfn_t get_gfn_type(struct domain *d,
                                    unsigned long gfn, p2m_type_t *t,
                                    p2m_query_t q)
{
    p2m_access_t a;
    return get_gfn_type_access(p2m_get_hostp2m(d), gfn, t, &a, q, NULL);
}

/* Syntactic sugar: most callers will use one of these. 
 * N.B. get_gfn_query() is the _only_ one guaranteed not to take the
 * p2m lock; none of the others can be called with the p2m or paging
 * lock held. */
#define get_gfn(d, g, t)         get_gfn_type((d), (g), (t), P2M_ALLOC)
#define get_gfn_query(d, g, t)   get_gfn_type((d), (g), (t), 0)
#define get_gfn_unshare(d, g, t) get_gfn_type((d), (g), (t), \
                                              P2M_ALLOC | P2M_UNSHARE)

/* Compatibility function exporting the old untyped interface */
static inline unsigned long get_gfn_untyped(struct domain *d, unsigned long gpfn)
{
    mfn_t mfn;
    p2m_type_t t;
    mfn = get_gfn(d, gpfn, &t);
    if ( p2m_is_valid(t) )
        return mfn_x(mfn);
    return INVALID_MFN;
}

/* Will release the p2m_lock for this gfn entry. */
void __put_gfn(struct p2m_domain *p2m, unsigned long gfn);

#define put_gfn(d, gfn) __put_gfn(p2m_get_hostp2m((d)), (gfn))

/* The intent of the "unlocked" accessor is to have the caller not worry about
 * put_gfn. They apply to very specific situations: debug printk's, dumps 
 * during a domain crash, or to peek at a p2m entry/type. Caller is not 
 * holding the p2m entry exclusively during or after calling this. 
 *
 * This is also used in the shadow code whenever the paging lock is
 * held -- in those cases, the caller is protected against concurrent
 * p2m updates by the fact that shadow_write_p2m_entry() also takes
 * the paging lock.
 *
 * Note that an unlocked accessor only makes sense for a "query" lookup.
 * Any other type of query can cause a change in the p2m and may need to
 * perform locking.
 */
static inline mfn_t get_gfn_query_unlocked(struct domain *d, 
                                           unsigned long gfn, 
                                           p2m_type_t *t)
{
    p2m_access_t a;
    return __get_gfn_type_access(p2m_get_hostp2m(d), gfn, t, &a, 0, NULL, 0);
}

/* General conversion function from mfn to gfn */
static inline unsigned long mfn_to_gfn(struct domain *d, mfn_t mfn)
{
    if ( paging_mode_translate(d) )
        return get_gpfn_from_mfn(mfn_x(mfn));
    else
        return mfn_x(mfn);
}

/* Deadlock-avoidance scheme when calling get_gfn on different gfn's */
struct two_gfns {
    struct domain  *first_domain;
    unsigned long   first_gfn;
    struct domain  *second_domain;
    unsigned long   second_gfn;
};

/* Returns mfn, type and access for potential caller consumption, but any
 * of those can be NULL */
static inline void get_two_gfns(struct domain *rd, unsigned long rgfn,
        p2m_type_t *rt, p2m_access_t *ra, mfn_t *rmfn, struct domain *ld, 
        unsigned long lgfn, p2m_type_t *lt, p2m_access_t *la, mfn_t *lmfn,
        p2m_query_t q, struct two_gfns *rval)
{
    mfn_t           *first_mfn, *second_mfn, scratch_mfn;
    p2m_access_t    *first_a, *second_a, scratch_a;
    p2m_type_t      *first_t, *second_t, scratch_t;

    /* Sort by domain, if same domain by gfn */

#define assign_pointers(dest, source)                   \
do {                                                    \
    rval-> dest ## _domain = source ## d;               \
    rval-> dest ## _gfn = source ## gfn;                \
    dest ## _mfn = (source ## mfn) ?: &scratch_mfn;     \
    dest ## _a   = (source ## a)   ?: &scratch_a;       \
    dest ## _t   = (source ## t)   ?: &scratch_t;       \
} while (0)

    if ( (rd->domain_id <= ld->domain_id) || ((rd == ld) && (rgfn <= lgfn)) )
    {
        assign_pointers(first, r);
        assign_pointers(second, l);
    } else {
        assign_pointers(first, l);
        assign_pointers(second, r);
    }

#undef assign_pointers

    /* Now do the gets */
    *first_mfn  = get_gfn_type_access(p2m_get_hostp2m(rval->first_domain), 
                                      rval->first_gfn, first_t, first_a, q, NULL);
    *second_mfn = get_gfn_type_access(p2m_get_hostp2m(rval->second_domain), 
                                      rval->second_gfn, second_t, second_a, q, NULL);
}

static inline void put_two_gfns(struct two_gfns *arg)
{
    if ( !arg )
        return;

    put_gfn(arg->second_domain, arg->second_gfn);
    put_gfn(arg->first_domain, arg->first_gfn);
}

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d);

/* Allocate a new p2m table for a domain. 
 *
 * Returns 0 for success or -errno. */
int p2m_alloc_table(struct p2m_domain *p2m);

/* Return all the p2m resources to Xen. */
void p2m_teardown(struct p2m_domain *p2m);
void p2m_final_teardown(struct domain *d);

/* Add a page to a domain's p2m table */
int guest_physmap_add_entry(struct domain *d, unsigned long gfn,
                            unsigned long mfn, unsigned int page_order, 
                            p2m_type_t t);

/* Untyped version for RAM only, for compatibility */
static inline int guest_physmap_add_page(struct domain *d,
                                         unsigned long gfn,
                                         unsigned long mfn,
                                         unsigned int page_order)
{
    return guest_physmap_add_entry(d, gfn, mfn, page_order, p2m_ram_rw);
}

/* Remove a page from a domain's p2m table */
void guest_physmap_remove_page(struct domain *d,
                               unsigned long gfn,
                               unsigned long mfn, unsigned int page_order);

/* Set a p2m range as populate-on-demand */
int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order);

/* Change types across all p2m entries in a domain */
void p2m_change_entry_type_global(struct domain *d, 
                                  p2m_type_t ot, p2m_type_t nt);

/* Change types across a range of p2m entries (start ... end-1) */
void p2m_change_type_range(struct domain *d, 
                           unsigned long start, unsigned long end,
                           p2m_type_t ot, p2m_type_t nt);

/* Compare-exchange the type of a single p2m entry */
p2m_type_t p2m_change_type(struct domain *d, unsigned long gfn,
                           p2m_type_t ot, p2m_type_t nt);

/* Set mmio addresses in the p2m table (for pass-through) */
int set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn);
int clear_mmio_p2m_entry(struct domain *d, unsigned long gfn);


/* 
 * Populate-on-demand
 */

/* Dump PoD information about the domain */
void p2m_pod_dump_data(struct domain *d);

/* Move all pages from the populate-on-demand cache to the domain page_list
 * (usually in preparation for domain destruction) */
void p2m_pod_empty_cache(struct domain *d);

/* Set populate-on-demand cache size so that the total memory allocated to a
 * domain matches target */
int p2m_pod_set_mem_target(struct domain *d, unsigned long target);

/* Call when decreasing memory reservation to handle PoD entries properly.
 * Will return '1' if all entries were handled and nothing more need be done.*/
int
p2m_pod_decrease_reservation(struct domain *d,
                             xen_pfn_t gpfn,
                             unsigned int order);

/* Scan pod cache when offline/broken page triggered */
int
p2m_pod_offline_or_broken_hit(struct page_info *p);

/* Replace pod cache when offline/broken page triggered */
void
p2m_pod_offline_or_broken_replace(struct page_info *p);


/*
 * Paging to disk and page-sharing
 */

#ifdef __x86_64__
/* Modify p2m table for shared gfn */
int set_shared_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn);

/* Check if a nominated gfn is valid to be paged out */
int p2m_mem_paging_nominate(struct domain *d, unsigned long gfn);
/* Evict a frame */
int p2m_mem_paging_evict(struct domain *d, unsigned long gfn);
/* Tell xenpaging to drop a paged out frame */
void p2m_mem_paging_drop_page(struct domain *d, unsigned long gfn, 
                                p2m_type_t p2mt);
/* Start populating a paged out frame */
void p2m_mem_paging_populate(struct domain *d, unsigned long gfn);
/* Prepare the p2m for paging a frame in */
int p2m_mem_paging_prep(struct domain *d, unsigned long gfn, uint64_t buffer);
/* Resume normal operation (in case a domain was paused) */
void p2m_mem_paging_resume(struct domain *d);
#else
static inline void p2m_mem_paging_drop_page(struct domain *d, unsigned long gfn,
                                            p2m_type_t p2mt)
{ }
static inline void p2m_mem_paging_populate(struct domain *d, unsigned long gfn)
{ }
#endif

#ifdef __x86_64__
/* Send mem event based on the access (gla is -1ull if not available).  Handles
 * the rw2rx conversion. Boolean return value indicates if access rights have 
 * been promoted with no underlying vcpu pause. If the req_ptr has been populated, 
 * then the caller must put the event in the ring (once having released get_gfn*
 * locks -- caller must also xfree the request. */
bool_t p2m_mem_access_check(unsigned long gpa, bool_t gla_valid, unsigned long gla, 
                          bool_t access_r, bool_t access_w, bool_t access_x,
                          mem_event_request_t **req_ptr);
/* Resumes the running of the VCPU, restarting the last instruction */
void p2m_mem_access_resume(struct domain *d);

/* Set access type for a region of pfns.
 * If start_pfn == -1ul, sets the default access type */
int p2m_set_mem_access(struct domain *d, unsigned long start_pfn, 
                       uint32_t nr, hvmmem_access_t access);

/* Get access type for a pfn
 * If pfn == -1ul, gets the default access type */
int p2m_get_mem_access(struct domain *d, unsigned long pfn, 
                       hvmmem_access_t *access);

#else
static inline bool_t p2m_mem_access_check(unsigned long gpa, bool_t gla_valid, 
                                        unsigned long gla, bool_t access_r, 
                                        bool_t access_w, bool_t access_x,
                                        mem_event_request_t **req_ptr)
{ return 1; }
static inline int p2m_set_mem_access(struct domain *d, 
                                     unsigned long start_pfn, 
                                     uint32_t nr, hvmmem_access_t access)
{ return -EINVAL; }
static inline int p2m_get_mem_access(struct domain *d, unsigned long pfn, 
                                     hvmmem_access_t *access)
{ return -EINVAL; }
#endif

/* 
 * Internal functions, only called by other p2m code
 */

struct page_info *p2m_alloc_ptp(struct p2m_domain *p2m, unsigned long type);
void p2m_free_ptp(struct p2m_domain *p2m, struct page_info *pg);

#if CONFIG_PAGING_LEVELS == 3
static inline int p2m_gfn_check_limit(
    struct domain *d, unsigned long gfn, unsigned int order)
{
    /*
     * 32bit AMD nested paging does not support over 4GB guest due to 
     * hardware translation limit. This limitation is checked by comparing
     * gfn with 0xfffffUL.
     */
    if ( !hap_enabled(d) || ((gfn + (1ul << order)) <= 0x100000UL) ||
         (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) )
        return 0;

    if ( !test_and_set_bool(d->arch.hvm_domain.svm.npt_4gb_warning) )
        dprintk(XENLOG_WARNING, "Dom%d failed to populate memory beyond"
                " 4GB: specify 'hap=0' domain config option.\n",
                d->domain_id);

    return -EINVAL;
}
#else
#define p2m_gfn_check_limit(d, g, o) 0
#endif

/* Directly set a p2m entry: only for use by p2m code. Does not need
 * a call to put_gfn afterwards/ */
int set_p2m_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
                  unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma);

/* Set up function pointers for PT implementation: only for use by p2m code */
extern void p2m_pt_init(struct p2m_domain *p2m);

/* Debugging and auditing of the P2M code? */
#define P2M_AUDIT     1
#define P2M_DEBUGGING 0

#if P2M_AUDIT
extern void audit_p2m(struct domain *d,
                      uint64_t *orphans,
                      uint64_t *m2p_bad,
                      uint64_t *p2m_bad);
#endif /* P2M_AUDIT */

/* Printouts */
#define P2M_PRINTK(_f, _a...)                                \
    debugtrace_printk("p2m: %s(): " _f, __func__, ##_a)
#define P2M_ERROR(_f, _a...)                                 \
    printk("pg error: %s(): " _f, __func__, ##_a)
#if P2M_DEBUGGING
#define P2M_DEBUG(_f, _a...)                                 \
    debugtrace_printk("p2mdebug: %s(): " _f, __func__, ##_a)
#else
#define P2M_DEBUG(_f, _a...) do { (void)(_f); } while(0)
#endif

/* Called by p2m code when demand-populating a PoD page */
int
p2m_pod_demand_populate(struct p2m_domain *p2m, unsigned long gfn,
                        unsigned int order,
                        p2m_query_t q);

/*
 * Functions specific to the p2m-pt implementation
 */

/* Extract the type from the PTE flags that store it */
static inline p2m_type_t p2m_flags_to_type(unsigned long flags)
{
    /* For AMD IOMMUs we need to use type 0 for plain RAM, but we need
     * to make sure that an entirely empty PTE doesn't have RAM type */
    if ( flags == 0 ) 
        return p2m_invalid;
#ifdef __x86_64__
    /* AMD IOMMUs use bits 9-11 to encode next io page level and bits
     * 59-62 for iommu flags so we can't use them to store p2m type info. */
    return (flags >> 12) & 0x7f;
#else
    return (flags >> 9) & 0x7;
#endif
}

/*
 * Nested p2m: shadow p2m tables used for nested HVM virtualization 
 */

/* Flushes specified p2m table */
void p2m_flush(struct vcpu *v, struct p2m_domain *p2m);
/* Flushes all nested p2m tables */
void p2m_flush_nestedp2m(struct domain *d);

void nestedp2m_write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
    l1_pgentry_t *p, mfn_t table_mfn, l1_pgentry_t new, unsigned int level);

#endif /* _XEN_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
