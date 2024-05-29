/* SPDX-License-Identifier: GPL-2.0-or-later */
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
 */

#ifndef _XEN_ASM_X86_P2M_H
#define _XEN_ASM_X86_P2M_H

#include <xen/paging.h>
#include <xen/mem_access.h>
#include <asm/mem_sharing.h>
#include <asm/page.h>    /* for pagetable_t */

/* Debugging and auditing of the P2M code? */
#if !defined(NDEBUG) && defined(CONFIG_HVM)
#define P2M_AUDIT     1
#else
#define P2M_AUDIT     0
#endif
#define P2M_DEBUGGING 0

extern bool opt_hap_1gb, opt_hap_2mb;

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
    p2m_map_foreign  = 14,        /* ram pages from foreign domain */
    p2m_ioreq_server = 15,
} p2m_type_t;

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
                       | p2m_to_mask(p2m_ram_shared)          \
                       | p2m_to_mask(p2m_ioreq_server))

/* Types that represent a physmap hole that is ok to replace with a shared
 * entry */
#define P2M_HOLE_TYPES (p2m_to_mask(p2m_mmio_dm)        \
                       | p2m_to_mask(p2m_invalid)       \
                       | p2m_to_mask(p2m_ram_paging_in) \
                       | p2m_to_mask(p2m_ram_paged))

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
                      | p2m_to_mask(p2m_ram_shared))

/* Write-discard types, which should discard the write operations */
#define P2M_DISCARD_WRITE_TYPES (p2m_to_mask(p2m_ram_ro)     \
                      | p2m_to_mask(p2m_grant_map_ro))

/* Types that can be subject to bulk transitions. */
#define P2M_CHANGEABLE_TYPES (p2m_to_mask(p2m_ram_rw) \
                              | p2m_to_mask(p2m_ram_logdirty) \
                              | p2m_to_mask(p2m_ioreq_server) )

#define P2M_POD_TYPES (p2m_to_mask(p2m_populate_on_demand))

/* Pageable types */
#define P2M_PAGEABLE_TYPES (p2m_to_mask(p2m_ram_rw) \
                            | p2m_to_mask(p2m_ram_logdirty) )

#ifdef CONFIG_MEM_PAGING
#define P2M_PAGING_TYPES (p2m_to_mask(p2m_ram_paging_out)        \
                          | p2m_to_mask(p2m_ram_paged)           \
                          | p2m_to_mask(p2m_ram_paging_in))

#define P2M_PAGED_TYPES (p2m_to_mask(p2m_ram_paged))
#else
#define P2M_PAGING_TYPES 0
#define P2M_PAGED_TYPES 0
#endif

/* Shared types */
/* XXX: Sharable types could include p2m_ram_ro too, but we would need to
 * reinit the type correctly after fault */
#define P2M_SHARABLE_TYPES (p2m_to_mask(p2m_ram_rw) \
                            | p2m_to_mask(p2m_ram_logdirty) )
#define P2M_SHARED_TYPES   (p2m_to_mask(p2m_ram_shared))

/* Types established/cleaned up via special accessors. */
#define P2M_SPECIAL_TYPES (P2M_GRANT_TYPES | \
                           p2m_to_mask(p2m_map_foreign) | \
                           p2m_to_mask(p2m_mmio_direct))

/* Valid types not necessarily associated with a (valid) MFN. */
#define P2M_INVALID_MFN_TYPES (P2M_POD_TYPES                  \
                               | p2m_to_mask(p2m_mmio_direct) \
                               | P2M_PAGING_TYPES)

/* Broken type: the frame backing this pfn has failed in hardware
 * and must not be touched. */
#define P2M_BROKEN_TYPES (p2m_to_mask(p2m_ram_broken))

/* Useful predicates */
#define p2m_is_ram(_t) (p2m_to_mask(_t) & P2M_RAM_TYPES)
#define p2m_is_hole(_t) (p2m_to_mask(_t) & P2M_HOLE_TYPES)
#define p2m_is_mmio(_t) (p2m_to_mask(_t) & P2M_MMIO_TYPES)
#define p2m_is_readonly(_t) (p2m_to_mask(_t) & P2M_RO_TYPES)
#define p2m_is_discard_write(_t) (p2m_to_mask(_t) & P2M_DISCARD_WRITE_TYPES)
#define p2m_is_changeable(_t) (p2m_to_mask(_t) & P2M_CHANGEABLE_TYPES)
#define p2m_is_pod(_t) (p2m_to_mask(_t) & P2M_POD_TYPES)
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
#define p2m_is_special(_t)  (p2m_to_mask(_t) & P2M_SPECIAL_TYPES)
#define p2m_is_broken(_t)   (p2m_to_mask(_t) & P2M_BROKEN_TYPES)
#define p2m_is_foreign(_t)  (p2m_to_mask(_t) & p2m_to_mask(p2m_map_foreign))

#define p2m_is_any_ram(_t)  (p2m_to_mask(_t) &                   \
                             (P2M_RAM_TYPES | P2M_GRANT_TYPES |  \
                              p2m_to_mask(p2m_map_foreign)))

#define p2m_allows_invalid_mfn(t) (p2m_to_mask(t) & P2M_INVALID_MFN_TYPES)

typedef enum {
    p2m_host,
    p2m_nested,
    p2m_alternate,
} p2m_class_t;

/* Per-p2m-table state */
struct p2m_domain {
#ifdef CONFIG_HVM
    /* Lock that protects updates to the p2m */
    mm_rwlock_t           lock;
#endif

    /*
     * Same as a domain's dirty_cpumask but limited to
     * this p2m and those physical cpus whose vcpu's are in
     * guestmode.
     */
    cpumask_var_t      dirty_cpumask;

    struct domain     *domain;   /* back pointer to domain */

    p2m_class_t       p2m_class; /* host/nested/alternate */

    /*
     * Default P2M access type for each page in the the domain: new pages,
     * swapped in pages, cleared pages, and pages that are ambiguously
     * retyped get this access type.  See definition of p2m_access_t.
     */
    p2m_access_t default_access;

#ifdef CONFIG_HVM

    /* Host p2m: Log-dirty ranges registered for the domain. */
    struct rangeset   *logdirty_ranges;

    /* Host p2m: Global log-dirty mode enabled for the domain. */
    bool               global_logdirty;

    /* Translated domain: p2m mapping */
    pagetable_t        phys_table;

    /* Pages used to construct the p2m */
    struct page_list_head pages;

    /* Alternate p2m: count of vcpu's currently using this p2m. */
    atomic_t           active_vcpus;

    int                (*set_entry)(struct p2m_domain *p2m,
                                    gfn_t gfn,
                                    mfn_t mfn, unsigned int page_order,
                                    p2m_type_t p2mt,
                                    p2m_access_t p2ma,
                                    int sve);
    mfn_t              (*get_entry)(struct p2m_domain *p2m,
                                    gfn_t gfn,
                                    p2m_type_t *p2mt,
                                    p2m_access_t *p2ma,
                                    p2m_query_t q,
                                    unsigned int *page_order,
                                    bool *sve);
    int                (*recalc)(struct p2m_domain *p2m,
                                 unsigned long gfn);
    void               (*enable_hardware_log_dirty)(struct p2m_domain *p2m);
    void               (*disable_hardware_log_dirty)(struct p2m_domain *p2m);
    void               (*flush_hardware_cached_dirty)(struct p2m_domain *p2m);
    void               (*change_entry_type_global)(struct p2m_domain *p2m,
                                                   p2m_type_t ot,
                                                   p2m_type_t nt);
    int                (*change_entry_type_range)(struct p2m_domain *p2m,
                                                  p2m_type_t ot, p2m_type_t nt,
                                                  unsigned long first_gfn,
                                                  unsigned long last_gfn);
    void               (*memory_type_changed)(struct p2m_domain *p2m);
    void               (*write_p2m_entry_pre)(struct domain *d,
                                              unsigned long gfn,
                                              l1_pgentry_t old,
                                              l1_pgentry_t new,
                                              unsigned int level);
    void               (*write_p2m_entry_post)(struct p2m_domain *p2m,
                                               unsigned int oflags);
#if P2M_AUDIT
    long               (*audit_p2m)(struct p2m_domain *p2m);
#endif

    /*
     * P2M updates may require TLBs to be flushed (invalidated).
     *
     * If 'defer_flush' is set, flushes may be deferred by setting
     * 'need_flush' and then flushing in 'tlb_flush()'.
     *
     * 'tlb_flush()' is only called if 'need_flush' was set.
     *
     * If a flush may be being deferred but an immediate flush is
     * required (e.g., if a page is being freed to pool other than the
     * domheap), call p2m_tlb_flush_sync().
     */
    void (*tlb_flush)(struct p2m_domain *p2m);
    unsigned int defer_flush;
    bool need_flush;

    /*
     * If true, and an access fault comes in and there is no vm_event
     * listener, pause domain.  Otherwise, remove access restrictions.
     */
    bool         access_required;

    /* Highest guest frame that's ever been mapped in the p2m */
    unsigned long max_mapped_pfn;

    /*
     * Alternate p2m's only: range of gfn's for which underlying
     * mfn may have duplicate mappings
     */
    unsigned long min_remapped_gfn;
    unsigned long max_remapped_gfn;

    /*
     * Populate-on-demand variables
     * All variables are protected with the pod lock. We cannot rely on
     * the p2m lock if it's turned into a fine-grained lock.
     * We only use the domain page_alloc lock for additions and
     * deletions to the domain's page list. Because we use it nested
     * within the PoD lock, we enforce it's ordering (by remembering
     * the unlock level in the arch_domain sub struct).
     */
    struct {
        struct page_list_head super,   /* List of superpages                */
                         single;       /* Non-super lists                   */
        long             count,        /* # of pages in cache lists         */
                         entry_count;  /* # of pages in p2m marked pod      */
        gfn_t            reclaim_single; /* Last gfn of a scan */
        gfn_t            max_guest;    /* gfn of max guest demand-populate */

        /*
         * Tracking of the most recently populated PoD pages, for eager
         * reclamation.
         */
        struct pod_mrp_list {
#define NR_POD_MRP_ENTRIES 32

/* Encode ORDER_2M superpage in top bit of GFN */
#define POD_LAST_SUPERPAGE (gfn_x(INVALID_GFN) & ~(gfn_x(INVALID_GFN) >> 1))

            unsigned long list[NR_POD_MRP_ENTRIES];
            unsigned int idx;
        } mrp;
        mm_lock_t        lock;         /* Locking of private pod structs,   *
                                        * not relying on the p2m lock.      */
    } pod;

    /*
     * Host p2m: when this flag is set, don't flush all the nested-p2m
     * tables on every host-p2m change.  The setter of this flag
     * is responsible for performing the full flush before releasing the
     * host p2m's lock.
     */
    bool               defer_nested_flush;

    /*
     * Nested p2ms only: nested p2m base value that this p2m shadows.
     * This can be cleared to P2M_BASE_EADDR under the per-p2m lock but
     * needs both the per-p2m lock and the per-domain nestedp2m lock
     * to set it to any other value.
     */
#define P2M_BASE_EADDR     (~0ULL)
    uint64_t           np2m_base;
    uint64_t           np2m_generation;

    /*
     * Nested p2ms: linked list of n2pms allocated to this domain.
     * The host p2m hasolds the head of the list and the np2ms are
     * threaded on in LRU order.
     */
    struct list_head   np2m_list;

    union {
        struct ept_data ept;
        /* NPT-equivalent structure could be added here. */
    };

    struct {
        spinlock_t lock;
        /*
         * ioreq server who's responsible for the emulation of
         * gfns with specific p2m type(for now, p2m_ioreq_server).
         */
        struct ioreq_server *server;
        /*
         * flags specifies whether read, write or both operations
         * are to be emulated by an ioreq server.
         */
        unsigned int flags;
        unsigned long entry_count;
    } ioreq;

    /* Number of foreign mappings. */
    unsigned long      nr_foreign;
    /* Cursor for iterating over the p2m on teardown. */
    unsigned long      teardown_gfn;
#endif /* CONFIG_HVM */
};

/* get host p2m table */
#define p2m_get_hostp2m(d)      ((d)->arch.p2m)

/* All common type definitions should live ahead of this inclusion. */
#ifdef _XEN_P2M_COMMON_H
# error "xen/p2m-common.h should not be included directly"
#endif
#include <xen/p2m-common.h>

bool arch_acquire_resource_check(const struct domain *d);

/*
 * Updates vCPU's n2pm to match its np2m_base in VMCx12 and returns that np2m.
 */
struct p2m_domain *p2m_get_nestedp2m(struct vcpu *v);
/* Similar to the above except that returned p2m is still write-locked */
struct p2m_domain *p2m_get_nestedp2m_locked(struct vcpu *v);

/* If vcpu is in host mode then behaviour matches p2m_get_hostp2m().
 * If vcpu is in guest mode then behaviour matches p2m_get_nestedp2m().
 */
struct p2m_domain *p2m_get_p2m(struct vcpu *v);

#define NP2M_SCHEDLE_IN  0
#define NP2M_SCHEDLE_OUT 1

#ifdef CONFIG_HVM
void np2m_schedule(int dir);
#else
static inline void np2m_schedule(int dir) {}
#endif

static inline bool p2m_is_hostp2m(const struct p2m_domain *p2m)
{
    return p2m->p2m_class == p2m_host;
}

static inline bool p2m_is_nestedp2m(const struct p2m_domain *p2m)
{
    return p2m->p2m_class == p2m_nested;
}

static inline bool p2m_is_altp2m(const struct p2m_domain *p2m)
{
    return p2m->p2m_class == p2m_alternate;
}

#ifdef CONFIG_HVM
static inline pagetable_t p2m_get_pagetable(const struct p2m_domain *p2m)
{
    return p2m->phys_table;
}
#else
pagetable_t p2m_get_pagetable(const struct p2m_domain *p2m);
#endif

/*
 * Ensure any deferred p2m TLB flush has been completed on all VCPUs.
 */
void p2m_tlb_flush_sync(struct p2m_domain *p2m);
void p2m_unlock_and_tlb_flush(struct p2m_domain *p2m);

/**** p2m query accessors. They lock p2m_lock, and thus serialize
 * lookups wrt modifications. They _do not_ release the lock on exit.
 * After calling any of the variants below, caller needs to use
 * put_gfn. ****/

mfn_t __nonnull(3, 4) p2m_get_gfn_type_access(
    struct p2m_domain *p2m, gfn_t gfn, p2m_type_t *t,
    p2m_access_t *a, p2m_query_t q, unsigned int *page_order, bool locked);

static inline mfn_t __nonnull(3, 4) _get_gfn_type_access(
    struct p2m_domain *p2m, gfn_t gfn, p2m_type_t *t,
    p2m_access_t *a, p2m_query_t q, unsigned int *page_order, bool locked)
{
    if ( !p2m || !paging_mode_translate(p2m->domain) )
    {
        /*
         * Not necessarily true, but for non-translated guests we claim
         * it's the most generic kind of memory.
         */
        *t = p2m_ram_rw;
        return _mfn(gfn_x(gfn));
    }

    return p2m_get_gfn_type_access(p2m, gfn, t, a, q, page_order, locked);
}

/*
 * Read a particular P2M table, mapping pages as we go.  Most callers
 * should _not_ call this directly; use the other get_gfn* functions
 * below unless you know you want to walk a p2m that isn't a domain's
 * main one.
 * If the lookup succeeds, the return value is != INVALID_MFN and
 * *page_order is filled in with the order of the superpage (if any) that
 * the entry was found in.
 */
static inline mfn_t __nonnull(3, 4) get_gfn_type_access(
    struct p2m_domain *p2m, unsigned long gfn, p2m_type_t *t,
    p2m_access_t *a, p2m_query_t q, unsigned int *page_order)
{
    return _get_gfn_type_access(p2m, _gfn(gfn), t, a, q, page_order, true);
}

/* General conversion function from gfn to mfn */
static inline mfn_t __nonnull(3) get_gfn_type(
    struct domain *d, unsigned long gfn, p2m_type_t *t, p2m_query_t q)
{
    p2m_access_t a;
    return get_gfn_type_access(p2m_get_hostp2m(d), gfn, t, &a, q, NULL);
}

/* Syntactic sugar: most callers will use one of these. */
#define get_gfn(d, g, t)         get_gfn_type((d), (g), (t), P2M_ALLOC)
#define get_gfn_query(d, g, t)   get_gfn_type((d), (g), (t), 0)
#define get_gfn_unshare(d, g, t) get_gfn_type((d), (g), (t), \
                                              P2M_ALLOC | P2M_UNSHARE)

/* Will release the p2m_lock for this gfn entry. */
void p2m_put_gfn(struct p2m_domain *p2m, gfn_t gfn);

static inline void put_gfn(struct domain *d, unsigned long gfn)
{
    if ( !paging_mode_translate(d) )
        /* Nothing to do in this case */
        return;

    p2m_put_gfn(p2m_get_hostp2m(d), _gfn(gfn));
}

/*
 * The intent of the "unlocked" accessor is to have the caller not worry about
 * put_gfn. They apply to very specific situations: debug printk's, dumps
 * during a domain crash, or to peek at a p2m entry/type. Caller is not
 * holding the p2m entry exclusively during or after calling this.
 *
 * This is also used in the shadow code whenever the paging lock is
 * held -- in those cases, the caller is protected against concurrent
 * p2m updates by the fact that write_p2m_entry() also takes
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
    return _get_gfn_type_access(p2m_get_hostp2m(d), _gfn(gfn), t, &a, 0,
                                NULL, 0);
}

/*
 * Atomically look up a GFN and take a reference count on the backing page.
 * This makes sure the page doesn't get freed (or shared) underfoot,
 * and should be used by any path that intends to write to the backing page.
 * Returns NULL if the page is not backed by RAM.
 * The caller is responsible for calling put_page() afterwards.
 */
struct page_info *p2m_get_page_from_gfn(struct p2m_domain *p2m, gfn_t gfn,
                                        p2m_type_t *t, p2m_access_t *a,
                                        p2m_query_t q);

static inline struct page_info *get_page_from_gfn(
    struct domain *d, unsigned long gfn, p2m_type_t *t, p2m_query_t q)
{
    struct page_info *page;

    if ( paging_mode_translate(d) )
        return p2m_get_page_from_gfn(p2m_get_hostp2m(d), _gfn(gfn), t, NULL, q);

    /* Non-translated guests see 1-1 RAM / MMIO mappings everywhere */
    if ( t )
        *t = likely(d != dom_io) ? p2m_ram_rw : p2m_mmio_direct;
    page = mfn_to_page(_mfn(gfn));
    return mfn_valid(_mfn(gfn)) && get_page(page, d) ? page : NULL;
}

/* General conversion function from mfn to gfn */
static inline gfn_t mfn_to_gfn(const struct domain *d, mfn_t mfn)
{
    if ( paging_mode_translate(d) )
        return _gfn(get_gpfn_from_mfn(mfn_x(mfn)));
    else
        return _gfn(mfn_x(mfn));
}

#ifdef CONFIG_HVM
#define AP2MGET_prepopulate true
#define AP2MGET_query false

/*
 * Looks up altp2m entry. If the entry is not found it looks up the entry in
 * hostp2m.
 * The prepopulate param is used to set the found entry in altp2m.
 */
int altp2m_get_effective_entry(struct p2m_domain *ap2m, gfn_t gfn, mfn_t *mfn,
                               p2m_type_t *t, p2m_access_t *a,
                               bool prepopulate);
#endif

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d);

/* Allocate a new p2m table for a domain.  Returns 0 for success or -errno. */
int p2m_alloc_table(struct p2m_domain *p2m);

/* Return all the p2m resources to Xen. */
void p2m_teardown(struct p2m_domain *p2m, bool remove_root, bool *preempted);
void p2m_final_teardown(struct domain *d);

/* Add/remove a page to/from a domain's p2m table. */
int p2m_add_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                 unsigned int page_order, p2m_type_t t);
int p2m_remove_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                    unsigned int page_order);

/* Untyped version for RAM only, for compatibility and PV. */
int __must_check guest_physmap_add_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                                        unsigned int page_order);

/* Set a p2m range as populate-on-demand */
int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order);

#ifdef CONFIG_HVM

/* Enable hardware-assisted log-dirty. */
void p2m_enable_hardware_log_dirty(struct domain *d);

/* Disable hardware-assisted log-dirty */
void p2m_disable_hardware_log_dirty(struct domain *d);

/* Flush hardware cached dirty GFNs */
void p2m_flush_hardware_cached_dirty(struct domain *d);

#else

static inline void p2m_flush_hardware_cached_dirty(struct domain *d) {}

#endif

/* Change types across all p2m entries in a domain */
void p2m_change_entry_type_global(struct domain *d,
                                  p2m_type_t ot, p2m_type_t nt);

/* Change types across a range of p2m entries (start ... end-1) */
void p2m_change_type_range(struct domain *d,
                           unsigned long start, unsigned long end,
                           p2m_type_t ot, p2m_type_t nt);

/* Compare-exchange the type of a single p2m entry */
int p2m_change_type_one(struct domain *d, unsigned long gfn_l,
                        p2m_type_t ot, p2m_type_t nt);

/* Synchronously change the p2m type for a range of gfns */
int p2m_finish_type_change(struct domain *d,
                           gfn_t first_gfn,
                           unsigned long max_nr);

static inline bool p2m_is_global_logdirty(const struct domain *d)
{
#ifdef CONFIG_HVM
    return p2m_get_hostp2m(d)->global_logdirty;
#else
    return false;
#endif
}

int p2m_is_logdirty_range(struct p2m_domain *p2m, unsigned long start,
                          unsigned long end);

/* Set mmio addresses in the p2m table (for pass-through) */
int set_mmio_p2m_entry(struct domain *d, gfn_t gfn, mfn_t mfn,
                       unsigned int order);

/* Set identity addresses in the p2m table (for pass-through) */
int set_identity_p2m_entry(struct domain *d, unsigned long gfn,
                           p2m_access_t p2ma, unsigned int flag);
int clear_identity_p2m_entry(struct domain *d, unsigned long gfn);
/* HVM-only callers can use these directly: */
int p2m_add_identity_entry(struct domain *d, unsigned long gfn_l,
                           p2m_access_t p2ma, unsigned int flag);
int p2m_remove_identity_entry(struct domain *d, unsigned long gfn_l);

/*
 * Populate-on-demand
 */

/* Dump PoD information about the domain */
void p2m_pod_dump_data(struct domain *d);

#ifdef CONFIG_HVM

/* Report a change affecting memory types. */
void p2m_memory_type_changed(struct domain *d);

/* Called by p2m code when demand-populating a PoD page */
bool
p2m_pod_demand_populate(struct p2m_domain *p2m, gfn_t gfn, unsigned int order);

/* Move all pages from the populate-on-demand cache to the domain page_list
 * (usually in preparation for domain destruction) */
int p2m_pod_empty_cache(struct domain *d);

/* Set populate-on-demand cache size so that the total memory allocated to a
 * domain matches target */
int p2m_pod_set_mem_target(struct domain *d, unsigned long target);

/* Obtain a consistent snapshot of PoD related domain state. */
void p2m_pod_get_mem_target(const struct domain *d, xen_pod_target_t *target);

/* Check whether PoD is (still) active in a domain. */
bool p2m_pod_active(const struct domain *d);

/* Scan pod cache when offline/broken page triggered */
int
p2m_pod_offline_or_broken_hit(struct page_info *p);

/* Replace pod cache when offline/broken page triggered */
void
p2m_pod_offline_or_broken_replace(struct page_info *p);

/* Perform cleanup of p2m mappings ahead of teardown. */
int
relinquish_p2m_mapping(struct domain *d);

#else

static inline bool
p2m_pod_demand_populate(struct p2m_domain *p2m, gfn_t gfn, unsigned int order)
{
    return false;
}

static inline int p2m_pod_empty_cache(struct domain *d)
{
    return 0;
}

static inline bool p2m_pod_active(const struct domain *d)
{
    return false;
}

static inline int p2m_pod_offline_or_broken_hit(struct page_info *p)
{
    return 0;
}

static inline void p2m_pod_offline_or_broken_replace(struct page_info *p)
{
    ASSERT_UNREACHABLE();
}

static inline int relinquish_p2m_mapping(struct domain *d)
{
    return 0;
}

#endif


/*
 * Paging to disk and page-sharing
 */

/* Modify p2m table for shared gfn */
int set_shared_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn);

/* Tell xenpaging to drop a paged out frame */
void p2m_mem_paging_drop_page(struct domain *d, gfn_t gfn, p2m_type_t p2mt);
/* Start populating a paged out frame */
void p2m_mem_paging_populate(struct domain *d, gfn_t gfn);
/* Resume normal operation (in case a domain was paused) */
struct vm_event_st;
void p2m_mem_paging_resume(struct domain *d, struct vm_event_st *rsp);

/*
 * Internal functions, only called by other p2m code
 */

mfn_t p2m_alloc_ptp(struct p2m_domain *p2m, unsigned int level);
void p2m_free_ptp(struct p2m_domain *p2m, struct page_info *pg);

/* Directly set a p2m entry: only for use by p2m code. Does not need
 * a call to put_gfn afterwards/ */
int __must_check p2m_set_entry(struct p2m_domain *p2m, gfn_t gfn, mfn_t mfn,
                               unsigned int page_order, p2m_type_t p2mt,
                               p2m_access_t p2ma);

#if defined(CONFIG_HVM)
/* Set up function pointers for PT implementation: only for use by p2m code */
extern void p2m_pt_init(struct p2m_domain *p2m);
#else
static inline void p2m_pt_init(struct p2m_domain *p2m) {}
#endif

void *map_domain_gfn(struct p2m_domain *p2m, gfn_t gfn, mfn_t *mfn,
                     p2m_query_t q, uint32_t *pfec);

#if P2M_AUDIT
extern void audit_p2m(struct domain *d,
                      uint64_t *orphans,
                      uint64_t *m2p_bad,
                      uint64_t *p2m_bad);
#endif /* P2M_AUDIT */

/* Printouts */
#define P2M_PRINTK(f, a...)                                \
    debugtrace_printk("p2m: %s(): " f, __func__, ##a)
#define P2M_ERROR(f, a...)                                 \
    printk(XENLOG_G_ERR "pg error: %s(): " f, __func__, ##a)
#if P2M_DEBUGGING
#define P2M_DEBUG(f, a...)                                 \
    debugtrace_printk("p2mdebug: %s(): " f, __func__, ##a)
#else
#define P2M_DEBUG(f, a...) do { (void)(f); } while(0)
#endif

#ifdef CONFIG_HVM

/*
 * Functions specific to the p2m-pt implementation
 */

/* Extract the type from the PTE flags that store it */
static inline p2m_type_t p2m_flags_to_type(unsigned int flags)
{
    /*
     * For AMD IOMMUs we need to use type 0 for plain RAM, but we need
     * to make sure that an entirely empty PTE doesn't have RAM type.
     */
    if ( flags == 0 )
        return p2m_invalid;

    /*
     * AMD IOMMUs use bits 9-11 to encode next io page level and bits
     * 59-62 for iommu flags so we can't use them to store p2m type info.
     */
    return (flags >> 12) & 0x7f;
}

static inline p2m_type_t p2m_recalc_type_range(bool recalc, p2m_type_t t,
                                               struct p2m_domain *p2m,
                                               unsigned long gfn_start,
                                               unsigned long gfn_end)
{
    if ( !recalc || !p2m_is_changeable(t) )
        return t;

    if ( t == p2m_ioreq_server && p2m->ioreq.server != NULL )
        return t;

    return p2m_is_logdirty_range(p2m, gfn_start, gfn_end) ? p2m_ram_logdirty
                                                          : p2m_ram_rw;
}

static inline p2m_type_t p2m_recalc_type(bool recalc, p2m_type_t t,
                                         struct p2m_domain *p2m,
                                         unsigned long gfn)
{
    return p2m_recalc_type_range(recalc, t, p2m, gfn, gfn);
}

int p2m_pt_handle_deferred_changes(uint64_t gpa);

/*
 * Nested p2m: shadow p2m tables used for nested HVM virtualization
 */

/* Flushes specified p2m table */
void p2m_flush(struct vcpu *v, struct p2m_domain *p2m);
/* Flushes all nested p2m tables */
void p2m_flush_nestedp2m(struct domain *d);
/* Flushes the np2m specified by np2m_base (if it exists) */
void np2m_flush_base(struct vcpu *v, unsigned long np2m_base);

void hap_p2m_init(struct p2m_domain *p2m);
void shadow_p2m_init(struct p2m_domain *p2m);

void cf_check nestedp2m_write_p2m_entry_post(
    struct p2m_domain *p2m, unsigned int oflags);

/*
 * Alternate p2m: shadow p2m tables used for alternate memory views
 */

/* get current alternate p2m table */
static inline struct p2m_domain *p2m_get_altp2m(struct vcpu *v)
{
    unsigned int index = vcpu_altp2m(v).p2midx;

    if ( index == INVALID_ALTP2M )
        return NULL;

    BUG_ON(index >= MAX_ALTP2M);

    return v->domain->arch.altp2m_p2m[index];
}

/* set current alternate p2m table */
static inline bool p2m_set_altp2m(struct vcpu *v, unsigned int idx)
{
    struct p2m_domain *orig;

    BUG_ON(idx >= MAX_ALTP2M);

    if ( idx == vcpu_altp2m(v).p2midx )
        return false;

    orig = p2m_get_altp2m(v);
    BUG_ON(!orig);
    atomic_dec(&orig->active_vcpus);

    vcpu_altp2m(v).p2midx = idx;
    atomic_inc(&v->domain->arch.altp2m_p2m[idx]->active_vcpus);

    return true;
}

/* Switch alternate p2m for a single vcpu */
bool p2m_switch_vcpu_altp2m_by_id(struct vcpu *v, unsigned int idx);

/* Check to see if vcpu should be switched to a different p2m. */
void p2m_altp2m_check(struct vcpu *v, uint16_t idx);

/* Flush all the alternate p2m's for a domain */
void p2m_flush_altp2m(struct domain *d);

/* Alternate p2m paging */
bool p2m_altp2m_get_or_propagate(struct p2m_domain *ap2m, unsigned long gfn_l,
                                 mfn_t *mfn, p2m_type_t *p2mt,
                                 p2m_access_t *p2ma, unsigned int *page_order);

/* Make a specific alternate p2m valid */
int p2m_init_altp2m_by_id(struct domain *d, unsigned int idx);

/* Find an available alternate p2m and make it valid */
int p2m_init_next_altp2m(struct domain *d, uint16_t *idx,
                         xenmem_access_t hvmmem_default_access);

/* Make a specific alternate p2m invalid */
int p2m_destroy_altp2m_by_id(struct domain *d, unsigned int idx);

/* Switch alternate p2m for entire domain */
int p2m_switch_domain_altp2m_by_id(struct domain *d, unsigned int idx);

/* Change a gfn->mfn mapping */
int p2m_change_altp2m_gfn(struct domain *d, unsigned int idx,
                          gfn_t old_gfn, gfn_t new_gfn);

/* Propagate a host p2m change to all alternate p2m's */
int p2m_altp2m_propagate_change(struct domain *d, gfn_t gfn,
                                mfn_t mfn, unsigned int page_order,
                                p2m_type_t p2mt, p2m_access_t p2ma);

/* Set a specific p2m view visibility */
int p2m_set_altp2m_view_visibility(struct domain *d, unsigned int altp2m_idx,
                                   uint8_t visible);
#else /* !CONFIG_HVM */
struct p2m_domain *p2m_get_altp2m(struct vcpu *v);
static inline void p2m_altp2m_check(struct vcpu *v, uint16_t idx) {}
#endif /* CONFIG_HVM */

/* p2m access to IOMMU flags */
static inline unsigned int p2m_access_to_iommu_flags(p2m_access_t p2ma)
{
    switch ( p2ma )
    {
    case p2m_access_rw:
    case p2m_access_rwx:
        return IOMMUF_readable | IOMMUF_writable;

    case p2m_access_r:
    case p2m_access_rx:
    case p2m_access_rx2rw:
        return IOMMUF_readable;

    case p2m_access_w:
    case p2m_access_wx:
        return IOMMUF_writable;

    case p2m_access_n:
    case p2m_access_x:
    case p2m_access_n2rwx:
        return 0;
    }

    ASSERT_UNREACHABLE();
    return 0;
}

/*
 * p2m type to IOMMU flags
 */
static inline unsigned int p2m_get_iommu_flags(p2m_type_t p2mt,
                                               p2m_access_t p2ma, mfn_t mfn)
{
    unsigned int flags;

    switch( p2mt )
    {
    case p2m_ram_rw:
    case p2m_grant_map_rw:
    case p2m_ram_logdirty:
    case p2m_map_foreign:
        flags =  IOMMUF_readable | IOMMUF_writable;
        break;
    case p2m_ram_ro:
    case p2m_grant_map_ro:
        flags = IOMMUF_readable;
        break;
    case p2m_mmio_direct:
        flags = p2m_access_to_iommu_flags(p2ma);
        if ( (flags & IOMMUF_writable) &&
             rangeset_contains_singleton(mmio_ro_ranges, mfn_x(mfn)) )
            flags &= ~IOMMUF_writable;
        break;
    default:
        flags = 0;
        break;
    }

    return flags;
}

#ifdef CONFIG_HVM

int p2m_set_ioreq_server(struct domain *d, unsigned int flags,
                         struct ioreq_server *s);
struct ioreq_server *p2m_get_ioreq_server(struct domain *d,
                                          unsigned int *flags);

static inline int p2m_entry_modify(struct p2m_domain *p2m, p2m_type_t nt,
                                   p2m_type_t ot, mfn_t nfn, mfn_t ofn,
                                   unsigned int level)
{
    BUG_ON(!level);
    BUG_ON(level > 1 && (nt == p2m_ioreq_server || nt == p2m_map_foreign));

    if ( level != 1 || (nt == ot && mfn_eq(nfn, ofn)) )
        return 0;

    switch ( nt )
    {
    case p2m_ioreq_server:
        /*
         * p2m_ioreq_server is only used for 4K pages, so
         * the count is only done for level 1 entries.
         */
        p2m->ioreq.entry_count++;
        break;

    case p2m_map_foreign:
        if ( !mfn_valid(nfn) || p2m != p2m_get_hostp2m(p2m->domain) )
        {
            ASSERT_UNREACHABLE();
            return -EINVAL;
        }

        if ( !page_get_owner_and_reference(mfn_to_page(nfn)) )
            return -EBUSY;

        p2m->nr_foreign++;

        break;

    default:
        break;
    }

    switch ( ot )
    {
    case p2m_ioreq_server:
        ASSERT(p2m->ioreq.entry_count > 0);
        p2m->ioreq.entry_count--;
        break;

    case p2m_map_foreign:
        if ( !mfn_valid(ofn) || p2m != p2m_get_hostp2m(p2m->domain) )
        {
            ASSERT_UNREACHABLE();
            return -EINVAL;
        }
        put_page(mfn_to_page(ofn));
        p2m->nr_foreign--;
        break;

    default:
        break;
    }

    return 0;
}

#endif /* CONFIG_HVM */

#endif /* _XEN_ASM_X86_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
