/******************************************************************************
 * include/xen/mm.h
 *
 * Definitions for memory pages, frame numbers, addresses, allocations, etc.
 *
 * Copyright (c) 2002-2006, K A Fraser <keir@xensource.com>
 *
 *                         +---------------------+
 *                          Xen Memory Management
 *                         +---------------------+
 *
 * Xen has to handle many different address spaces.  It is important not to
 * get these spaces mixed up.  The following is a consistent terminology which
 * should be adhered to.
 *
 * mfn: Machine Frame Number
 *   The values Xen puts into its own pagetables.  This is the host physical
 *   memory address space with RAM, MMIO etc.
 *
 * gfn: Guest Frame Number
 *   The values a guest puts in its own pagetables.  For an auto-translated
 *   guest (hardware assisted with 2nd stage translation, or shadowed), gfn !=
 *   mfn.  For a non-translated guest which is aware of Xen, gfn == mfn.
 *
 * pfn: Pseudophysical Frame Number
 *   A linear idea of a guest physical address space. For an auto-translated
 *   guest, pfn == gfn while for a non-translated guest, pfn != gfn.
 *
 * WARNING: Some of these terms have changed over time while others have been
 * used inconsistently, meaning that a lot of existing code does not match the
 * definitions above.  New code should use these terms as described here, and
 * over time older code should be corrected to be consistent.
 *
 * An incomplete list of larger work area:
 * - Phase out the use of 'pfn' from the x86 pagetable code.  Callers should
 *   know explicitly whether they are talking about mfns or gfns.
 * - Phase out the use of 'pfn' from the ARM mm code.  A cursory glance
 *   suggests that 'mfn' and 'pfn' are currently used interchangeably, where
 *   'mfn' is the appropriate term to use.
 * - Phase out the use of gpfn/gmfn where pfn/mfn are meant.  This excludes
 *   the x86 shadow code, which uses gmfn/smfn pairs with different,
 *   documented, meanings.
 */

#ifndef __XEN_MM_H__
#define __XEN_MM_H__

#include <xen/compiler.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/typesafe.h>
#include <xen/kernel.h>
#include <xen/perfc.h>
#include <public/memory.h>

TYPE_SAFE(unsigned long, mfn);
#define PRI_mfn          "05lx"
#define INVALID_MFN      _mfn(~0UL)

#ifndef mfn_t
#define mfn_t /* Grep fodder: mfn_t, _mfn() and mfn_x() are defined above */
#undef mfn_t
#endif

static inline mfn_t mfn_add(mfn_t mfn, unsigned long i)
{
    return _mfn(mfn_x(mfn) + i);
}

static inline mfn_t mfn_max(mfn_t x, mfn_t y)
{
    return _mfn(max(mfn_x(x), mfn_x(y)));
}

static inline mfn_t mfn_min(mfn_t x, mfn_t y)
{
    return _mfn(min(mfn_x(x), mfn_x(y)));
}

static inline bool_t mfn_eq(mfn_t x, mfn_t y)
{
    return mfn_x(x) == mfn_x(y);
}

TYPE_SAFE(unsigned long, gfn);
#define PRI_gfn          "05lx"
#define INVALID_GFN      _gfn(~0UL)

#ifndef gfn_t
#define gfn_t /* Grep fodder: gfn_t, _gfn() and gfn_x() are defined above */
#undef gfn_t
#endif

static inline gfn_t gfn_add(gfn_t gfn, unsigned long i)
{
    return _gfn(gfn_x(gfn) + i);
}

static inline gfn_t gfn_max(gfn_t x, gfn_t y)
{
    return _gfn(max(gfn_x(x), gfn_x(y)));
}

static inline gfn_t gfn_min(gfn_t x, gfn_t y)
{
    return _gfn(min(gfn_x(x), gfn_x(y)));
}

static inline bool_t gfn_eq(gfn_t x, gfn_t y)
{
    return gfn_x(x) == gfn_x(y);
}

TYPE_SAFE(unsigned long, pfn);
#define PRI_pfn          "05lx"
#define INVALID_PFN      (~0UL)

#ifndef pfn_t
#define pfn_t /* Grep fodder: pfn_t, _pfn() and pfn_x() are defined above */
#undef pfn_t
#endif

struct page_info;

void put_page(struct page_info *);
int get_page(struct page_info *, struct domain *);
struct domain *__must_check page_get_owner_and_reference(struct page_info *);

/* Boot-time allocator. Turns into generic allocator after bootstrap. */
void init_boot_pages(paddr_t ps, paddr_t pe);
unsigned long alloc_boot_pages(
    unsigned long nr_pfns, unsigned long pfn_align);
void end_boot_allocator(void);

/* Xen suballocator. These functions are interrupt-safe. */
void init_xenheap_pages(paddr_t ps, paddr_t pe);
void xenheap_max_mfn(unsigned long mfn);
void *alloc_xenheap_pages(unsigned int order, unsigned int memflags);
void free_xenheap_pages(void *v, unsigned int order);
#define alloc_xenheap_page() (alloc_xenheap_pages(0,0))
#define free_xenheap_page(v) (free_xenheap_pages(v,0))
/* Map machine page range in Xen virtual address space. */
int map_pages_to_xen(
    unsigned long virt,
    unsigned long mfn,
    unsigned long nr_mfns,
    unsigned int flags);
/* Alter the permissions of a range of Xen virtual address space. */
int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int flags);
int destroy_xen_mappings(unsigned long v, unsigned long e);
/*
 * Create only non-leaf page table entries for the
 * page range in Xen virtual address space.
 */
int populate_pt_range(unsigned long virt, unsigned long mfn,
                      unsigned long nr_mfns);
/* Claim handling */
unsigned long domain_adjust_tot_pages(struct domain *d, long pages);
int domain_set_outstanding_pages(struct domain *d, unsigned long pages);
void get_outstanding_claims(uint64_t *free_pages, uint64_t *outstanding_pages);

/* Domain suballocator. These functions are *not* interrupt-safe.*/
void init_domheap_pages(paddr_t ps, paddr_t pe);
struct page_info *alloc_domheap_pages(
    struct domain *d, unsigned int order, unsigned int memflags);
void free_domheap_pages(struct page_info *pg, unsigned int order);
unsigned long avail_domheap_pages_region(
    unsigned int node, unsigned int min_width, unsigned int max_width);
unsigned long avail_domheap_pages(void);
unsigned long avail_node_heap_pages(unsigned int);
#define alloc_domheap_page(d,f) (alloc_domheap_pages(d,0,f))
#define free_domheap_page(p)  (free_domheap_pages(p,0))
unsigned int online_page(unsigned long mfn, uint32_t *status);
int offline_page(unsigned long mfn, int broken, uint32_t *status);
int query_page_offline(unsigned long mfn, uint32_t *status);
unsigned long total_free_pages(void);

void scrub_heap_pages(void);

int assign_pages(
    struct domain *d,
    struct page_info *pg,
    unsigned int order,
    unsigned int memflags);

/* Dump info to serial console */
void arch_dump_shared_mem_info(void);

/*
 * Extra fault info types which are used to further describe
 * the source of an access violation.
 */
typedef enum {
    npfec_kind_unknown, /* must be first */
    npfec_kind_in_gpt,  /* violation in guest page table */
    npfec_kind_with_gla /* violation with guest linear address */
} npfec_kind_t;

/*
 * Nested page fault exception codes.
 */
struct npfec {
    unsigned int read_access:1;
    unsigned int write_access:1;
    unsigned int insn_fetch:1;
    unsigned int present:1;
    unsigned int gla_valid:1;
    unsigned int kind:2;  /* npfec_kind_t */
};

/* memflags: */
#define _MEMF_no_refcount 0
#define  MEMF_no_refcount (1U<<_MEMF_no_refcount)
#define _MEMF_populate_on_demand 1
#define  MEMF_populate_on_demand (1U<<_MEMF_populate_on_demand)
#define _MEMF_tmem        2
#define  MEMF_tmem        (1U<<_MEMF_tmem)
#define _MEMF_no_dma      3
#define  MEMF_no_dma      (1U<<_MEMF_no_dma)
#define _MEMF_exact_node  4
#define  MEMF_exact_node  (1U<<_MEMF_exact_node)
#define _MEMF_no_owner    5
#define  MEMF_no_owner    (1U<<_MEMF_no_owner)
#define _MEMF_no_tlbflush 6
#define  MEMF_no_tlbflush (1U<<_MEMF_no_tlbflush)
#define _MEMF_node        8
#define  MEMF_node_mask   ((1U << (8 * sizeof(nodeid_t))) - 1)
#define  MEMF_node(n)     ((((n) + 1) & MEMF_node_mask) << _MEMF_node)
#define  MEMF_get_node(f) ((((f) >> _MEMF_node) - 1) & MEMF_node_mask)
#define _MEMF_bits        24
#define  MEMF_bits(n)     ((n)<<_MEMF_bits)

#ifdef CONFIG_PAGEALLOC_MAX_ORDER
#define MAX_ORDER CONFIG_PAGEALLOC_MAX_ORDER
#else
#define MAX_ORDER 20 /* 2^20 contiguous pages */
#endif

#define page_list_entry list_head

#include <asm/mm.h>

#ifndef page_list_entry
struct page_list_head
{
    struct page_info *next, *tail;
};
/* These must only have instances in struct page_info. */
# define page_list_entry

# define PAGE_LIST_NULL ((typeof(((struct page_info){}).list.next))~0)

# if !defined(pdx_to_page) && !defined(page_to_pdx)
#  if defined(__page_to_mfn) || defined(__mfn_to_page)
#   define page_to_pdx __page_to_mfn
#   define pdx_to_page __mfn_to_page
#  else
#   define page_to_pdx page_to_mfn
#   define pdx_to_page mfn_to_page
#  endif
# endif

# define PAGE_LIST_HEAD_INIT(name) { NULL, NULL }
# define PAGE_LIST_HEAD(name) \
    struct page_list_head name = PAGE_LIST_HEAD_INIT(name)
# define INIT_PAGE_LIST_HEAD(head) ((head)->tail = (head)->next = NULL)
# define INIT_PAGE_LIST_ENTRY(ent) ((ent)->prev = (ent)->next = PAGE_LIST_NULL)

static inline bool_t
page_list_empty(const struct page_list_head *head)
{
    return !head->next;
}
static inline struct page_info *
page_list_first(const struct page_list_head *head)
{
    return head->next;
}
static inline struct page_info *
page_list_last(const struct page_list_head *head)
{
    return head->tail;
}
static inline struct page_info *
page_list_next(const struct page_info *page,
               const struct page_list_head *head)
{
    return page != head->tail ? pdx_to_page(page->list.next) : NULL;
}
static inline struct page_info *
page_list_prev(const struct page_info *page,
               const struct page_list_head *head)
{
    return page != head->next ? pdx_to_page(page->list.prev) : NULL;
}
static inline void
page_list_add(struct page_info *page, struct page_list_head *head)
{
    if ( head->next )
    {
        page->list.next = page_to_pdx(head->next);
        head->next->list.prev = page_to_pdx(page);
    }
    else
    {
        head->tail = page;
        page->list.next = PAGE_LIST_NULL;
    }
    page->list.prev = PAGE_LIST_NULL;
    head->next = page;
}
static inline void
page_list_add_tail(struct page_info *page, struct page_list_head *head)
{
    page->list.next = PAGE_LIST_NULL;
    if ( head->next )
    {
        page->list.prev = page_to_pdx(head->tail);
        head->tail->list.next = page_to_pdx(page);
    }
    else
    {
        page->list.prev = PAGE_LIST_NULL;
        head->next = page;
    }
    head->tail = page;
}
static inline bool_t
__page_list_del_head(struct page_info *page, struct page_list_head *head,
                     struct page_info *next, struct page_info *prev)
{
    if ( head->next == page )
    {
        if ( head->tail != page )
        {
            next->list.prev = PAGE_LIST_NULL;
            head->next = next;
        }
        else
            head->tail = head->next = NULL;
        return 1;
    }

    if ( head->tail == page )
    {
        prev->list.next = PAGE_LIST_NULL;
        head->tail = prev;
        return 1;
    }

    return 0;
}
static inline void
page_list_del(struct page_info *page, struct page_list_head *head)
{
    struct page_info *next = pdx_to_page(page->list.next);
    struct page_info *prev = pdx_to_page(page->list.prev);

    if ( !__page_list_del_head(page, head, next, prev) )
    {
        next->list.prev = page->list.prev;
        prev->list.next = page->list.next;
    }
}
static inline void
page_list_del2(struct page_info *page, struct page_list_head *head1,
               struct page_list_head *head2)
{
    struct page_info *next = pdx_to_page(page->list.next);
    struct page_info *prev = pdx_to_page(page->list.prev);

    if ( !__page_list_del_head(page, head1, next, prev) &&
         !__page_list_del_head(page, head2, next, prev) )
    {
        next->list.prev = page->list.prev;
        prev->list.next = page->list.next;
    }
}
static inline struct page_info *
page_list_remove_head(struct page_list_head *head)
{
    struct page_info *page = head->next;

    if ( page )
        page_list_del(page, head);

    return page;
}
static inline void
page_list_move(struct page_list_head *dst, struct page_list_head *src)
{
    if ( !page_list_empty(src) )
    {
        *dst = *src;
        INIT_PAGE_LIST_HEAD(src);
    }
}
static inline void
page_list_splice(struct page_list_head *list, struct page_list_head *head)
{
    struct page_info *first, *last, *at;

    if ( page_list_empty(list) )
        return;

    if ( page_list_empty(head) )
    {
        head->next = list->next;
        head->tail = list->tail;
        return;
    }

    first = list->next;
    last = list->tail;
    at = head->next;

    ASSERT(first->list.prev == PAGE_LIST_NULL);
    ASSERT(first->list.prev == at->list.prev);
    head->next = first;

    last->list.next = page_to_pdx(at);
    at->list.prev = page_to_pdx(last);
}

#define page_list_for_each(pos, head) \
    for ( pos = (head)->next; pos; pos = page_list_next(pos, head) )
#define page_list_for_each_safe(pos, tmp, head) \
    for ( pos = (head)->next; \
          pos ? (tmp = page_list_next(pos, head), 1) : 0; \
          pos = tmp )
#define page_list_for_each_safe_reverse(pos, tmp, head) \
    for ( pos = (head)->tail; \
          pos ? (tmp = page_list_prev(pos, head), 1) : 0; \
          pos = tmp )
#else
# define page_list_head                  list_head
# define PAGE_LIST_HEAD_INIT             LIST_HEAD_INIT
# define PAGE_LIST_HEAD                  LIST_HEAD
# define INIT_PAGE_LIST_HEAD             INIT_LIST_HEAD
# define INIT_PAGE_LIST_ENTRY            INIT_LIST_HEAD

static inline bool_t
page_list_empty(const struct page_list_head *head)
{
    return !!list_empty(head);
}
static inline struct page_info *
page_list_first(const struct page_list_head *head)
{
    return list_first_entry(head, struct page_info, list);
}
static inline struct page_info *
page_list_last(const struct page_list_head *head)
{
    return list_last_entry(head, struct page_info, list);
}
static inline struct page_info *
page_list_next(const struct page_info *page,
               const struct page_list_head *head)
{
    return list_entry(page->list.next, struct page_info, list);
}
static inline struct page_info *
page_list_prev(const struct page_info *page,
               const struct page_list_head *head)
{
    return list_entry(page->list.prev, struct page_info, list);
}
static inline void
page_list_add(struct page_info *page, struct page_list_head *head)
{
    list_add(&page->list, head);
}
static inline void
page_list_add_tail(struct page_info *page, struct page_list_head *head)
{
    list_add_tail(&page->list, head);
}
static inline void
page_list_del(struct page_info *page, struct page_list_head *head)
{
    list_del(&page->list);
}
static inline void
page_list_del2(struct page_info *page, struct page_list_head *head1,
               struct page_list_head *head2)
{
    list_del(&page->list);
}
static inline struct page_info *
page_list_remove_head(struct page_list_head *head)
{
    struct page_info *pg;

    if ( page_list_empty(head) )
        return NULL;

    pg = page_list_first(head);
    list_del(&pg->list);
    return pg;
}
static inline void
page_list_move(struct page_list_head *dst, struct page_list_head *src)
{
    if ( !list_empty(src) )
        list_replace_init(src, dst);
}
static inline void
page_list_splice(struct page_list_head *list, struct page_list_head *head)
{
    list_splice(list, head);
}

# define page_list_for_each(pos, head)   list_for_each_entry(pos, head, list)
# define page_list_for_each_safe(pos, tmp, head) \
    list_for_each_entry_safe(pos, tmp, head, list)
# define page_list_for_each_safe_reverse(pos, tmp, head) \
    list_for_each_entry_safe_reverse(pos, tmp, head, list)
#endif

static inline unsigned int get_order_from_bytes(paddr_t size)
{
    unsigned int order;

    size = (size - 1) >> PAGE_SHIFT;
    for ( order = 0; size; order++ )
        size >>= 1;

    return order;
}

static inline unsigned int get_order_from_pages(unsigned long nr_pages)
{
    unsigned int order;

    nr_pages--;
    for ( order = 0; nr_pages; order++ )
        nr_pages >>= 1;

    return order;
}

void scrub_one_page(struct page_info *);

#ifndef arch_free_heap_page
#define arch_free_heap_page(d, pg)                      \
    page_list_del(pg, is_xen_heap_page(pg) ?            \
                      &(d)->xenpage_list : &(d)->page_list)
#endif

int xenmem_add_to_physmap_one(struct domain *d, unsigned int space,
                              union xen_add_to_physmap_batch_extra extra,
                              unsigned long idx, gfn_t gfn);

/* Returns 0 on success, or negative on error. */
int __must_check guest_remove_page(struct domain *d, unsigned long gmfn);

#define RAM_TYPE_CONVENTIONAL 0x00000001
#define RAM_TYPE_RESERVED     0x00000002
#define RAM_TYPE_UNUSABLE     0x00000004
#define RAM_TYPE_ACPI         0x00000008
/* TRUE if the whole page at @mfn is of the requested RAM type(s) above. */
int page_is_ram_type(unsigned long mfn, unsigned long mem_type);

/* Prepare/destroy a ring for a dom0 helper. Helper with talk
 * with Xen on behalf of this domain. */
int prepare_ring_for_helper(struct domain *d, unsigned long gmfn,
                            struct page_info **_page, void **_va);
void destroy_ring_for_helper(void **_va, struct page_info *page);

#include <asm/flushtlb.h>

static inline void accumulate_tlbflush(bool *need_tlbflush,
                                       const struct page_info *page,
                                       uint32_t *tlbflush_timestamp)
{
    if ( page->u.free.need_tlbflush &&
         page->tlbflush_timestamp <= tlbflush_current_time() &&
         (!*need_tlbflush ||
          page->tlbflush_timestamp > *tlbflush_timestamp) )
    {
        *need_tlbflush = true;
        *tlbflush_timestamp = page->tlbflush_timestamp;
    }
}

static inline void filtered_flush_tlb_mask(uint32_t tlbflush_timestamp)
{
    cpumask_t mask = cpu_online_map;

    tlbflush_filter(mask, tlbflush_timestamp);
    if ( !cpumask_empty(&mask) )
    {
        perfc_incr(need_flush_tlb_flush);
        flush_tlb_mask(&mask);
    }
}

#endif /* __XEN_MM_H__ */
