
#ifndef __ASM_X86_MM_H__
#define __ASM_X86_MM_H__

#include <xen/config.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/perfc.h>
#include <xen/sched.h>

#include <asm/processor.h>
#include <asm/atomic.h>
#include <asm/desc.h>
#include <asm/flushtlb.h>
#include <asm/io.h>

#include <hypervisor-ifs/hypervisor-if.h>

/*
 * Per-page-frame information.
 * 
 * Every architecture must ensure the following:
 *  1. 'struct pfn_info' contains a 'struct list_head list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->u.free.order)

struct pfn_info
{
    /* Each frame can be threaded onto a doubly-linked list. */
    struct list_head list;

    /* Context-dependent fields follow... */
    union {

        /* Page is in use by a domain. */
        struct {
            /* Owner of this page. */
            struct domain *domain;
            /* Reference count and various PGC_xxx flags and fields. */
            u32 count_info;
            /* Type reference count and various PGT_xxx flags and fields. */
            u32 type_info;
        } inuse;

        /* Page is on a free list. */
        struct {
            /* Mask of possibly-tainted TLBs. */
            unsigned long cpu_mask;
            /* Must be at same offset as 'u.inuse.count_flags'. */
            u32 __unavailable;
            /* Order-size of the free chunk this page is the head of. */
            u8 order;
        } free;

    } u;

    /* Timestamp from 'TLB clock', used to reduce need for safety flushes. */
    u32 tlbflush_timestamp;
};

 /* The following page types are MUTUALLY EXCLUSIVE. */
#define PGT_none            (0<<29) /* no special uses of this page */
#define PGT_l1_page_table   (1<<29) /* using this page as an L1 page table? */
#define PGT_l2_page_table   (2<<29) /* using this page as an L2 page table? */
#define PGT_l3_page_table   (3<<29) /* using this page as an L3 page table? */
#define PGT_l4_page_table   (4<<29) /* using this page as an L4 page table? */
#define PGT_gdt_page        (5<<29) /* using this page in a GDT? */
#define PGT_ldt_page        (6<<29) /* using this page in an LDT? */
#define PGT_writable_page   (7<<29) /* has writable mappings of this page? */
#define PGT_type_mask       (7<<29) /* Bits 29-31. */
 /* Has this page been validated for use as its current type? */
#define _PGT_validated      28
#define PGT_validated       (1<<_PGT_validated)
 /* 10-bit most significant bits of va address if used as l1 page table */
#define PGT_va_shift        18
#define PGT_va_mask         (((1<<10)-1)<<PGT_va_shift)
 /* 18-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1<<18)-1)

 /* For safety, force a TLB flush when this page's type changes. */
#define _PGC_tlb_flush_on_type_change 31
#define PGC_tlb_flush_on_type_change  (1<<_PGC_tlb_flush_on_type_change)
 /* Owning guest has pinned this page to its current type? */
#define _PGC_guest_pinned             30
#define PGC_guest_pinned              (1<<_PGC_guest_pinned)
 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated                29
#define PGC_allocated                 (1<<_PGC_allocated)
 /* 28-bit count of references to this frame. */
#define PGC_count_mask                ((1<<29)-1)


/* We trust the slab allocator in slab.c, and our use of it. */
#define PageSlab(page)		(1)
#define PageSetSlab(page)	((void)0)
#define PageClearSlab(page)	((void)0)

#define IS_XEN_HEAP_FRAME(_pfn) (page_to_phys(_pfn) < xenheap_phys_end)

#define SHARE_PFN_WITH_DOMAIN(_pfn, _dom)                                   \
    do {                                                                    \
        (_pfn)->u.inuse.domain = (_dom);                                    \
        /* The incremented type count is intended to pin to 'writable'. */  \
        (_pfn)->u.inuse.type_info  = PGT_writable_page | PGT_validated | 1; \
        wmb(); /* install valid domain ptr before updating refcnt. */       \
        spin_lock(&(_dom)->page_alloc_lock);                                \
        /* _dom holds an allocation reference */                            \
        (_pfn)->u.inuse.count_info = PGC_allocated | 1;                     \
        if ( unlikely((_dom)->xenheap_pages++ == 0) )                       \
            get_knownalive_domain(_dom);                                    \
        list_add_tail(&(_pfn)->list, &(_dom)->xenpage_list);                \
        spin_unlock(&(_dom)->page_alloc_lock);                              \
    } while ( 0 )

extern struct pfn_info *frame_table;
extern unsigned long frame_table_size;
extern unsigned long max_page;
void init_frametable(void *frametable_vstart, unsigned long nr_pages);

int alloc_page_type(struct pfn_info *page, unsigned int type);
void free_page_type(struct pfn_info *page, unsigned int type);

static inline void put_page(struct pfn_info *page)
{
    u32 nx, x, y = page->u.inuse.count_info;

    do {
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
        free_domheap_page(page);
}


static inline int get_page(struct pfn_info *page,
                           struct domain *domain)
{
    u32 x, nx, y = page->u.inuse.count_info;
    struct domain *p, *np = page->u.inuse.domain;

    do {
        x  = y;
        nx = x + 1;
        p  = np;
        if ( unlikely((x & PGC_count_mask) == 0) ||  /* Not allocated? */
             unlikely((nx & PGC_count_mask) == 0) || /* Count overflow? */
             unlikely(p != domain) )                 /* Wrong owner? */
        {
            DPRINTK("Error pfn %08lx: ed=%p(%u), sd=%p(%u),"
                    " caf=%08x, taf=%08x\n",
                    page_to_pfn(page), domain, domain->domain,
                    p, (p && !((x & PGC_count_mask) == 0))?p->domain:999, 
                    x, page->u.inuse.type_info);
            return 0;
        }
        __asm__ __volatile__(
            LOCK_PREFIX "cmpxchg8b %3"
            : "=a" (np), "=d" (y), "=b" (p),
              "=m" (*(volatile u64 *)(&page->u.inuse.domain))
            : "0" (p), "1" (x), "b" (p), "c" (nx) );
    }
    while ( unlikely(np != p) || unlikely(y != x) );

    return 1;
}


static inline void put_page_type(struct pfn_info *page)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x - 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            page->tlbflush_timestamp = tlbflush_clock;
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & PGT_validated) )
            {
                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and the
                 * validated bit is clear => other ops will spin or fail.
                 */
                if ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, 
                                           x & ~PGT_validated)) != x) )
                    goto again;
                /* We cleared the 'valid bit' so we must do the clear up. */
                free_page_type(page, x & PGT_type_mask);
                /* Carry on as we were, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
            }
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


static inline int get_page_type(struct pfn_info *page, u32 type)
{
    u32 nx, x, y = page->u.inuse.type_info;
 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            DPRINTK("Type count overflow on pfn %08lx\n", page_to_pfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & PGT_type_mask) != type )
            {
                nx &= ~(PGT_type_mask | PGT_validated);
                nx |= type;
                /* No extra validation needed for writable pages. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else if ( unlikely((x & PGT_type_mask) != type) )
        {
            DPRINTK("Unexpected type (saw %08x != exp %08x) for pfn %08lx\n",
                    x & PGT_type_mask, type, page_to_pfn(page));
            return 0;
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            /* Someone else is updating validation of this page. Wait... */
            while ( (y = page->u.inuse.type_info) != x )
            {
                rep_nop();
                barrier();
            }
            goto again;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type)) )
        {
            DPRINTK("Error while validating pfn %08lx for type %08x."
                    " caf=%08x taf=%08x\n",
                    page_to_pfn(page), type,
		    page->u.inuse.count_info,
		    page->u.inuse.type_info);
            put_page_type(page);
            return 0;
        }
        set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}


static inline void put_page_and_type(struct pfn_info *page)
{
    put_page_type(page);
    put_page(page);
}


static inline int get_page_and_type(struct pfn_info *page,
                                    struct domain *domain,
                                    u32 type)
{
    int rc = get_page(page, domain);

    if ( likely(rc) && unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        rc = 0;
    }

    return rc;
}

#define ASSERT_PAGE_IS_TYPE(_p, _t)                            \
    ASSERT(((_p)->u.inuse.type_info & PGT_type_mask) == (_t)); \
    ASSERT(((_p)->u.inuse.type_info & PGT_count_mask) != 0)
#define ASSERT_PAGE_IS_DOMAIN(_p, _d)                          \
    ASSERT(((_p)->u.inuse.count_info & PGC_count_mask) != 0);  \
    ASSERT((_p)->u.inuse.domain == (_d))

int check_descriptor(unsigned long *d);

/*
 * Use currently-executing domain's pagetables on the specified CPUs.
 * i.e., stop borrowing someone else's tables if you are the idle domain.
 */
void synchronise_pagetables(unsigned long cpu_mask);

/*
 * The MPT (machine->physical mapping table) is an array of word-sized
 * values, indexed on machine frame number. It is expected that guest OSes
 * will use it to store a "physical" frame number to give the appearance of
 * contiguous (or near contiguous) physical memory.
 */
#undef  machine_to_phys_mapping
#ifdef __x86_64__
extern unsigned long *machine_to_phys_mapping;
#else
#define machine_to_phys_mapping ((unsigned long *)RDWR_MPT_VIRT_START)
#endif

/* Part of the domain API. */
int do_mmu_update(mmu_update_t *updates, int count, int *success_count);

#define DEFAULT_GDT_ENTRIES     (LAST_RESERVED_GDT_ENTRY+1)
#define DEFAULT_GDT_ADDRESS     ((unsigned long)gdt_table)

#ifdef MEMORY_GUARD
void *memguard_init(void *heap_start);
void memguard_guard_range(void *p, unsigned long l);
void memguard_unguard_range(void *p, unsigned long l);
int memguard_is_guarded(void *p);
#else
#define memguard_init(_s)              (_s)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)
#define memguard_is_guarded(_p)        (0)
#endif


typedef struct {
    void	(*enable)(void);
    void	(*disable)(void);
} vm_assist_info_t;
extern vm_assist_info_t vm_assist_info[];


/* Writable Pagetables */
#define	PTWR_NR_WRITABLES 1
typedef struct {
    unsigned long disconnected;
    l1_pgentry_t disconnected_page[ENTRIES_PER_L1_PAGETABLE];
    unsigned long writable_l1;
    unsigned long writables[PTWR_NR_WRITABLES];
    int writable_idx;
    l1_pgentry_t writable_page[PTWR_NR_WRITABLES][ENTRIES_PER_L1_PAGETABLE];
#ifdef PTWR_TRACK_DOMAIN
    domid_t domain;
#endif
} __cacheline_aligned ptwr_info_t;

extern ptwr_info_t ptwr_info[];

#define PTWR_CLEANUP_ACTIVE	1
#define PTWR_CLEANUP_INACTIVE	2

void ptwr_reconnect_disconnected(unsigned long addr);
void ptwr_flush_inactive(void);
int ptwr_do_page_fault(unsigned long);

static always_inline void 
__cleanup_writable_pagetable(
    const int what)
{
    int cpu = smp_processor_id();

    if (what & PTWR_CLEANUP_ACTIVE)
        if (ptwr_info[cpu].disconnected != ENTRIES_PER_L2_PAGETABLE)
            ptwr_reconnect_disconnected(0L);
    if (what & PTWR_CLEANUP_INACTIVE)
        if (ptwr_info[cpu].writable_idx)
            ptwr_flush_inactive();
}

static always_inline void
cleanup_writable_pagetable(
    struct domain *d, const int what)
{
    if ( unlikely(VM_ASSIST(d, VMASST_TYPE_writable_pagetables)) )
        __cleanup_writable_pagetable(what);
}

#endif /* __ASM_X86_MM_H__ */
