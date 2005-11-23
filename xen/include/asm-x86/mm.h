
#ifndef __ASM_X86_MM_H__
#define __ASM_X86_MM_H__

#include <xen/config.h>
#include <xen/cpumask.h>
#include <xen/list.h>
#include <asm/io.h>
#include <asm/uaccess.h>

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

    /* Reference count and various PGC_xxx flags and fields. */
    u32 count_info;

    /* Context-dependent fields follow... */
    union {

        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Owner of this page (NULL if page is anonymous). */
            u32 _domain; /* pickled format */
            /* Type reference count and various PGT_xxx flags and fields. */
            unsigned long type_info;
        } __attribute__ ((packed)) inuse;

        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        struct {
            /* Order-size of the free chunk this page is the head of. */
            u32 order;
            /* Mask of possibly-tainted TLBs. */
            cpumask_t cpumask;
        } __attribute__ ((packed)) free;

    } u;

    /* Timestamp from 'TLB clock', used to reduce need for safety flushes. */
    u32 tlbflush_timestamp;
};

 /* The following page types are MUTUALLY EXCLUSIVE. */
#define PGT_none            (0U<<29) /* no special uses of this page */
#define PGT_l1_page_table   (1U<<29) /* using this page as an L1 page table? */
#define PGT_l2_page_table   (2U<<29) /* using this page as an L2 page table? */
#define PGT_l3_page_table   (3U<<29) /* using this page as an L3 page table? */
#define PGT_l4_page_table   (4U<<29) /* using this page as an L4 page table? */
#define PGT_gdt_page        (5U<<29) /* using this page in a GDT? */
#define PGT_ldt_page        (6U<<29) /* using this page in an LDT? */
#define PGT_writable_page   (7U<<29) /* has writable mappings of this page? */

#define PGT_l1_shadow       PGT_l1_page_table
#define PGT_l2_shadow       PGT_l2_page_table
#define PGT_l3_shadow       PGT_l3_page_table
#define PGT_l4_shadow       PGT_l4_page_table
#define PGT_hl2_shadow      (5U<<29)
#define PGT_snapshot        (6U<<29)
#define PGT_writable_pred   (7U<<29) /* predicted gpfn with writable ref */

#define PGT_fl1_shadow      (5U<<29)
#define PGT_type_mask       (7U<<29) /* Bits 29-31. */

 /* Has this page been validated for use as its current type? */
#define _PGT_validated      28
#define PGT_validated       (1U<<_PGT_validated)
 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         27
#define PGT_pinned          (1U<<_PGT_pinned)
#if defined(__i386__)
 /* The 11 most significant bits of virt address if this is a page table. */
#define PGT_va_shift        16
#define PGT_va_mask         (((1U<<11)-1)<<PGT_va_shift)
 /* Is the back pointer still mutable (i.e. not fixed yet)? */
#define PGT_va_mutable      (((1U<<11)-1)<<PGT_va_shift)
 /* Is the back pointer unknown (e.g., p.t. is mapped at multiple VAs)? */
#define PGT_va_unknown      (((1U<<11)-2)<<PGT_va_shift)
#elif defined(__x86_64__)
 /* The 27 most significant bits of virt address if this is a page table. */
#define PGT_va_shift        32
#define PGT_va_mask         ((unsigned long)((1U<<28)-1)<<PGT_va_shift)
 /* Is the back pointer still mutable (i.e. not fixed yet)? */
#define PGT_va_mutable      ((unsigned long)((1U<<28)-1)<<PGT_va_shift)
 /* Is the back pointer unknown (e.g., p.t. is mapped at multiple VAs)? */
#define PGT_va_unknown      ((unsigned long)((1U<<28)-2)<<PGT_va_shift)
#endif

 /* 16-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<16)-1)

 /* 23-bit mfn mask for shadow types: good for up to 32GB RAM. */
#define PGT_mfn_mask        ((1U<<23)-1)

#define PGT_score_shift     23
#define PGT_score_mask      (((1U<<4)-1)<<PGT_score_shift)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* Set when fullshadow mode marks a page out-of-sync */
#define _PGC_out_of_sync     30
#define PGC_out_of_sync     (1U<<_PGC_out_of_sync)
 /* Set when fullshadow mode is using a page as a page table */
#define _PGC_page_table      29
#define PGC_page_table      (1U<<_PGC_page_table)
 /* 29-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<29)-1)

/* We trust the slab allocator in slab.c, and our use of it. */
#define PageSlab(page)	    (1)
#define PageSetSlab(page)   ((void)0)
#define PageClearSlab(page) ((void)0)

#define IS_XEN_HEAP_FRAME(_pfn) (page_to_phys(_pfn) < xenheap_phys_end)

#if defined(__i386__)
#define pickle_domptr(_d)   ((u32)(unsigned long)(_d))
#define unpickle_domptr(_d) ((struct domain *)(unsigned long)(_d))
#define PRtype_info "08lx" /* should only be used for printk's */
#elif defined(__x86_64__)
static inline struct domain *unpickle_domptr(u32 _domain)
{ return (_domain == 0) ? NULL : __va(_domain); }
static inline u32 pickle_domptr(struct domain *domain)
{ return (domain == NULL) ? 0 : (u32)__pa(domain); }
#define PRtype_info "016lx"/* should only be used for printk's */
#endif

#define page_get_owner(_p)    (unpickle_domptr((_p)->u.inuse._domain))
#define page_set_owner(_p,_d) ((_p)->u.inuse._domain = pickle_domptr(_d))

#define SHARE_PFN_WITH_DOMAIN(_pfn, _dom)                                   \
    do {                                                                    \
        page_set_owner((_pfn), (_dom));                                     \
        /* The incremented type count is intended to pin to 'writable'. */  \
        (_pfn)->u.inuse.type_info = PGT_writable_page | PGT_validated | 1;  \
        wmb(); /* install valid domain ptr before updating refcnt. */       \
        spin_lock(&(_dom)->page_alloc_lock);                                \
        /* _dom holds an allocation reference */                            \
        ASSERT((_pfn)->count_info == 0);                                    \
        (_pfn)->count_info |= PGC_allocated | 1;                            \
        if ( unlikely((_dom)->xenheap_pages++ == 0) )                       \
            get_knownalive_domain(_dom);                                    \
        list_add_tail(&(_pfn)->list, &(_dom)->xenpage_list);                \
        spin_unlock(&(_dom)->page_alloc_lock);                              \
    } while ( 0 )

extern struct pfn_info *frame_table;
extern unsigned long max_page;
extern unsigned long total_pages;
void init_frametable(void);

int alloc_page_type(struct pfn_info *page, unsigned long type);
void free_page_type(struct pfn_info *page, unsigned long type);
extern void invalidate_shadow_ldt(struct vcpu *d);
extern int shadow_remove_all_write_access(
    struct domain *d, unsigned long gpfn, unsigned long gmfn);
extern u32 shadow_remove_all_access( struct domain *d, unsigned long gmfn);
extern int _shadow_mode_refcounts(struct domain *d);

static inline void put_page(struct pfn_info *page)
{
    u32 nx, x, y = page->count_info;

    do {
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
        free_domheap_page(page);
}


static inline int get_page(struct pfn_info *page,
                           struct domain *domain)
{
    u32 x, nx, y = page->count_info;
    u32 d, nd = page->u.inuse._domain;
    u32 _domain = pickle_domptr(domain);

    do {
        x  = y;
        nx = x + 1;
        d  = nd;
        if ( unlikely((x & PGC_count_mask) == 0) ||  /* Not allocated? */
             unlikely((nx & PGC_count_mask) == 0) || /* Count overflow? */
             unlikely(d != _domain) )                /* Wrong owner? */
        {
            if ( !_shadow_mode_refcounts(domain) )
                DPRINTK("Error pfn %lx: rd=%p, od=%p, caf=%08x, taf=%" PRtype_info "\n",
                        page_to_pfn(page), domain, unpickle_domptr(d),
                        x, page->u.inuse.type_info);
            return 0;
        }
        __asm__ __volatile__(
            LOCK_PREFIX "cmpxchg8b %3"
            : "=d" (nd), "=a" (y), "=c" (d),
              "=m" (*(volatile u64 *)(&page->count_info))
            : "0" (d), "1" (x), "c" (d), "b" (nx) );
    }
    while ( unlikely(nd != d) || unlikely(y != x) );

    return 1;
}

void put_page_type(struct pfn_info *page);
int  get_page_type(struct pfn_info *page, unsigned long type);
int  get_page_from_l1e(l1_pgentry_t l1e, struct domain *d);
void put_page_from_l1e(l1_pgentry_t l1e, struct domain *d);

static inline void put_page_and_type(struct pfn_info *page)
{
    put_page_type(page);
    put_page(page);
}


static inline int get_page_and_type(struct pfn_info *page,
                                    struct domain *domain,
                                    unsigned long type)
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
    ASSERT(((_p)->count_info & PGC_count_mask) != 0);          \
    ASSERT(page_get_owner(_p) == (_d))

int check_descriptor(struct desc_struct *d);

/*
 * The MPT (machine->physical mapping table) is an array of word-sized
 * values, indexed on machine frame number. It is expected that guest OSes
 * will use it to store a "physical" frame number to give the appearance of
 * contiguous (or near contiguous) physical memory.
 */
#undef  machine_to_phys_mapping
#define machine_to_phys_mapping  ((unsigned long *)RDWR_MPT_VIRT_START)
#define INVALID_M2P_ENTRY        (~0UL)
#define VALID_M2P(_e)            (!((_e) & (1UL<<(BITS_PER_LONG-1))))
#define IS_INVALID_M2P_ENTRY(_e) (!VALID_M2P(_e))

#define set_pfn_from_mfn(mfn, pfn) (machine_to_phys_mapping[(mfn)] = (pfn))
#define get_pfn_from_mfn(mfn)      (machine_to_phys_mapping[(mfn)])

/*
 * The phys_to_machine_mapping is the reversed mapping of MPT for full
 * virtualization.  It is only used by shadow_mode_translate()==true
 * guests, so we steal the address space that would have normally
 * been used by the read-only MPT map.
 */
#define phys_to_machine_mapping ((unsigned long *)RO_MPT_VIRT_START)
#define INVALID_MFN             (~0UL)
#define VALID_MFN(_mfn)         (!((_mfn) & (1U<<31)))

#define set_mfn_from_pfn(pfn, mfn) (phys_to_machine_mapping[(pfn)] = (mfn))
static inline unsigned long get_mfn_from_pfn(unsigned long pfn) 
{
    unsigned long mfn;
    l1_pgentry_t pte;

    if ( (__copy_from_user(&pte, &phys_to_machine_mapping[pfn],
                           sizeof(pte)) == 0) &&
         (l1e_get_flags(pte) & _PAGE_PRESENT) )
	mfn = l1e_get_pfn(pte);
    else
	mfn = INVALID_MFN;
    
    return mfn; 
}

#ifdef MEMORY_GUARD
void memguard_init(void);
void memguard_guard_range(void *p, unsigned long l);
void memguard_unguard_range(void *p, unsigned long l);
#else
#define memguard_init()                ((void)0)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)
#endif

void memguard_guard_stack(void *p);

/* Writable Pagetables */
struct ptwr_info {
    /* Linear address where the guest is updating the p.t. page. */
    unsigned long l1va;
    /* Copy of the p.t. page, taken before guest is given write access. */
    l1_pgentry_t *page;
    /* A temporary Xen mapping of the actual p.t. page. */
    l1_pgentry_t *pl1e;
    /* Index in L2 page table where this L1 p.t. is always hooked. */
    unsigned int l2_idx; /* NB. Only used for PTWR_PT_ACTIVE. */
    /* Info about last ptwr update batch. */
    unsigned int prev_nr_updates;
    /* Exec domain which created writable mapping. */
    struct vcpu *vcpu;
    /* EIP of the address which took the original write fault
       used for stats collection only */
    unsigned long eip;
};

#define PTWR_PT_ACTIVE 0
#define PTWR_PT_INACTIVE 1

#define PTWR_CLEANUP_ACTIVE 1
#define PTWR_CLEANUP_INACTIVE 2

int  ptwr_init(struct domain *);
void ptwr_destroy(struct domain *);
void ptwr_flush(struct domain *, const int);
int  ptwr_do_page_fault(struct domain *, unsigned long, 
			struct cpu_user_regs *);
int  revalidate_l1(struct domain *, l1_pgentry_t *, l1_pgentry_t *);

void cleanup_writable_pagetable(struct domain *d);
#define sync_pagetable_state(d)                 \
    do {                                        \
        LOCK_BIGLOCK(d);                        \
        cleanup_writable_pagetable(d);          \
        UNLOCK_BIGLOCK(d);                      \
    } while ( 0 )

int audit_adjust_pgtables(struct domain *d, int dir, int noisy);

#ifndef NDEBUG

#define AUDIT_SHADOW_ALREADY_LOCKED ( 1u << 0 )
#define AUDIT_ERRORS_OK             ( 1u << 1 )
#define AUDIT_QUIET                 ( 1u << 2 )

void _audit_domain(struct domain *d, int flags);
#define audit_domain(_d) _audit_domain((_d), AUDIT_ERRORS_OK)
void audit_domains(void);

#else

#define _audit_domain(_d, _f) ((void)0)
#define audit_domain(_d)      ((void)0)
#define audit_domains()       ((void)0)

#endif

#ifdef PERF_ARRAYS

void ptwr_eip_stat_reset();
void ptwr_eip_stat_print();

#else

#define ptwr_eip_stat_reset() ((void)0)
#define ptwr_eip_stat_print() ((void)0)

#endif

int new_guest_cr3(unsigned long pfn);

void propagate_page_fault(unsigned long addr, u16 error_code);

extern int __sync_lazy_execstate(void);

#endif /* __ASM_X86_MM_H__ */
