
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
#include <asm/uaccess.h>

#include <public/xen.h>

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

    /* Timestamp from 'TLB clock', used to reduce need for safety flushes. */
    u32 tlbflush_timestamp;

    /* Reference count and various PGC_xxx flags and fields. */
    u32 count_info;

    /* Context-dependent fields follow... */
    union {

        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Owner of this page (NULL if page is anonymous). */
            u32 _domain; /* pickled format */
            /* Type reference count and various PGT_xxx flags and fields. */
            u32 type_info;
        } PACKED inuse;

        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        struct {
            /* Mask of possibly-tainted TLBs. */
            u32 cpu_mask;
            /* Order-size of the free chunk this page is the head of. */
            u8 order;
        } PACKED free;

    } PACKED u;

} PACKED;

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
#define PGT_validated       (1U<<_PGT_validated)
 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         27
#define PGT_pinned          (1U<<_PGT_pinned)
 /* The 10 most significant bits of virt address if this is a page table. */
#define PGT_va_shift        17
#define PGT_va_mask         (((1U<<10)-1)<<PGT_va_shift)
 /* Is the back pointer still mutable (i.e. not fixed yet)? */
#define PGT_va_mutable      (((1U<<10)-1)<<PGT_va_shift)
 /* Is the back pointer unknown (e.g., p.t. is mapped at multiple VAs)? */
#define PGT_va_unknown      (((1U<<10)-2)<<PGT_va_shift)
 /* 17-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<17)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* 31-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<31)-1)

/* We trust the slab allocator in slab.c, and our use of it. */
#define PageSlab(page)	    (1)
#define PageSetSlab(page)   ((void)0)
#define PageClearSlab(page) ((void)0)

#define IS_XEN_HEAP_FRAME(_pfn) (page_to_phys(_pfn) < xenheap_phys_end)

#if defined(__i386__)

#define pickle_domptr(_d)   ((u32)(unsigned long)(_d))
#define unpickle_domptr(_d) ((struct domain *)(unsigned long)(_d))

#elif defined(__x86_64__)
static inline struct domain *unpickle_domptr(u32 _domain)
{ return (_domain == 0) ? NULL : __va(_domain); }
static inline u32 pickle_domptr(struct domain *domain)
{ return (domain == NULL) ? 0 : (u32)__pa(domain); }

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

#define INVALID_P2M_ENTRY (~0UL)

extern struct pfn_info *frame_table;
extern unsigned long frame_table_size;
extern unsigned long max_page;
void init_frametable(void);

int alloc_page_type(struct pfn_info *page, unsigned int type);
void free_page_type(struct pfn_info *page, unsigned int type);

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
            DPRINTK("Error pfn %08lx: ed=%p, sd=%p, caf=%08x, taf=%08x\n",
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
int  get_page_type(struct pfn_info *page, u32 type);

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
    ASSERT(((_p)->count_info & PGC_count_mask) != 0);          \
    ASSERT(page_get_owner(_p) == (_d))

int check_descriptor(struct desc_struct *d);

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

/*
 * The phys_to_machine_mapping is the reversed mapping of MPT for full
 * virtualization.
 */
#undef  phys_to_machine_mapping

#define machine_to_phys_mapping ((unsigned long *)RDWR_MPT_VIRT_START)
#define __phys_to_machine_mapping ((unsigned long *)PERDOMAIN_VIRT_START)
/* Returns the machine physical */
static inline unsigned long phys_to_machine_mapping(unsigned long pfn) 
{
    unsigned long mfn;
    l1_pgentry_t pte;

   if (__get_user(l1_pgentry_val(pte), (__phys_to_machine_mapping + pfn))) {
       return 0;
   }
               
   mfn = l1_pgentry_to_phys(pte) >> PAGE_SHIFT;
   return mfn; 
}
#define set_machinetophys(_mfn, _pfn) machine_to_phys_mapping[(_mfn)] = (_pfn)

#define DEFAULT_GDT_ENTRIES     (LAST_RESERVED_GDT_ENTRY+1)
#define DEFAULT_GDT_ADDRESS     ((unsigned long)gdt_table)

#ifdef MEMORY_GUARD
void *memguard_init(void *heap_start);
void memguard_guard_stack(void *p);
void memguard_guard_range(void *p, unsigned long l);
void memguard_unguard_range(void *p, unsigned long l);
#else
#define memguard_init(_s)              (_s)
#define memguard_guard_stack(_p)       ((void)0)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)
#endif


typedef struct {
    void	(*enable)(struct domain *);
    void	(*disable)(struct domain *);
} vm_assist_info_t;
extern vm_assist_info_t vm_assist_info[];


/* Writable Pagetables */
typedef struct {
    /* Linear address where the guest is updating the p.t. page. */
    unsigned long l1va;
    /* Copy of the p.t. page, taken before guest is given write access. */
    l1_pgentry_t *page;
    /* A temporary Xen mapping of the actual p.t. page. */
    l1_pgentry_t *pl1e;
    /* Index in L2 page table where this L1 p.t. is always hooked. */
    unsigned int l2_idx; /* NB. Only used for PTWR_PT_ACTIVE. */
} ptwr_ptinfo_t;

typedef struct {
    ptwr_ptinfo_t ptinfo[2];
} __cacheline_aligned ptwr_info_t;

extern ptwr_info_t ptwr_info[];

#define PTWR_PT_ACTIVE 0
#define PTWR_PT_INACTIVE 1

#define PTWR_CLEANUP_ACTIVE 1
#define PTWR_CLEANUP_INACTIVE 2

void ptwr_flush(const int);
int ptwr_do_page_fault(unsigned long);

int new_guest_cr3(unsigned long pfn);

#define __cleanup_writable_pagetable(_what)                                 \
do {                                                                        \
    int cpu = smp_processor_id();                                           \
    if ((_what) & PTWR_CLEANUP_ACTIVE)                                      \
        if (ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va)                     \
            ptwr_flush(PTWR_PT_ACTIVE);                                     \
    if ((_what) & PTWR_CLEANUP_INACTIVE)                                    \
        if (ptwr_info[cpu].ptinfo[PTWR_PT_INACTIVE].l1va)                   \
            ptwr_flush(PTWR_PT_INACTIVE);                                   \
} while ( 0 )

#define cleanup_writable_pagetable(_d)                                    \
    do {                                                                  \
        if ( unlikely(VM_ASSIST((_d), VMASST_TYPE_writable_pagetables)) ) \
        __cleanup_writable_pagetable(PTWR_CLEANUP_ACTIVE |                \
                                     PTWR_CLEANUP_INACTIVE);              \
    } while ( 0 )

#ifndef NDEBUG
void audit_domain(struct domain *d);
void audit_domains(void);
#else
#define audit_domain(_d) ((void)0)
#define audit_domains()  ((void)0)
#endif

void propagate_page_fault(unsigned long addr, u16 error_code);

#endif /* __ASM_X86_MM_H__ */
