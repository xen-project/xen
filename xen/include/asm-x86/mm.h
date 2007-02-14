
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
 *  1. 'struct page_info' contains a 'struct list_head list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->u.free.order)

struct page_info
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

    union {
        /*
         * Timestamp from 'TLB clock', used to avoid extra safety flushes.
         * Only valid for: a) free pages, and b) pages with zero type count
         * (except page table pages when the guest is in shadow mode).
         */
        u32 tlbflush_timestamp;

        /*
         * Guest pages with a shadow.  This does not conflict with
         * tlbflush_timestamp since page table pages are explicitly not
         * tracked for TLB-flush avoidance when a guest runs in shadow mode.
         */
        unsigned long shadow_flags;
    };
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
#define PGT_type_mask       (7U<<29) /* Bits 29-31. */

 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         28
#define PGT_pinned          (1U<<_PGT_pinned)
 /* Has this page been validated for use as its current type? */
#define _PGT_validated      27
#define PGT_validated       (1U<<_PGT_validated)
 /* PAE only: is this an L2 page directory containing Xen-private mappings? */
#define _PGT_pae_xen_l2     26
#define PGT_pae_xen_l2      (1U<<_PGT_pae_xen_l2)

 /* 16-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<16)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* Set on a *guest* page to mark it out-of-sync with its shadow */
#define _PGC_out_of_sync     30
#define PGC_out_of_sync     (1U<<_PGC_out_of_sync)
 /* Set when is using a page as a page table */
#define _PGC_page_table      29
#define PGC_page_table      (1U<<_PGC_page_table)
 /* 29-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<29)-1)

/* We trust the slab allocator in slab.c, and our use of it. */
#define PageSlab(page)	    (1)
#define PageSetSlab(page)   ((void)0)
#define PageClearSlab(page) ((void)0)

#define IS_XEN_HEAP_FRAME(_pfn) (page_to_maddr(_pfn) < xenheap_phys_end)

#if defined(__i386__)
#define pickle_domptr(_d)   ((u32)(unsigned long)(_d))
static inline struct domain *unpickle_domptr(u32 _domain)
{ return (_domain & 1) ? NULL : (void *)_domain; }
#define PRtype_info "08lx" /* should only be used for printk's */
#elif defined(__x86_64__)
static inline struct domain *unpickle_domptr(u32 _domain)
{ return ((_domain == 0) || (_domain & 1)) ? NULL : __va(_domain); }
static inline u32 pickle_domptr(struct domain *domain)
{ return (domain == NULL) ? 0 : (u32)__pa(domain); }
#define PRtype_info "016lx"/* should only be used for printk's */
#endif

/* The order of the largest allocation unit we use for shadow pages */
#if CONFIG_PAGING_LEVELS == 2
#define SHADOW_MAX_ORDER 0 /* Only ever need 4k allocations */
#else  
#define SHADOW_MAX_ORDER 2 /* Need up to 16k allocs for 32-bit on PAE/64 */
#endif

#define page_get_owner(_p)    (unpickle_domptr((_p)->u.inuse._domain))
#define page_set_owner(_p,_d) ((_p)->u.inuse._domain = pickle_domptr(_d))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
extern void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly);
extern void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly);

extern struct page_info *frame_table;
extern unsigned long max_page;
extern unsigned long total_pages;
void init_frametable(void);

int alloc_page_type(struct page_info *page, unsigned long type);
void free_page_type(struct page_info *page, unsigned long type);
void invalidate_shadow_ldt(struct vcpu *d);
int _shadow_mode_refcounts(struct domain *d);

static inline void put_page(struct page_info *page)
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


static inline int get_page(struct page_info *page,
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
                gdprintk(XENLOG_INFO,
                        "Error pfn %lx: rd=%p, od=%p, caf=%08x, taf=%"
                        PRtype_info "\n",
                        page_to_mfn(page), domain, unpickle_domptr(d),
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

void put_page_type(struct page_info *page);
int  get_page_type(struct page_info *page, unsigned long type);
int  get_page_from_l1e(l1_pgentry_t l1e, struct domain *d);
void put_page_from_l1e(l1_pgentry_t l1e, struct domain *d);

static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}


static inline int get_page_and_type(struct page_info *page,
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

static inline int page_is_removable(struct page_info *page)
{
    return ((page->count_info & PGC_count_mask) == 1);
}

#define ASSERT_PAGE_IS_TYPE(_p, _t)                            \
    ASSERT(((_p)->u.inuse.type_info & PGT_type_mask) == (_t)); \
    ASSERT(((_p)->u.inuse.type_info & PGT_count_mask) != 0)
#define ASSERT_PAGE_IS_DOMAIN(_p, _d)                          \
    ASSERT(((_p)->count_info & PGC_count_mask) != 0);          \
    ASSERT(page_get_owner(_p) == (_d))

// Quick test for whether a given page can be represented directly in CR3.
//
#if CONFIG_PAGING_LEVELS == 3
#define MFN_FITS_IN_CR3(_MFN) !(mfn_x(_MFN) >> 20)

/* returns a lowmem machine address of the copied L3 root table */
unsigned long
pae_copy_root(struct vcpu *v, l3_pgentry_t *l3tab);
#endif /* CONFIG_PAGING_LEVELS == 3 */

int check_descriptor(const struct domain *, struct desc_struct *d);


/******************************************************************************
 * With shadow pagetables, the different kinds of address start 
 * to get get confusing.
 * 
 * Virtual addresses are what they usually are: the addresses that are used 
 * to accessing memory while the guest is running.  The MMU translates from 
 * virtual addresses to machine addresses. 
 * 
 * (Pseudo-)physical addresses are the abstraction of physical memory the
 * guest uses for allocation and so forth.  For the purposes of this code, 
 * we can largely ignore them.
 *
 * Guest frame numbers (gfns) are the entries that the guest puts in its
 * pagetables.  For normal paravirtual guests, they are actual frame numbers,
 * with the translation done by the guest.  
 * 
 * Machine frame numbers (mfns) are the entries that the hypervisor puts
 * in the shadow page tables.
 *
 * Elsewhere in the xen code base, the name "gmfn" is generally used to refer
 * to a "machine frame number, from the guest's perspective", or in other
 * words, pseudo-physical frame numbers.  However, in the shadow code, the
 * term "gmfn" means "the mfn of a guest page"; this combines naturally with
 * other terms such as "smfn" (the mfn of a shadow page), gl2mfn (the mfn of a
 * guest L2 page), etc...
 */

/* With this defined, we do some ugly things to force the compiler to
 * give us type safety between mfns and gfns and other integers.
 * TYPE_SAFE(int foo) defines a foo_t, and _foo() and foo_x() functions 
 * that translate beween int and foo_t.
 * 
 * It does have some performance cost because the types now have 
 * a different storage attribute, so may not want it on all the time. */

#ifndef NDEBUG
#define TYPE_SAFETY 1
#endif

#ifdef TYPE_SAFETY
#define TYPE_SAFE(_type,_name)                                  \
typedef struct { _type _name; } _name##_t;                      \
static inline _name##_t _##_name(_type n) { return (_name##_t) { n }; } \
static inline _type _name##_x(_name##_t n) { return n._name; }
#else
#define TYPE_SAFE(_type,_name)                                          \
typedef _type _name##_t;                                                \
static inline _name##_t _##_name(_type n) { return n; }                 \
static inline _type _name##_x(_name##_t n) { return n; }
#endif

TYPE_SAFE(unsigned long,mfn);

/* Macro for printk formats: use as printk("%"PRI_mfn"\n", mfn_x(foo)); */
#define PRI_mfn "05lx"


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

#ifdef CONFIG_COMPAT
#define compat_machine_to_phys_mapping ((unsigned int *)RDWR_COMPAT_MPT_VIRT_START)
#define set_gpfn_from_mfn(mfn, pfn) \
    ((void)(compat_disabled || \
            (mfn) >= (RDWR_COMPAT_MPT_VIRT_END - RDWR_COMPAT_MPT_VIRT_START) / 4 || \
            (compat_machine_to_phys_mapping[(mfn)] = (unsigned int)(pfn))), \
     machine_to_phys_mapping[(mfn)] = (pfn))
#else
#define set_gpfn_from_mfn(mfn, pfn) (machine_to_phys_mapping[(mfn)] = (pfn))
#endif
#define get_gpfn_from_mfn(mfn)      (machine_to_phys_mapping[(mfn)])

#define mfn_to_gmfn(_d, mfn)                            \
    ( (paging_mode_translate(_d))                       \
      ? get_gpfn_from_mfn(mfn)                          \
      : (mfn) )

#define gmfn_to_mfn(_d, gpfn)  mfn_x(gfn_to_mfn(_d, gpfn))

#define INVALID_MFN             (~0UL)

#ifdef CONFIG_COMPAT
#define compat_pfn_to_cr3(pfn) (((unsigned)(pfn) << 12) | ((unsigned)(pfn) >> 20))
#define compat_cr3_to_pfn(cr3) (((unsigned)(cr3) >> 12) | ((unsigned)(cr3) << 20))
#endif

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

int  ptwr_do_page_fault(struct vcpu *, unsigned long,
                        struct cpu_user_regs *);

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

int new_guest_cr3(unsigned long pfn);
void make_cr3(struct vcpu *v, unsigned long mfn);
void update_cr3(struct vcpu *v);
void propagate_page_fault(unsigned long addr, u16 error_code);

int __sync_lazy_execstate(void);

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);
long subarch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);
#ifdef CONFIG_COMPAT
int compat_arch_memory_op(int op, XEN_GUEST_HANDLE(void));
int compat_subarch_memory_op(int op, XEN_GUEST_HANDLE(void));
#endif

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags);

int map_ldt_shadow_page(unsigned int);

#ifdef CONFIG_COMPAT
int setup_arg_xlat_area(struct vcpu *, l4_pgentry_t *);
#else
# define setup_arg_xlat_area(vcpu, l4tab) 0
#endif

#endif /* __ASM_X86_MM_H__ */
