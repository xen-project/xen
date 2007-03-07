/*
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *                    dom0 vp model support
 */
#ifndef __ASM_IA64_MM_H__
#define __ASM_IA64_MM_H__

#include <xen/config.h>
#ifdef LINUX_2_6
#include <linux/gfp.h>
#endif
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/perfc.h>
#include <xen/sched.h>

#include <asm/processor.h>
#include <asm/atomic.h>
#include <asm/tlbflush.h>
#include <asm/flushtlb.h>
#include <asm/io.h>

#include <public/xen.h>

/*
 * The following is for page_alloc.c.
 */

typedef unsigned long page_flags_t;

/*
 * Per-page-frame information.
 * 
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct list_head list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn)	((_pfn)->u.free.order)

#define PRtype_info "016lx"

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

    /* Timestamp from 'TLB clock', used to reduce need for safety flushes. */
    u32 tlbflush_timestamp;

#if 0
// following added for Linux compiling
    page_flags_t flags;
    atomic_t _count;
    struct list_head lru;	// is this the same as above "list"?
#endif
};

#define set_page_count(p,v) 	atomic_set(&(p)->_count, v - 1)

/*
 * Still small set of flags defined by far on IA-64.
 * IA-64 should make it a definition same as x86_64.
 */
/* The following page types are MUTUALLY EXCLUSIVE. */
#define PGT_none            (0<<29) /* no special uses of this page */
#define PGT_l1_page_table   (1<<29) /* using this page as an L1 page table? */
#define PGT_l2_page_table   (2<<29) /* using this page as an L2 page table? */
#define PGT_l3_page_table   (3<<29) /* using this page as an L3 page table? */
#define PGT_l4_page_table   (4<<29) /* using this page as an L4 page table? */
 /* Value 5 reserved. See asm-x86/mm.h */
 /* Value 6 reserved. See asm-x86/mm.h */
#define PGT_writable_page   (7<<29) /* has writable mappings of this page? */
#define PGT_type_mask       (7<<29) /* Bits 29-31. */

 /* Has this page been validated for use as its current type? */
#define _PGT_validated      28
#define PGT_validated       (1<<_PGT_validated)
 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         27
#define PGT_pinned          (1U<<_PGT_pinned)

 /* 16-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<16)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* Bit 30 reserved. See asm-x86/mm.h */
 /* Bit 29 reserved. See asm-x86/mm.h */
 /* 29-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<29)-1)

#define IS_XEN_HEAP_FRAME(_pfn) ((page_to_maddr(_pfn) < xenheap_phys_end) \
				 && (page_to_maddr(_pfn) >= xen_pstart))

extern void *xen_heap_start;
#define __pickle(a)	((unsigned long)a - (unsigned long)xen_heap_start)
#define __unpickle(a)	(void *)(a + xen_heap_start)

static inline struct domain *unpickle_domptr(u64 _d)
{ return (_d == 0) ? NULL : __unpickle(_d); }
static inline u32 pickle_domptr(struct domain *_d)
{ return (_d == NULL) ? 0 : (u32)__pickle(_d); }

#define page_get_owner(_p)	(unpickle_domptr((_p)->u.inuse._domain))
#define page_set_owner(_p, _d)	((_p)->u.inuse._domain = pickle_domptr(_d))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
void share_xen_page_with_guest(struct page_info *page,
                               struct domain *d, int readonly);
void share_xen_page_with_privileged_guests(struct page_info *page,
                                           int readonly);

extern struct page_info *frame_table;
extern unsigned long frame_table_size;
extern struct list_head free_list;
extern spinlock_t free_list_lock;
extern unsigned int free_pfns;
extern unsigned long max_page;

extern void __init init_frametable(void);
void add_to_domain_alloc_list(unsigned long ps, unsigned long pe);

static inline void put_page(struct page_info *page)
{
    u32 nx, x, y = page->count_info;

    do {
	x = y;
	nx = x - 1;
    }
    while (unlikely((y = cmpxchg_rel(&page->count_info, x, nx)) != x));

    if (unlikely((nx & PGC_count_mask) == 0))
	free_domheap_page(page);
}

/* count_info and ownership are checked atomically. */
static inline int get_page(struct page_info *page,
                           struct domain *domain)
{
    u64 x, nx, y = *((u64*)&page->count_info);
    u32 _domain = pickle_domptr(domain);

    do {
	x = y;
	nx = x + 1;
	if (unlikely((x & PGC_count_mask) == 0) ||	/* Not allocated? */
	    unlikely((nx & PGC_count_mask) == 0) ||	/* Count overflow? */
	    unlikely((x >> 32) != _domain)) {		/* Wrong owner? */

	    gdprintk(XENLOG_INFO, "Error pfn %lx: rd=%p, od=%p, caf=%016lx, taf=%"
		PRtype_info "\n", page_to_mfn(page), domain,
		unpickle_domptr(x >> 32), x, page->u.inuse.type_info);
	    return 0;
	}
    }
    while(unlikely((y = cmpxchg_acq((u64*)&page->count_info, x, nx)) != x));
    return 1;
}

extern void put_page_type(struct page_info *page);
extern int get_page_type(struct page_info *page, u32 type);

static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}


static inline int get_page_and_type(struct page_info *page,
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

static inline int page_is_removable(struct page_info *page)
{
    return ((page->count_info & PGC_count_mask) == 2);
}

#define	set_machinetophys(_mfn, _pfn) do { } while(0);

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

// prototype of misc memory stuff
//unsigned long __get_free_pages(unsigned int mask, unsigned int order);
//void __free_pages(struct page_info *page, unsigned int order);
void *pgtable_quicklist_alloc(void);
void pgtable_quicklist_free(void *pgtable_entry);

// FOLLOWING FROM linux-2.6.7/include/mm.h

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next;

	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	unsigned long vm_flags;		/* Flags, listed below. */

#ifndef XEN
	struct rb_node vm_rb;

// XEN doesn't need all the backing store stuff
	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	union {
		struct {
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;

		struct prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.  A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
#endif
};
/*
 * vm_flags..
 */
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_GROWSUP	0x00000200
#define VM_SHM		0x00000400	/* shared memory area, don't swap out */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

#define VM_EXECUTABLE	0x00001000
#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_RESERVED	0x00080000	/* Don't unmap it from swap_out */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_NONLINEAR	0x00800000	/* Is non-linear (remap_file_pages) */

#ifndef VM_STACK_DEFAULT_FLAGS		/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK_FLAGS	(VM_GROWSUP | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#else
#define VM_STACK_FLAGS	(VM_GROWSDOWN | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#endif

#if 0	/* removed when rebasing to 2.6.13 */
/*
 * The zone field is never updated after free_area_init_core()
 * sets it, so none of the operations on it need to be atomic.
 * We'll have up to (MAX_NUMNODES * MAX_NR_ZONES) zones total,
 * so we use (MAX_NODES_SHIFT + MAX_ZONES_SHIFT) here to get enough bits.
 */
#define NODEZONE_SHIFT (sizeof(page_flags_t)*8 - MAX_NODES_SHIFT - MAX_ZONES_SHIFT)
#define NODEZONE(node, zone)	((node << ZONES_SHIFT) | zone)

static inline unsigned long page_zonenum(struct page_info *page)
{
	return (page->flags >> NODEZONE_SHIFT) & (~(~0UL << ZONES_SHIFT));
}
static inline unsigned long page_to_nid(struct page_info *page)
{
	return (page->flags >> (NODEZONE_SHIFT + ZONES_SHIFT));
}

struct zone;
extern struct zone *zone_table[];

static inline struct zone *page_zone(struct page_info *page)
{
	return zone_table[page->flags >> NODEZONE_SHIFT];
}

static inline void set_page_zone(struct page_info *page, unsigned long nodezone_num)
{
	page->flags &= ~(~0UL << NODEZONE_SHIFT);
	page->flags |= nodezone_num << NODEZONE_SHIFT;
}
#endif

#ifndef CONFIG_DISCONTIGMEM          /* Don't use mapnrs, do it properly */
extern unsigned long max_mapnr;
#endif

static inline void *lowmem_page_address(struct page_info *page)
{
	return __va(page_to_mfn(page) << PAGE_SHIFT);
}

#if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
#define HASHED_PAGE_VIRTUAL
#endif

#if defined(WANT_PAGE_VIRTUAL)
#define page_address(page) ((page)->virtual)
#define set_page_address(page, address)			\
	do {						\
		(page)->virtual = (address);		\
	} while(0)
#define page_address_init()  do { } while(0)
#endif

#if defined(HASHED_PAGE_VIRTUAL)
void *page_address(struct page_info *page);
void set_page_address(struct page_info *page, void *virtual);
void page_address_init(void);
#endif

#if !defined(HASHED_PAGE_VIRTUAL) && !defined(WANT_PAGE_VIRTUAL)
#define page_address(page) lowmem_page_address(page)
#define set_page_address(page, address)  do { } while(0)
#define page_address_init()  do { } while(0)
#endif


#ifndef CONFIG_DEBUG_PAGEALLOC
static inline void
kernel_map_pages(struct page_info *page, int numpages, int enable)
{
}
#endif

extern unsigned long num_physpages;
extern unsigned long totalram_pages;
extern int nr_swap_pages;

extern void alloc_dom_xen_and_dom_io(void);
extern void mm_teardown(struct domain* d);
extern void mm_final_teardown(struct domain* d);
extern struct page_info * assign_new_domain_page(struct domain *d, unsigned long mpaddr);
extern void assign_new_domain0_page(struct domain *d, unsigned long mpaddr);
extern int __assign_domain_page(struct domain *d, unsigned long mpaddr, unsigned long physaddr, unsigned long flags);
extern void assign_domain_page(struct domain *d, unsigned long mpaddr, unsigned long physaddr);
extern void assign_domain_io_page(struct domain *d, unsigned long mpaddr, unsigned long flags);
struct p2m_entry;
extern unsigned long lookup_domain_mpa(struct domain *d, unsigned long mpaddr, struct p2m_entry* entry);
extern void *domain_mpa_to_imva(struct domain *d, unsigned long mpaddr);
extern volatile pte_t *lookup_noalloc_domain_pte(struct domain* d, unsigned long mpaddr);
extern unsigned long assign_domain_mmio_page(struct domain *d, unsigned long mpaddr, unsigned long phys_addr, unsigned long size, unsigned long flags);
extern unsigned long assign_domain_mach_page(struct domain *d, unsigned long mpaddr, unsigned long size, unsigned long flags);
int domain_page_mapped(struct domain *d, unsigned long mpaddr);
int efi_mmio(unsigned long physaddr, unsigned long size);
extern unsigned long ____lookup_domain_mpa(struct domain *d, unsigned long mpaddr);
extern unsigned long do_dom0vp_op(unsigned long cmd, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3);
extern unsigned long dom0vp_zap_physmap(struct domain *d, unsigned long gpfn, unsigned int extent_order);
extern unsigned long dom0vp_add_physmap(struct domain* d, unsigned long gpfn, unsigned long mfn, unsigned long flags, domid_t domid);
extern unsigned long dom0vp_add_physmap_with_gmfn(struct domain* d, unsigned long gpfn, unsigned long gmfn, unsigned long flags, domid_t domid);
#ifdef CONFIG_XEN_IA64_EXPOSE_P2M
extern void expose_p2m_init(void);
extern unsigned long dom0vp_expose_p2m(struct domain* d, unsigned long conv_start_gpfn, unsigned long assign_start_gpfn, unsigned long expose_size, unsigned long granule_pfn);
#else
#define expose_p2m_init()       do { } while (0)
#define dom0vp_expose_p2m(d, conv_start_gpfn, assign_start_gpfn, expose_size, granule_pfn)	(-ENOSYS)
#endif

extern volatile unsigned long *mpt_table;
extern unsigned long gmfn_to_mfn_foreign(struct domain *d, unsigned long gpfn);
extern u64 translate_domain_pte(u64 pteval, u64 address, u64 itir__, u64* logps, struct p2m_entry* entry);
#define machine_to_phys_mapping	mpt_table

#define INVALID_M2P_ENTRY        (~0UL)
#define VALID_M2P(_e)            (!((_e) & (1UL<<63)))

#define set_gpfn_from_mfn(mfn, pfn) (machine_to_phys_mapping[(mfn)] = (pfn))
#define get_gpfn_from_mfn(mfn)      (machine_to_phys_mapping[(mfn)])

/* If pmt table is provided by control pannel later, we need __get_user
* here. However if it's allocated by HV, we should access it directly
*/

#define mfn_to_gmfn(_d, mfn)			\
    get_gpfn_from_mfn(mfn)

#define gmfn_to_mfn(_d, gpfn)			\
    gmfn_to_mfn_foreign((_d), (gpfn))

#define __gpfn_invalid(_d, gpfn)			\
	(lookup_domain_mpa((_d), ((gpfn)<<PAGE_SHIFT), NULL) & GPFN_INV_MASK)

#define __gmfn_valid(_d, gpfn)	!__gpfn_invalid(_d, gpfn)

/* Return I/O type if trye */
#define __gpfn_is_io(_d, gpfn)				\
({                                          \
    u64 pte, ret=0;                                \
    pte = lookup_domain_mpa((_d), ((gpfn)<<PAGE_SHIFT), NULL);	\
    if(!(pte&GPFN_INV_MASK))        \
        ret = pte & GPFN_IO_MASK;        \
    ret;                \
})

#define __gpfn_is_mem(_d, gpfn)				\
({                                          \
    u64 pte, ret=0;                                \
    pte = lookup_domain_mpa((_d), ((gpfn)<<PAGE_SHIFT), NULL);		   \
    if((!(pte&GPFN_INV_MASK))&&((pte & GPFN_IO_MASK)==GPFN_MEM))   \
        ret = 1;             \
    ret;                \
})


#define __gpa_to_mpa(_d, gpa)   \
    ((gmfn_to_mfn((_d),(gpa)>>PAGE_SHIFT)<<PAGE_SHIFT)|((gpa)&~PAGE_MASK))

#define __mpa_to_gpa(madr) \
    ((get_gpfn_from_mfn((madr) >> PAGE_SHIFT) << PAGE_SHIFT) | \
    ((madr) & ~PAGE_MASK))

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags);

#define domain_clamp_alloc_bitsize(d, b) (b)

#endif /* __ASM_IA64_MM_H__ */
