#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/config.h>
#include <xen/mm.h>
#include <asm/hvm/vcpu.h>
#include <asm/hvm/domain.h>
#include <asm/e820.h>

struct trap_bounce {
    unsigned long  error_code;
    unsigned short flags; /* TBF_ */
    unsigned short cs;
    unsigned long  eip;
};

#define MAPHASH_ENTRIES 8
#define MAPHASH_HASHFN(pfn) ((pfn) & (MAPHASH_ENTRIES-1))
#define MAPHASHENT_NOTINUSE ((u16)~0U)
struct vcpu_maphash {
    struct vcpu_maphash_entry {
        unsigned long mfn;
        uint16_t      idx;
        uint16_t      refcnt;
    } hash[MAPHASH_ENTRIES];
} __cacheline_aligned;

#define MAPCACHE_ORDER   10
#define MAPCACHE_ENTRIES (1 << MAPCACHE_ORDER)
struct mapcache {
    /* The PTEs that provide the mappings, and a cursor into the array. */
    l1_pgentry_t *l1tab;
    unsigned int cursor;

    /* Protects map_domain_page(). */
    spinlock_t lock;

    /* Garbage mappings are flushed from TLBs in batches called 'epochs'. */
    unsigned int epoch, shadow_epoch[MAX_VIRT_CPUS];
    u32 tlbflush_timestamp;

    /* Which mappings are in use, and which are garbage to reap next epoch? */
    unsigned long inuse[BITS_TO_LONGS(MAPCACHE_ENTRIES)];
    unsigned long garbage[BITS_TO_LONGS(MAPCACHE_ENTRIES)];

    /* Lock-free per-VCPU hash of recently-used mappings. */
    struct vcpu_maphash vcpu_maphash[MAX_VIRT_CPUS];
};

extern void mapcache_init(struct domain *);

/* x86/64: toggle guest between kernel and user modes. */
extern void toggle_guest_mode(struct vcpu *);

/*
 * Initialise a hypercall-transfer page. The given pointer must be mapped
 * in Xen virtual address space (accesses are not validated or checked).
 */
extern void hypercall_page_initialise(struct domain *d, void *);

/************************************************/
/*          shadow paging extension             */
/************************************************/
struct shadow_domain {
    spinlock_t        lock;  /* shadow domain lock */
    int               locker; /* processor which holds the lock */
    const char       *locker_function; /* Func that took it */
    unsigned int      opt_flags;    /* runtime tunable optimizations on/off */
    struct list_head  pinned_shadows; 

    /* Memory allocation */
    struct list_head  freelists[SHADOW_MAX_ORDER + 1]; 
    struct list_head  p2m_freelist;
    unsigned int      total_pages;  /* number of pages allocated */
    unsigned int      free_pages;   /* number of pages on freelists */
    unsigned int      p2m_pages;    /* number of pages allocates to p2m */

    /* Shadow hashtable */
    struct shadow_page_info **hash_table;
    int hash_walking;  /* Some function is walking the hash table */

    /* Shadow log-dirty bitmap */
    unsigned long *dirty_bitmap;
    unsigned int dirty_bitmap_size;  /* in pages, bit per page */

    /* Shadow log-dirty mode stats */
    unsigned int fault_count;
    unsigned int dirty_count;
};

struct shadow_vcpu {
#if CONFIG_PAGING_LEVELS >= 3
    /* PAE guests: per-vcpu shadow top-level table */
    l3_pgentry_t l3table[4] __attribute__((__aligned__(32)));
    /* PAE guests: per-vcpu cache of the top-level *guest* entries */
    l3_pgentry_t gl3e[4] __attribute__((__aligned__(32)));
#endif
    /* Non-PAE guests: pointer to guest top-level pagetable */
    void *guest_vtable;
    /* Last MFN that we emulated a write to. */
    unsigned long last_emulated_mfn;
    /* MFN of the last shadow that we shot a writeable mapping in */
    unsigned long last_writeable_pte_smfn;
};

/************************************************/
/*       p2m handling                           */
/************************************************/

struct p2m_domain {
    /* Lock that protects updates to the p2m */
    spinlock_t         lock;
    int                locker;   /* processor which holds the lock */
    const char        *locker_function; /* Func that took it */
    
    /* Pages used to construct the p2m */
    struct list_head   pages;

    /* Functions to call to get or free pages for the p2m */
    struct page_info * (*alloc_page  )(struct domain *d);
    void               (*free_page   )(struct domain *d, 
                                       struct page_info *pg);

    /* Highest guest frame that's ever been mapped in the p2m */
    unsigned long max_mapped_pfn;
};

/************************************************/
/*       common paging data structure           */
/************************************************/
struct paging_domain {
    u32               mode;  /* flags to control paging operation */

    /* extension for shadow paging support */
    struct shadow_domain shadow;

    /* Other paging assistance code will have structs here */
};

struct paging_vcpu {
    /* Pointers to mode-specific entry points. */
    struct paging_mode *mode;
    /* HVM guest: paging enabled (CR0.PG)?  */
    unsigned int translate_enabled:1;

    /* paging support extension */
    struct shadow_vcpu shadow;
};

struct arch_domain
{
    l1_pgentry_t *mm_perdomain_pt;
#ifdef CONFIG_X86_64
    l2_pgentry_t *mm_perdomain_l2;
    l3_pgentry_t *mm_perdomain_l3;
#endif

#ifdef CONFIG_X86_32
    /* map_domain_page() mapping cache. */
    struct mapcache mapcache;
#endif

#ifdef CONFIG_COMPAT
    unsigned int hv_compat_vstart;
    l3_pgentry_t *mm_arg_xlat_l3;
#endif

    /* I/O-port admin-specified access capabilities. */
    struct rangeset *ioport_caps;

    struct hvm_domain hvm_domain;

    struct paging_domain paging;
    struct p2m_domain p2m ;

    /* Shadow translated domain: P2M mapping */
    pagetable_t phys_table;

    /* Pseudophysical e820 map (XENMEM_memory_map).  */
    struct e820entry e820[3];
    unsigned int nr_e820;
} __cacheline_aligned;

#ifdef CONFIG_X86_PAE
struct pae_l3_cache {
    /*
     * Two low-memory (<4GB) PAE L3 tables, used as fallback when the guest
     * supplies a >=4GB PAE L3 table. We need two because we cannot set up
     * an L3 table while we are currently running on it (without using
     * expensive atomic 64-bit operations).
     */
    l3_pgentry_t  table[2][4] __attribute__((__aligned__(32)));
    unsigned long high_mfn;  /* The >=4GB MFN being shadowed. */
    unsigned int  inuse_idx; /* Which of the two cache slots is in use? */
    spinlock_t    lock;
};
#define pae_l3_cache_init(c) spin_lock_init(&(c)->lock)
#else /* !CONFIG_X86_PAE */
struct pae_l3_cache { };
#define pae_l3_cache_init(c) ((void)0)
#endif

struct arch_vcpu
{
    /* Needs 16-byte aligment for FXSAVE/FXRSTOR. */
    struct vcpu_guest_context guest_context
    __attribute__((__aligned__(16)));

    struct pae_l3_cache pae_l3_cache;

    unsigned long      flags; /* TF_ */

    void (*schedule_tail) (struct vcpu *);

    void (*ctxt_switch_from) (struct vcpu *);
    void (*ctxt_switch_to) (struct vcpu *);

    /* Bounce information for propagating an exception to guest OS. */
    struct trap_bounce trap_bounce;

    /* I/O-port access bitmap. */
    XEN_GUEST_HANDLE(uint8_t) iobmp; /* Guest kernel virtual address of the bitmap. */
    int iobmp_limit;  /* Number of ports represented in the bitmap.  */
    int iopl;         /* Current IOPL for this VCPU. */

#ifdef CONFIG_X86_32
    struct desc_struct int80_desc;
#endif

    /* Virtual Machine Extensions */
    struct hvm_vcpu hvm_vcpu;

    /*
     * Every domain has a L1 pagetable of its own. Per-domain mappings
     * are put in this table (eg. the current GDT is mapped here).
     */
    l1_pgentry_t *perdomain_ptes;

#ifdef CONFIG_X86_64
    pagetable_t guest_table_user;       /* (MFN) x86/64 user-space pagetable */
#endif
    pagetable_t guest_table;            /* (MFN) guest notion of cr3 */
    /* guest_table holds a ref to the page, and also a type-count unless
     * shadow refcounts are in use */
    pagetable_t shadow_table[4];        /* (MFN) shadow(s) of guest */
    pagetable_t monitor_table;          /* (MFN) hypervisor PT (for HVM) */
    unsigned long cr3;           	    /* (MA) value to install in HW CR3 */

    /* Current LDT details. */
    unsigned long shadow_ldt_mapcnt;

    struct paging_vcpu paging;
} __cacheline_aligned;

/* shorthands to improve code legibility */
#define hvm_vmx         hvm_vcpu.u.vmx
#define hvm_svm         hvm_vcpu.u.svm

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
