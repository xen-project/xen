#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/radix-tree.h>
#include <asm/hvm/vcpu.h>
#include <asm/hvm/domain.h>
#include <asm/e820.h>
#include <asm/mce.h>
#include <public/vcpu.h>

#define has_32bit_shinfo(d)    ((d)->arch.has_32bit_shinfo)
#define is_pv_32bit_domain(d)  ((d)->arch.is_32bit_pv)
#define is_pv_32bit_vcpu(v)    (is_pv_32bit_domain((v)->domain))
#define is_pv_32on64_domain(d) (is_pv_32bit_domain(d))
#define is_pv_32on64_vcpu(v)   (is_pv_32on64_domain((v)->domain))

#define is_hvm_pv_evtchn_domain(d) (has_hvm_container_domain(d) && \
        d->arch.hvm_domain.irq.callback_via_type == HVMIRQ_callback_vector)
#define is_hvm_pv_evtchn_vcpu(v) (is_hvm_pv_evtchn_domain(v->domain))
#define is_domain_direct_mapped(d) ((void)(d), 0)

#define VCPU_TRAP_NMI          1
#define VCPU_TRAP_MCE          2
#define VCPU_TRAP_LAST         VCPU_TRAP_MCE

#define nmi_state              async_exception_state(VCPU_TRAP_NMI)
#define mce_state              async_exception_state(VCPU_TRAP_MCE)

#define nmi_pending            nmi_state.pending
#define mce_pending            mce_state.pending

struct trap_bounce {
    uint32_t      error_code;
    uint8_t       flags; /* TBF_ */
    uint16_t      cs;
    unsigned long eip;
};

#define MAPHASH_ENTRIES 8
#define MAPHASH_HASHFN(pfn) ((pfn) & (MAPHASH_ENTRIES-1))
#define MAPHASHENT_NOTINUSE ((u32)~0U)
struct mapcache_vcpu {
    /* Shadow of mapcache_domain.epoch. */
    unsigned int shadow_epoch;

    /* Lock-free per-VCPU hash of recently-used mappings. */
    struct vcpu_maphash_entry {
        unsigned long mfn;
        uint32_t      idx;
        uint32_t      refcnt;
    } hash[MAPHASH_ENTRIES];
};

struct mapcache_domain {
    /* The number of array entries, and a cursor into the array. */
    unsigned int entries;
    unsigned int cursor;

    /* Protects map_domain_page(). */
    spinlock_t lock;

    /* Garbage mappings are flushed from TLBs in batches called 'epochs'. */
    unsigned int epoch;
    u32 tlbflush_timestamp;

    /* Which mappings are in use, and which are garbage to reap next epoch? */
    unsigned long *inuse;
    unsigned long *garbage;
};

int mapcache_domain_init(struct domain *);
int mapcache_vcpu_init(struct vcpu *);
void mapcache_override_current(struct vcpu *);

/* x86/64: toggle guest between kernel and user modes. */
void toggle_guest_mode(struct vcpu *);

/*
 * Initialise a hypercall-transfer page. The given pointer must be mapped
 * in Xen virtual address space (accesses are not validated or checked).
 */
void hypercall_page_initialise(struct domain *d, void *);

/************************************************/
/*          shadow paging extension             */
/************************************************/
struct shadow_domain {
    unsigned int      opt_flags;    /* runtime tunable optimizations on/off */
    struct page_list_head pinned_shadows;

    /* Memory allocation */
    struct page_list_head freelist;
    unsigned int      total_pages;  /* number of pages allocated */
    unsigned int      free_pages;   /* number of pages on freelists */
    unsigned int      p2m_pages;    /* number of pages allocates to p2m */

    /* 1-to-1 map for use when HVM vcpus have paging disabled */
    pagetable_t unpaged_pagetable;

    /* reflect guest table dirty status, incremented by write
     * emulation and remove write permission */
    atomic_t gtable_dirty_version;

    /* Shadow hashtable */
    struct page_info **hash_table;
    bool_t hash_walking;  /* Some function is walking the hash table */

    /* Fast MMIO path heuristic */
    bool_t has_fast_mmio_entries;

    /* OOS */
    bool_t oos_active;
    bool_t oos_off;

    /* Has this domain ever used HVMOP_pagetable_dying? */
    bool_t pagetable_dying_op;
};

struct shadow_vcpu {
    /* PAE guests: per-vcpu shadow top-level table */
    l3_pgentry_t l3table[4] __attribute__((__aligned__(32)));
    /* PAE guests: per-vcpu cache of the top-level *guest* entries */
    l3_pgentry_t gl3e[4] __attribute__((__aligned__(32)));
    /* Non-PAE guests: pointer to guest top-level pagetable */
    void *guest_vtable;
    /* Last MFN that we emulated a write to as unshadow heuristics. */
    unsigned long last_emulated_mfn_for_unshadow;
    /* MFN of the last shadow that we shot a writeable mapping in */
    unsigned long last_writeable_pte_smfn;
    /* Last frame number that we emulated a write to. */
    unsigned long last_emulated_frame;
    /* Last MFN that we emulated a write successfully */
    unsigned long last_emulated_mfn;

    /* Shadow out-of-sync: pages that this vcpu has let go out of sync */
    mfn_t oos[SHADOW_OOS_PAGES];
    mfn_t oos_snapshot[SHADOW_OOS_PAGES];
    struct oos_fixup {
        int next;
        mfn_t smfn[SHADOW_OOS_FIXUPS];
        unsigned long off[SHADOW_OOS_FIXUPS];
    } oos_fixup[SHADOW_OOS_PAGES];

    bool_t pagetable_dying;
};

/************************************************/
/*            hardware assisted paging          */
/************************************************/
struct hap_domain {
    struct page_list_head freelist;
    unsigned int      total_pages;  /* number of pages allocated */
    unsigned int      free_pages;   /* number of pages on freelists */
    unsigned int      p2m_pages;    /* number of pages allocates to p2m */
};

/************************************************/
/*       common paging data structure           */
/************************************************/
struct log_dirty_domain {
    /* log-dirty radix tree to record dirty pages */
    mfn_t          top;
    unsigned int   allocs;
    unsigned int   failed_allocs;

    /* log-dirty mode stats */
    unsigned int   fault_count;
    unsigned int   dirty_count;

    /* functions which are paging mode specific */
    int            (*enable_log_dirty   )(struct domain *d, bool_t log_global);
    int            (*disable_log_dirty  )(struct domain *d);
    void           (*clean_dirty_bitmap )(struct domain *d);
};

struct paging_domain {
    /* paging lock */
    mm_lock_t lock;

    /* flags to control paging operation */
    u32                     mode;
    /* extension for shadow paging support */
    struct shadow_domain    shadow;
    /* extension for hardware-assited paging */
    struct hap_domain       hap;
    /* log dirty support */
    struct log_dirty_domain log_dirty;

    /* preemption handling */
    struct {
        const struct domain *dom;
        unsigned int op;
        union {
            struct {
                unsigned long done:PADDR_BITS - PAGE_SHIFT;
                unsigned long i4:PAGETABLE_ORDER;
                unsigned long i3:PAGETABLE_ORDER;
            } log_dirty;
        };
    } preempt;

    /* alloc/free pages from the pool for paging-assistance structures
     * (used by p2m and log-dirty code for their tries) */
    struct page_info * (*alloc_page)(struct domain *d);
    void (*free_page)(struct domain *d, struct page_info *pg);
    /* Has that pool ever run out of memory? */
    bool_t p2m_alloc_failed;
};

struct paging_vcpu {
    /* Pointers to mode-specific entry points. */
    const struct paging_mode *mode;
    /* Nested Virtualization: paging mode of nested guest */
    const struct paging_mode *nestedmode;
    /* HVM guest: last emulate was to a pagetable */
    unsigned int last_write_was_pt:1;
    /* HVM guest: last write emulation succeeds */
    unsigned int last_write_emul_ok:1;
    /* Translated guest: virtual TLB */
    struct shadow_vtlb *vtlb;
    spinlock_t          vtlb_lock;

    /* paging support extension */
    struct shadow_vcpu shadow;
};

#define MAX_CPUID_INPUT 40
typedef xen_domctl_cpuid_t cpuid_input_t;

#define MAX_NESTEDP2M 10
struct p2m_domain;
struct time_scale {
    int shift;
    u32 mul_frac;
};

struct pv_domain
{
    l1_pgentry_t **gdt_ldt_l1tab;

    /* map_domain_page() mapping cache. */
    struct mapcache_domain mapcache;
};

struct arch_domain
{
    struct page_info *perdomain_l3_pg;

    unsigned int hv_compat_vstart;

    bool_t s3_integrity;

    /* I/O-port admin-specified access capabilities. */
    struct rangeset *ioport_caps;
    uint32_t pci_cf8;
    uint8_t cmos_idx;

    struct list_head pdev_list;

    union {
        struct pv_domain pv_domain;
        struct hvm_domain hvm_domain;
    };

    struct paging_domain paging;
    struct p2m_domain *p2m;
    /* To enforce lock ordering in the pod code wrt the 
     * page_alloc lock */
    int page_alloc_unlock_level;

    /* nestedhvm: translate l2 guest physical to host physical */
    struct p2m_domain *nested_p2m[MAX_NESTEDP2M];
    mm_lock_t nested_p2m_lock;

    /* NB. protected by d->event_lock and by irq_desc[irq].lock */
    struct radix_tree_root irq_pirq;

    /* Maximum physical-address bitwidth supported by this guest. */
    unsigned int physaddr_bitsize;

    /* Is a 32-bit PV (non-HVM) guest? */
    bool_t is_32bit_pv;
    /* Is shared-info page in 32-bit format? */
    bool_t has_32bit_shinfo;
    /* Domain cannot handle spurious page faults? */
    bool_t suppress_spurious_page_faults;

    /* Continuable domain_relinquish_resources(). */
    enum {
        RELMEM_not_started,
        RELMEM_shared,
        RELMEM_xen,
        RELMEM_l4,
        RELMEM_l3,
        RELMEM_l2,
        RELMEM_done,
    } relmem;
    struct page_list_head relmem_list;

    cpuid_input_t *cpuids;

    struct PITState vpit;

    /* TSC management (emulation, pv, scaling, stats) */
    int tsc_mode;            /* see include/asm-x86/time.h */
    bool_t vtsc;             /* tsc is emulated (may change after migrate) */
    s_time_t vtsc_last;      /* previous TSC value (guarantee monotonicity) */
    spinlock_t vtsc_lock;
    uint64_t vtsc_offset;    /* adjustment for save/restore/migrate */
    uint32_t tsc_khz;        /* cached khz for certain emulated cases */
    struct time_scale vtsc_to_ns; /* scaling for certain emulated cases */
    struct time_scale ns_to_vtsc; /* scaling for certain emulated cases */
    uint32_t incarnation;    /* incremented every restore or live migrate
                                (possibly other cases in the future */
    uint64_t vtsc_kerncount; /* for hvm, counts all vtsc */
    uint64_t vtsc_usercount; /* not used for hvm */

    /* Pseudophysical e820 map (XENMEM_memory_map).  */
    spinlock_t e820_lock;
    struct e820entry *e820;
    unsigned int nr_e820;

    /* set auto_unmask to 1 if you want PHYSDEVOP_eoi to automatically
     * unmask the event channel */
    bool_t auto_unmask;
    /* Shared page for notifying that explicit PIRQ EOI is required. */
    unsigned long *pirq_eoi_map;
    unsigned long pirq_eoi_map_mfn;

    unsigned int psr_rmid; /* RMID assigned to the domain for CMT */
} __cacheline_aligned;

#define has_arch_pdevs(d)    (!list_empty(&(d)->arch.pdev_list))

#define gdt_ldt_pt_idx(v) \
      ((v)->vcpu_id >> (PAGETABLE_ORDER - GDT_LDT_VCPU_SHIFT))
#define gdt_ldt_ptes(d, v) \
    ((d)->arch.pv_domain.gdt_ldt_l1tab[gdt_ldt_pt_idx(v)] + \
     (((v)->vcpu_id << GDT_LDT_VCPU_SHIFT) & (L1_PAGETABLE_ENTRIES - 1)))

struct pv_vcpu
{
    /* map_domain_page() mapping cache. */
    struct mapcache_vcpu mapcache;

    struct trap_info *trap_ctxt;

    unsigned long gdt_frames[FIRST_RESERVED_GDT_PAGE];
    unsigned long ldt_base;
    unsigned int gdt_ents, ldt_ents;

    unsigned long kernel_ss, kernel_sp;
    unsigned long ctrlreg[8];

    unsigned long event_callback_eip;
    unsigned long failsafe_callback_eip;
    union {
        unsigned long syscall_callback_eip;
        struct {
            unsigned int event_callback_cs;
            unsigned int failsafe_callback_cs;
        };
    };

    unsigned long vm_assist;

    unsigned long syscall32_callback_eip;
    unsigned long sysenter_callback_eip;
    unsigned short syscall32_callback_cs;
    unsigned short sysenter_callback_cs;
    bool_t syscall32_disables_events;
    bool_t sysenter_disables_events;

    /* Segment base addresses. */
    unsigned long fs_base;
    unsigned long gs_base_kernel;
    unsigned long gs_base_user;

    /* Bounce information for propagating an exception to guest OS. */
    struct trap_bounce trap_bounce;
    struct trap_bounce int80_bounce;

    /* I/O-port access bitmap. */
    XEN_GUEST_HANDLE(uint8) iobmp; /* Guest kernel vaddr of the bitmap. */
    unsigned int iobmp_limit; /* Number of ports represented in the bitmap. */
    unsigned int iopl;        /* Current IOPL for this VCPU. */

    /* Current LDT details. */
    unsigned long shadow_ldt_mapcnt;
    spinlock_t shadow_ldt_lock;

    /* data breakpoint extension MSRs */
    uint32_t dr_mask[4];

    /* Deferred VA-based update state. */
    bool_t need_update_runstate_area;
    struct vcpu_time_info pending_system_time;
};

typedef enum __packed {
    SMAP_CHECK_HONOR_CPL_AC,    /* honor the guest's CPL and AC */
    SMAP_CHECK_ENABLED,         /* enable the check */
    SMAP_CHECK_DISABLED,        /* disable the check */
} smap_check_policy_t;

struct arch_vcpu
{
    /*
     * guest context (mirroring struct vcpu_guest_context) common
     * between pv and hvm guests
     */

    void              *fpu_ctxt;
    unsigned long      vgc_flags;
    struct cpu_user_regs user_regs;
    unsigned long      debugreg[8];

    /* other state */

    unsigned long      flags; /* TF_ */

    void (*schedule_tail) (struct vcpu *);

    void (*ctxt_switch_from) (struct vcpu *);
    void (*ctxt_switch_to) (struct vcpu *);

    /* Virtual Machine Extensions */
    union {
        struct pv_vcpu pv_vcpu;
        struct hvm_vcpu hvm_vcpu;
    };

    pagetable_t guest_table_user;       /* (MFN) x86/64 user-space pagetable */
    pagetable_t guest_table;            /* (MFN) guest notion of cr3 */
    struct page_info *old_guest_table;  /* partially destructed pagetable */
    /* guest_table holds a ref to the page, and also a type-count unless
     * shadow refcounts are in use */
    pagetable_t shadow_table[4];        /* (MFN) shadow(s) of guest */
    pagetable_t monitor_table;          /* (MFN) hypervisor PT (for HVM) */
    unsigned long cr3;                  /* (MA) value to install in HW CR3 */

    /*
     * The save area for Processor Extended States and the bitmask of the
     * XSAVE/XRSTOR features. They are used by: 1) when a vcpu (which has
     * dirtied FPU/SSE) is scheduled out we XSAVE the states here; 2) in
     * #NM handler, we XRSTOR the states we XSAVE-ed;
     */
    struct xsave_struct *xsave_area;
    uint64_t xcr0;
    /* Accumulated eXtended features mask for using XSAVE/XRESTORE by Xen
     * itself, as we can never know whether guest OS depends on content
     * preservation whenever guest OS clears one feature flag (for example,
     * temporarily).
     * However, processor should not be able to touch eXtended states before
     * it explicitly enables it via xcr0.
     */
    uint64_t xcr0_accum;
    /* This variable determines whether nonlazy extended state has been used,
     * and thus should be saved/restored. */
    bool_t nonlazy_xstate_used;

    /*
     * The SMAP check policy when updating runstate_guest(v) and the
     * secondary system time.
     */
    smap_check_policy_t smap_check_policy;

    struct vmce vmce;

    struct paging_vcpu paging;

    uint32_t gdbsx_vcpu_event;

    /* A secondary copy of the vcpu time info. */
    XEN_GUEST_HANDLE(vcpu_time_info_t) time_info_guest;

    /*
     * Should we emulate the next matching instruction on VCPU resume
     * after a mem_event?
     */
    struct {
        uint32_t emulate_flags;
        unsigned long gpa;
        unsigned long eip;
    } mem_event;

} __cacheline_aligned;

smap_check_policy_t smap_policy_change(struct vcpu *v,
                                       smap_check_policy_t new_policy);

/* Shorthands to improve code legibility. */
#define hvm_vmx         hvm_vcpu.u.vmx
#define hvm_svm         hvm_vcpu.u.svm

bool_t update_runstate_area(struct vcpu *);
bool_t update_secondary_system_time(struct vcpu *,
                                    struct vcpu_time_info *);

void vcpu_show_execution_state(struct vcpu *);
void vcpu_show_registers(const struct vcpu *);

/* Clean up CR4 bits that are not under guest control. */
unsigned long pv_guest_cr4_fixup(const struct vcpu *, unsigned long guest_cr4);

/* Convert between guest-visible and real CR4 values. */
#define pv_guest_cr4_to_real_cr4(v)                         \
    (((v)->arch.pv_vcpu.ctrlreg[4]                          \
      | (mmu_cr4_features                                   \
         & (X86_CR4_PGE | X86_CR4_PSE | X86_CR4_SMEP |      \
            X86_CR4_SMAP | X86_CR4_OSXSAVE |                \
            X86_CR4_FSGSBASE))                              \
      | ((v)->domain->arch.vtsc ? X86_CR4_TSD : 0))         \
     & ~X86_CR4_DE)
#define real_cr4_to_pv_guest_cr4(c)                         \
    ((c) & ~(X86_CR4_PGE | X86_CR4_PSE | X86_CR4_TSD |      \
             X86_CR4_OSXSAVE | X86_CR4_SMEP |               \
             X86_CR4_FSGSBASE | X86_CR4_SMAP))

void domain_cpuid(struct domain *d,
                  unsigned int  input,
                  unsigned int  sub_input,
                  unsigned int  *eax,
                  unsigned int  *ebx,
                  unsigned int  *ecx,
                  unsigned int  *edx);

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
