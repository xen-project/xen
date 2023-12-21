#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/mm.h>
#include <xen/radix-tree.h>
#include <asm/hvm/vcpu.h>
#include <asm/hvm/domain.h>
#include <asm/e820.h>
#include <asm/mce.h>
#include <asm/vpmu.h>
#include <asm/x86_emulate.h>
#include <public/vcpu.h>
#include <public/hvm/hvm_info_table.h>

#define has_32bit_shinfo(d)    ((d)->arch.has_32bit_shinfo)

/*
 * Set to true if either the global vector-type callback or per-vCPU
 * LAPIC vectors are used. Assume all vCPUs will use
 * HVMOP_set_evtchn_upcall_vector as long as the initial vCPU does.
 */
#define is_hvm_pv_evtchn_domain(d) (is_hvm_domain(d) && \
        ((d)->arch.hvm.irq->callback_via_type == HVMIRQ_callback_vector || \
         (d)->vcpu[0]->arch.hvm.evtchn_upcall_vector))
#define is_domain_direct_mapped(d) ((void)(d), 0)

#define VCPU_TRAP_NONE         0
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

int mapcache_domain_init(struct domain *d);
int mapcache_vcpu_init(struct vcpu *v);
void mapcache_override_current(struct vcpu *v);

/* x86/64: toggle guest between kernel and user modes. */
void toggle_guest_mode(struct vcpu *v);
/* x86/64: toggle guest page tables between kernel and user modes. */
void toggle_guest_pt(struct vcpu *v);

/*
 * Initialise a hypercall-transfer page. The given pointer must be mapped
 * in Xen virtual address space (accesses are not validated or checked).
 */
void init_hypercall_page(struct domain *d, void *ptr);

/************************************************/
/*          shadow paging extension             */
/************************************************/
struct shadow_domain {
#ifdef CONFIG_SHADOW_PAGING
    unsigned int      opt_flags;    /* runtime tunable optimizations on/off */
    struct page_list_head pinned_shadows;

    /* 1-to-1 map for use when HVM vcpus have paging disabled */
    pagetable_t unpaged_pagetable;

    /* reflect guest table dirty status, incremented by write
     * emulation and remove write permission */
    atomic_t gtable_dirty_version;

    /* Shadow hashtable */
    struct page_info **hash_table;
    bool hash_walking;  /* Some function is walking the hash table */

    /* Fast MMIO path heuristic */
    bool has_fast_mmio_entries;

#ifdef CONFIG_HVM
    /* OOS */
    bool oos_active;

    /* Has this domain ever used HVMOP_pagetable_dying? */
    bool pagetable_dying_op;
#endif

#ifdef CONFIG_PV
    /* PV L1 Terminal Fault mitigation. */
    struct tasklet pv_l1tf_tasklet;
#endif /* CONFIG_PV */
#endif
};

struct shadow_vcpu {
#ifdef CONFIG_SHADOW_PAGING
#ifdef CONFIG_HVM
    /* PAE guests: per-vcpu shadow top-level table */
    l3_pgentry_t l3table[4] __attribute__((__aligned__(32)));
    /* PAE guests: per-vcpu cache of the top-level *guest* entries */
    l3_pgentry_t gl3e[4] __attribute__((__aligned__(32)));

    /* shadow(s) of guest (MFN) */
    pagetable_t shadow_table[4];
#else
    /* shadow of guest (MFN) */
    pagetable_t shadow_table[1];
#endif

    /* Last MFN that we emulated a write to as unshadow heuristics. */
    unsigned long last_emulated_mfn_for_unshadow;
    /* MFN of the last shadow that we shot a writeable mapping in */
    unsigned long last_writeable_pte_smfn;
#ifdef CONFIG_HVM
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

    bool pagetable_dying;
#endif
#endif
};

/************************************************/
/*            hardware assisted paging          */
/************************************************/
struct hap_domain {
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
    unsigned long  fault_count;
    unsigned long  dirty_count;

    /* functions which are paging mode specific */
    const struct log_dirty_ops {
        int        (*enable  )(struct domain *d);
        int        (*disable )(struct domain *d);
        void       (*clean   )(struct domain *d);
    } *ops;
};

struct paging_domain {
    /* paging lock */
    mm_lock_t lock;

    /* flags to control paging operation */
    u32                     mode;
    /* Has that pool ever run out of memory? */
    bool                    p2m_alloc_failed;
    /* extension for shadow paging support */
    struct shadow_domain    shadow;
    /* extension for hardware-assited paging */
    struct hap_domain       hap;

    /* Memory allocation (common to shadow and HAP) */
    struct page_list_head   freelist;
    unsigned int            total_pages;  /* number of pages allocated */
    unsigned int            free_pages;   /* number of pages on freelists */
    unsigned int            p2m_pages;    /* number of pages allocated to p2m */

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

    void (*update_paging_modes)(struct vcpu *v);

#ifdef CONFIG_HVM
    /* Flush selected vCPUs TLBs.  NULL for all. */
    bool __must_check (*flush_tlb)(const unsigned long *vcpu_bitmap);
#endif
};

struct paging_vcpu {
    /* Pointers to mode-specific entry points. */
    const struct paging_mode *mode;
    /* Nested Virtualization: paging mode of nested guest */
    const struct paging_mode *nestedmode;
#ifdef CONFIG_HVM
    /* HVM guest: last emulate was to a pagetable */
    unsigned int last_write_was_pt:1;
    /* HVM guest: last write emulation succeeds */
    unsigned int last_write_emul_ok:1;
#endif
    /* Translated guest: virtual TLB */
    struct shadow_vtlb *vtlb;
    spinlock_t          vtlb_lock;

    /* paging support extension */
    struct shadow_vcpu shadow;
};

#define MAX_NESTEDP2M 10

#define MAX_ALTP2M      10 /* arbitrary */
#define INVALID_ALTP2M  0xffff
#define MAX_EPTP        (PAGE_SIZE / sizeof(uint64_t))
struct p2m_domain;
struct time_scale {
    int shift;
    u32 mul_frac;
};

struct pv_domain
{
    l1_pgentry_t **gdt_ldt_l1tab;

    atomic_t nr_l4_pages;

    /* Is a 32-bit PV guest? */
    bool is_32bit;
    /* XPTI active? */
    bool xpti;
    /* Use PCID feature? */
    bool pcid;
    /* Mitigate L1TF with shadow/crashing? */
    bool check_l1tf;

    /* map_domain_page() mapping cache. */
    struct mapcache_domain mapcache;

    struct cpuidmasks *cpuidmasks;
};

struct monitor_write_data {
    struct {
        unsigned int msr : 1;
        unsigned int cr0 : 1;
        unsigned int cr3 : 1;
        unsigned int cr4 : 1;
    } do_write;

    bool cr3_noflush;

    uint32_t msr;
    uint64_t value;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
};

struct arch_domain
{
    struct page_info *perdomain_l3_pg;

#ifdef CONFIG_PV32
    unsigned int hv_compat_vstart;
#endif

    /* Maximum physical-address bitwidth supported by this guest. */
    unsigned int physaddr_bitsize;

    /* I/O-port admin-specified access capabilities. */
    struct rangeset *ioport_caps;
    uint32_t pci_cf8;
    uint8_t cmos_idx;

    uint8_t spec_ctrl_flags; /* See SCF_DOM_MASK */

    union {
        struct pv_domain pv;
        struct hvm_domain hvm;
    };

    struct paging_domain paging;
    struct p2m_domain *p2m;
    /* To enforce lock ordering in the pod code wrt the
     * page_alloc lock */
    int page_alloc_unlock_level;

    /* Continuable domain_relinquish_resources(). */
    unsigned int rel_priv;
    struct page_list_head relmem_list;

    const struct arch_csw {
        void (*from)(struct vcpu *v);
        void (*to)(struct vcpu *v);
        void noreturn (*tail)(void);
    } *ctxt_switch;

#ifdef CONFIG_HVM
    /* nestedhvm: translate l2 guest physical to host physical */
    struct p2m_domain *nested_p2m[MAX_NESTEDP2M];
    mm_lock_t nested_p2m_lock;

    /* altp2m: allow multiple copies of host p2m */
    bool altp2m_active;
    struct p2m_domain *altp2m_p2m[MAX_ALTP2M];
    mm_lock_t altp2m_list_lock;
    uint64_t *altp2m_eptp;
    uint64_t *altp2m_visible_eptp;
#endif

    /* NB. protected by d->event_lock and by irq_desc[irq].lock */
    struct radix_tree_root irq_pirq;

    /* Is shared-info page in 32-bit format? */
    bool has_32bit_shinfo;

    /* Is PHYSDEVOP_eoi to automatically unmask the event channel? */
    bool auto_unmask;

    /*
     * The width of the FIP/FDP register in the FPU that needs to be
     * saved/restored during a context switch.  This is needed because
     * the FPU can either: a) restore the 64-bit FIP/FDP and clear FCS
     * and FDS; or b) restore the 32-bit FIP/FDP (clearing the upper
     * 32-bits of FIP/FDP) and restore FCS/FDS.
     *
     * Which one is needed depends on the guest.
     *
     * This can be either: 8, 4 or 0.  0 means auto-detect the size
     * based on the width of FIP/FDP values that are written by the
     * guest.
     */
    uint8_t x87_fip_width;

    /*
     * The domain's CPU Policy.  "cpu_policy" is considered the canonical
     * pointer, but the "cpuid" and "msr" aliases exist so the most
     * appropriate one can be used for local code clarity.
     */
    union {
        struct cpu_policy *cpu_policy;
        struct cpu_policy *cpuid;
        struct cpu_policy *msr;
    };

    struct PITState vpit;

    /* TSC management (emulation, pv, scaling, stats) */
    int tsc_mode;            /* see asm/time.h */
    bool vtsc;               /* tsc is emulated (may change after migrate) */
    s_time_t vtsc_last;      /* previous TSC value (guarantee monotonicity) */
    uint64_t vtsc_offset;    /* adjustment for save/restore/migrate */
    uint32_t tsc_khz;        /* cached guest khz for certain emulated or
                                hardware TSC scaling cases */
    struct time_scale vtsc_to_ns; /* scaling for certain emulated or
                                     hardware TSC scaling cases */
    struct time_scale ns_to_vtsc; /* scaling for certain emulated or
                                     hardware TSC scaling cases */
    uint32_t incarnation;    /* incremented every restore or live migrate
                                (possibly other cases in the future */

    /* Pseudophysical e820 map (XENMEM_memory_map).  */
    spinlock_t e820_lock;
    struct e820entry *e820;
    unsigned int nr_e820;

    /* RMID assigned to the domain for CMT */
    unsigned int psr_rmid;
    /* COS assigned to the domain for each socket */
    unsigned int *psr_cos_ids;

    /* Shared page for notifying that explicit PIRQ EOI is required. */
    unsigned long *pirq_eoi_map;
    unsigned long pirq_eoi_map_mfn;

    /* Arch-specific monitor options */
    struct {
        unsigned int write_ctrlreg_enabled                                 : 4;
        unsigned int write_ctrlreg_sync                                    : 4;
        unsigned int write_ctrlreg_onchangeonly                            : 4;
        unsigned int singlestep_enabled                                    : 1;
        unsigned int software_breakpoint_enabled                           : 1;
        unsigned int debug_exception_enabled                               : 1;
        unsigned int debug_exception_sync                                  : 1;
        unsigned int cpuid_enabled                                         : 1;
        unsigned int descriptor_access_enabled                             : 1;
        unsigned int guest_request_userspace_enabled                       : 1;
        unsigned int emul_unimplemented_enabled                            : 1;
        unsigned int io_enabled                                            : 1;
        /*
         * By default all events are sent.
         * This is used to filter out pagefaults.
         */
        unsigned int inguest_pagefault_disabled                            : 1;
        unsigned int control_register_values                               : 1;
        unsigned int vmexit_enabled                                        : 1;
        unsigned int vmexit_sync                                           : 1;
        struct monitor_msr_bitmap *msr_bitmap;
        uint64_t write_ctrlreg_mask[4];
    } monitor;

    /* Mem_access emulation control */
    bool mem_access_emulate_each_rep;

    /* Don't unconditionally inject #GP for unhandled MSRs. */
    bool msr_relaxed;

    /* Emulated devices enabled bitmap. */
    uint32_t emulation_flags;
} __cacheline_aligned;

#ifdef CONFIG_HVM
#define X86_EMU_LAPIC    XEN_X86_EMU_LAPIC
#define X86_EMU_HPET     XEN_X86_EMU_HPET
#define X86_EMU_PM       XEN_X86_EMU_PM
#define X86_EMU_RTC      XEN_X86_EMU_RTC
#define X86_EMU_IOAPIC   XEN_X86_EMU_IOAPIC
#define X86_EMU_PIC      XEN_X86_EMU_PIC
#define X86_EMU_VGA      XEN_X86_EMU_VGA
#define X86_EMU_IOMMU    XEN_X86_EMU_IOMMU
#define X86_EMU_USE_PIRQ XEN_X86_EMU_USE_PIRQ
#define X86_EMU_VPCI     XEN_X86_EMU_VPCI
#else
#define X86_EMU_LAPIC    0
#define X86_EMU_HPET     0
#define X86_EMU_PM       0
#define X86_EMU_RTC      0
#define X86_EMU_IOAPIC   0
#define X86_EMU_PIC      0
#define X86_EMU_VGA      0
#define X86_EMU_IOMMU    0
#define X86_EMU_USE_PIRQ 0
#define X86_EMU_VPCI     0
#endif

#define X86_EMU_PIT     XEN_X86_EMU_PIT

/* This must match XEN_X86_EMU_ALL in xen.h */
#define X86_EMU_ALL             (X86_EMU_LAPIC | X86_EMU_HPET |         \
                                 X86_EMU_PM | X86_EMU_RTC |             \
                                 X86_EMU_IOAPIC | X86_EMU_PIC |         \
                                 X86_EMU_VGA | X86_EMU_IOMMU |          \
                                 X86_EMU_PIT | X86_EMU_USE_PIRQ |       \
                                 X86_EMU_VPCI)

#define has_vlapic(d)      (!!((d)->arch.emulation_flags & X86_EMU_LAPIC))
#define has_vhpet(d)       (!!((d)->arch.emulation_flags & X86_EMU_HPET))
#define has_vpm(d)         (!!((d)->arch.emulation_flags & X86_EMU_PM))
#define has_vrtc(d)        (!!((d)->arch.emulation_flags & X86_EMU_RTC))
#define has_vioapic(d)     (!!((d)->arch.emulation_flags & X86_EMU_IOAPIC))
#define has_vpic(d)        (!!((d)->arch.emulation_flags & X86_EMU_PIC))
#define has_vvga(d)        (!!((d)->arch.emulation_flags & X86_EMU_VGA))
#define has_viommu(d)      (!!((d)->arch.emulation_flags & X86_EMU_IOMMU))
#define has_vpit(d)        (!!((d)->arch.emulation_flags & X86_EMU_PIT))
#define has_pirq(d)        (!!((d)->arch.emulation_flags & X86_EMU_USE_PIRQ))
#define has_vpci(d)        (!!((d)->arch.emulation_flags & X86_EMU_VPCI))

#define gdt_ldt_pt_idx(v) \
      ((v)->vcpu_id >> (PAGETABLE_ORDER - GDT_LDT_VCPU_SHIFT))
#define pv_gdt_ptes(v) \
    ((v)->domain->arch.pv.gdt_ldt_l1tab[gdt_ldt_pt_idx(v)] + \
     (((v)->vcpu_id << GDT_LDT_VCPU_SHIFT) & (L1_PAGETABLE_ENTRIES - 1)))
#define pv_ldt_ptes(v) (pv_gdt_ptes(v) + 16)

struct pv_vcpu
{
    /* map_domain_page() mapping cache. */
    struct mapcache_vcpu mapcache;

    unsigned int vgc_flags;

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

    unsigned long syscall32_callback_eip;
    unsigned long sysenter_callback_eip;
    unsigned short syscall32_callback_cs;
    unsigned short sysenter_callback_cs;
    bool syscall32_disables_events;
    bool sysenter_disables_events;

    /*
     * 64bit segment bases.
     *
     * FS and the active GS are always stale when the vCPU is in context, as
     * the guest can change them behind Xen's back with MOV SREG, or
     * WR{FS,GS}BASE on capable hardware.
     *
     * The inactive GS base is never stale, as guests can't use SWAPGS to
     * access it - all modification is performed by Xen either directly
     * (hypercall, #GP emulation), or indirectly (toggle_guest_mode()).
     *
     * The vCPU context switch path is optimised based on this fact, so any
     * path updating or swapping the inactive base must update the cached
     * value as well.
     *
     * Which GS base is active and inactive depends on whether the vCPU is in
     * user or kernel context.
     */
    unsigned long fs_base;
    unsigned long gs_base_kernel;
    unsigned long gs_base_user;

    /* Bounce information for propagating an exception to guest OS. */
    struct trap_bounce trap_bounce;

    /* I/O-port access bitmap. */
    XEN_GUEST_HANDLE(uint8) iobmp; /* Guest kernel vaddr of the bitmap. */
    unsigned int iobmp_limit; /* Number of ports represented in the bitmap. */
#define IOPL(val) MASK_INSR(val, X86_EFLAGS_IOPL)
    unsigned int iopl;        /* Current IOPL for this VCPU, shifted left by
                               * 12 to match the eflags register. */

    /*
     * %dr7 bits the guest has set, but aren't loaded into hardware, and are
     * completely emulated.
     */
    uint32_t dr7_emul;

    /* Deferred VA-based update state. */
    bool need_update_runstate_area;
    struct vcpu_time_info pending_system_time;
};

struct arch_vcpu
{
    /*
     * guest context (mirroring struct vcpu_guest_context) common
     * between pv and hvm guests
     */

    void              *fpu_ctxt;
    struct cpu_user_regs user_regs;

    /* Debug registers. */
    unsigned long dr[4];
    unsigned long dr7; /* Ideally int, but __vmread() needs long. */
    unsigned int dr6;

    /* other state */

    unsigned long      flags; /* TF_ */

    struct vpmu_struct vpmu;

    struct {
        bool    pending;
        uint8_t old_mask;
    } async_exception_state[VCPU_TRAP_LAST];
#define async_exception_state(t) async_exception_state[(t)-1]
    uint8_t async_exception_mask;

    /* Virtual Machine Extensions */
    union {
        struct pv_vcpu pv;
        struct hvm_vcpu hvm;
    };

    /*
     * guest_table{,_user} hold a ref to the page, and also a type-count
     * unless shadow refcounts are in use
     */
    pagetable_t guest_table_user;       /* (MFN) x86/64 user-space pagetable */
    pagetable_t guest_table;            /* (MFN) guest notion of cr3 */
    struct page_info *old_guest_table;  /* partially destructed pagetable */
    struct page_info *old_guest_ptpg;   /* containing page table of the */
                                        /* former, if any */
    bool old_guest_table_partial;       /* Are we dropping a type ref, or just
                                         * finishing up a partial de-validation? */

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
    bool nonlazy_xstate_used;

    /* Restore all FPU state (lazy and non-lazy state) on context switch? */
    bool fully_eager_fpu;

    struct vmce vmce;

    struct paging_vcpu paging;

    uint32_t gdbsx_vcpu_event;

    /* A secondary copy of the vcpu time info. */
    XEN_GUEST_HANDLE(vcpu_time_info_t) time_info_guest;
    struct guest_area time_guest_area;

    struct arch_vm_event *vm_event;

    struct vcpu_msrs *msrs;

    struct {
        bool next_interrupt_enabled;
    } monitor;
};

struct guest_memory_policy
{
    bool nested_guest_mode;
};

void update_guest_memory_policy(struct vcpu *v,
                                struct guest_memory_policy *policy);

void domain_cpu_policy_changed(struct domain *d);

bool update_secondary_system_time(struct vcpu *v,
                                  struct vcpu_time_info *u);
void force_update_secondary_system_time(struct vcpu *v,
                                        struct vcpu_time_info *map);

void vcpu_show_registers(const struct vcpu *v);

static inline struct vcpu_guest_context *alloc_vcpu_guest_context(void)
{
    return vmalloc(sizeof(struct vcpu_guest_context));
}

static inline void free_vcpu_guest_context(struct vcpu_guest_context *vgc)
{
    vfree(vgc);
}

void arch_vcpu_regs_init(struct vcpu *v);

struct vcpu_hvm_context;
int arch_set_info_hvm_guest(struct vcpu *v, const struct vcpu_hvm_context *ctx);

#ifdef CONFIG_PV
void pv_inject_event(const struct x86_event *event);
#else
static inline void pv_inject_event(const struct x86_event *event)
{
    ASSERT_UNREACHABLE();
}
#endif

static inline void pv_inject_hw_exception(unsigned int vector, int errcode)
{
    const struct x86_event event = {
        .vector = vector,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode,
    };

    pv_inject_event(&event);
}

static inline void pv_inject_page_fault(int errcode, unsigned long cr2)
{
    const struct x86_event event = {
        .vector = X86_EXC_PF,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode,
        .cr2 = cr2,
    };

    pv_inject_event(&event);
}

static inline void pv_inject_sw_interrupt(unsigned int vector)
{
    const struct x86_event event = {
        .vector = vector,
        .type = X86_EVENTTYPE_SW_INTERRUPT,
        .error_code = X86_EVENT_NO_EC,
    };

    pv_inject_event(&event);
}

#define PV32_VM_ASSIST_MASK ((1UL << VMASST_TYPE_4gb_segments)        | \
                             (1UL << VMASST_TYPE_4gb_segments_notify) | \
                             (1UL << VMASST_TYPE_writable_pagetables) | \
                             (1UL << VMASST_TYPE_pae_extended_cr3)    | \
                             (1UL << VMASST_TYPE_architectural_iopl)  | \
                             (1UL << VMASST_TYPE_runstate_update_flag))
/*
 * Various of what PV32_VM_ASSIST_MASK has isn't really applicable to 64-bit,
 * but we can't make such requests fail all of the sudden.
 */
#define PV64_VM_ASSIST_MASK (PV32_VM_ASSIST_MASK                      | \
                             (1UL << VMASST_TYPE_m2p_strict))
#define HVM_VM_ASSIST_MASK  (1UL << VMASST_TYPE_runstate_update_flag)

#define arch_vm_assist_valid_mask(d) \
    (is_hvm_domain(d) ? HVM_VM_ASSIST_MASK \
                      : is_pv_32bit_domain(d) ? PV32_VM_ASSIST_MASK \
                                              : PV64_VM_ASSIST_MASK)

struct arch_vcpu_io {
};

/* Maxphysaddr supportable by the paging infrastructure. */
unsigned int domain_max_paddr_bits(const struct domain *d);

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
