
#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/config.h>
#include <xen/mm.h>
#include <asm/vmx_vmcs.h>

struct trap_bounce {
    unsigned long  error_code;
    unsigned short flags; /* TBF_ */
    unsigned short cs;
    unsigned long  eip;
};

struct arch_domain
{
    l1_pgentry_t *mm_perdomain_pt;
#ifdef CONFIG_X86_64
    l2_pgentry_t *mm_perdomain_l2;
    l3_pgentry_t *mm_perdomain_l3;
#endif

    /* Writable pagetables. */
    struct ptwr_info ptwr[2];

    /* I/O-port admin-specified access capabilities. */
    struct rangeset *ioport_caps;

    /* Shadow mode status and controls. */
    struct shadow_ops *ops;
    unsigned int shadow_mode;  /* flags to control shadow table operation */
    unsigned int shadow_nest;  /* Recursive depth of shadow_lock() nesting */

    /* shadow hashtable */
    struct shadow_status *shadow_ht;
    struct shadow_status *shadow_ht_free;
    struct shadow_status *shadow_ht_extras; /* extra allocation units */
    unsigned int shadow_extras_count;

    /* shadow dirty bitmap */
    unsigned long *shadow_dirty_bitmap;
    unsigned int shadow_dirty_bitmap_size;  /* in pages, bit per page */

    /* shadow mode stats */
    unsigned int shadow_page_count;
    unsigned int hl2_page_count;
    unsigned int snapshot_page_count;

    unsigned int shadow_fault_count;
    unsigned int shadow_dirty_count;

    /* full shadow mode */
    struct out_of_sync_entry *out_of_sync; /* list of out-of-sync pages */
    struct out_of_sync_entry *out_of_sync_free;
    struct out_of_sync_entry *out_of_sync_extras;
    unsigned int out_of_sync_extras_count;

    struct list_head free_shadow_frames;

    pagetable_t         phys_table;         /* guest 1:1 pagetable */
    struct vmx_platform vmx_platform;
} __cacheline_aligned;

struct arch_vcpu
{
    /* Needs 16-byte aligment for FXSAVE/FXRSTOR. */
    struct vcpu_guest_context guest_context
    __attribute__((__aligned__(16)));

    unsigned long      flags; /* TF_ */

    void (*schedule_tail) (struct vcpu *);

    /* Bounce information for propagating an exception to guest OS. */
    struct trap_bounce trap_bounce;

    /* I/O-port access bitmap. */
    u8 *iobmp;        /* Guest kernel virtual address of the bitmap. */
    int iobmp_limit;  /* Number of ports represented in the bitmap.  */
    int iopl;         /* Current IOPL for this VCPU. */

#ifdef CONFIG_X86_32
    struct desc_struct int80_desc;
#endif

    /* Virtual Machine Extensions */
    struct arch_vmx_struct arch_vmx;

    /*
     * Every domain has a L1 pagetable of its own. Per-domain mappings
     * are put in this table (eg. the current GDT is mapped here).
     */
    l1_pgentry_t *perdomain_ptes;

    pagetable_t  guest_table_user;      /* x86/64: user-space pagetable. */
    pagetable_t  guest_table;           /* (MA) guest notion of cr3 */
    pagetable_t  shadow_table;          /* (MA) shadow of guest */
    pagetable_t  monitor_table;         /* (MA) used in hypervisor */

    l2_pgentry_t *guest_vtable;         /* virtual address of pagetable */
    l2_pgentry_t *shadow_vtable;        /* virtual address of shadow_table */
    l2_pgentry_t *monitor_vtable;		/* virtual address of monitor_table */
    l1_pgentry_t *hl2_vtable;			/* virtual address of hl2_table */

#ifdef CONFIG_X86_64
    l3_pgentry_t *guest_vl3table;
    l4_pgentry_t *guest_vl4table;
#endif

    unsigned long monitor_shadow_ref;

    /* Current LDT details. */
    unsigned long shadow_ldt_mapcnt;
} __cacheline_aligned;

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
