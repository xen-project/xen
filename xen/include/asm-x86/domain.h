/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */

#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

struct trap_bounce {
    unsigned long  error_code;
    unsigned long  cr2;
    unsigned short flags; /* TBF_ */
    unsigned short cs;
    unsigned long  eip;
};

struct arch_domain
{
    l1_pgentry_t *mm_perdomain_pt;
#ifdef __x86_64__
    l2_pgentry_t *mm_perdomain_l2;
    l3_pgentry_t *mm_perdomain_l3;
#endif

    /* shadow mode status and controls */
    unsigned int shadow_mode;  /* flags to control shadow table operation */
    spinlock_t   shadow_lock;
    unsigned long min_pfn;     /* min host physical */
    unsigned long max_pfn;     /* max host physical */

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
    unsigned int shadow_fault_count;     
    unsigned int shadow_dirty_count;     
    unsigned int shadow_dirty_net_count;     
    unsigned int shadow_dirty_block_count;     
} __cacheline_aligned;

struct arch_exec_domain
{
    unsigned long      kernel_sp;
    unsigned long      kernel_ss;

    unsigned long      flags; /* TF_ */

    /* Hardware debugging registers */
    unsigned long      debugreg[8];  /* %%db0-7 debug registers */

    /* floating point info */
    struct i387_state  i387;

    /* general user-visible register state */
    execution_context_t user_ctxt;

    void (*schedule_tail) (struct exec_domain *);

    /*
     * Return vectors pushed to us by guest OS.
     * The stack frame for events is exactly that of an x86 hardware interrupt.
     * The stack frame for a failsafe callback is augmented with saved values
     * for segment registers %ds, %es, %fs and %gs:
     * 	%ds, %es, %fs, %gs, %eip, %cs, %eflags [, %oldesp, %oldss]
     */
    unsigned long event_selector;    /* entry CS  */
    unsigned long event_address;     /* entry EIP */

    unsigned long failsafe_selector; /* entry CS  */
    unsigned long failsafe_address;  /* entry EIP */

    /* Bounce information for propagating an exception to guest OS. */
    struct trap_bounce trap_bounce;

    /* I/O-port access bitmap. */
    u64 io_bitmap_sel; /* Selector to tell us which part of the IO bitmap are
                        * "interesting" (i.e. have clear bits) */
    u8 *io_bitmap; /* Pointer to task's IO bitmap or NULL */

    /* Trap info. */
#ifdef ARCH_HAS_FAST_TRAP
    int                fast_trap_idx;
    struct desc_struct fast_trap_desc;
#endif
    trap_info_t        traps[256];
#ifdef CONFIG_VMX
    struct arch_vmx_struct arch_vmx; /* Virtual Machine Extensions */
#endif

    /*
     * Every domain has a L1 pagetable of its own. Per-domain mappings
     * are put in this table (eg. the current GDT is mapped here).
     */
    l1_pgentry_t *perdomain_ptes;
    pagetable_t  pagetable;

    pagetable_t  monitor_table;
    pagetable_t  phys_table;            /* 1:1 pagetable */
    pagetable_t  shadow_table;
    l2_pgentry_t *vpagetable;	        /* virtual address of pagetable */
    l2_pgentry_t *shadow_vtable;	/* virtual address of shadow_table */
    l2_pgentry_t *guest_pl2e_cache;	/* guest page directory cache */

    /* Virtual CR2 value. Can be read/written by guest. */
    unsigned long guest_cr2;

    /* Current LDT details. */
    unsigned long ldt_base, ldt_ents, shadow_ldt_mapcnt;
    /* Next entry is passed to LGDT on domain switch. */
    char gdt[10]; /* NB. 10 bytes needed for x86_64. Use 6 bytes for x86_32. */
} __cacheline_aligned;

#define IDLE0_ARCH_EXEC_DOMAIN                                      \
{                                                                   \
    perdomain_ptes: 0,                                              \
    pagetable:      mk_pagetable(__pa(idle_pg_table))               \
}

#endif /* __ASM_DOMAIN_H__ */
