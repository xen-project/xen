/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/param.h>

#include <asm/endbr.h>
#include <asm/idt.h>
#include <asm/msr.h>
#include <asm/pv/domain.h>
#include <asm/pv/shim.h>
#include <asm/shstk.h>
#include <asm/stubs.h>
#include <asm/traps.h>

DEFINE_PER_CPU_READ_MOSTLY(idt_entry_t *, idt);

/* LastExceptionFromIP on this hardware.  Zero if LER is not in use. */
unsigned int __ro_after_init ler_msr;
static bool __initdata opt_ler;
boolean_param("ler", opt_ler);

int8_t __ro_after_init opt_fred = 0;
boolean_param("fred", opt_fred);

void nocall entry_PF(void);
void nocall lstar_enter(void);
void nocall cstar_enter(void);

/*
 * Sets up system tables and descriptors for IDT devliery.
 *
 * - Sets up TSS with stack pointers, including ISTs
 * - Inserts TSS selector into regular and compat GDTs
 * - Loads GDT, IDT, TR then null LDT
 * - Sets up IST references in the IDT
 */
static void load_system_tables(void)
{
    unsigned int i, cpu = smp_processor_id();
    unsigned long stack_bottom = get_stack_bottom(),
        stack_top = stack_bottom & ~(STACK_SIZE - 1);
    struct tss_page *tss_page = &this_cpu(tss_page);
    idt_entry_t *idt = this_cpu(idt);

    /* The TSS may be live.  Disuade any clever optimisations. */
    volatile struct tss64 *tss = &tss_page->tss;
    seg_desc_t *gdt =
        this_cpu(gdt) - FIRST_RESERVED_GDT_ENTRY;

    const struct desc_ptr gdtr = {
        .base = (unsigned long)gdt,
        .limit = LAST_RESERVED_GDT_BYTE,
    };
    const struct desc_ptr idtr = {
        .base = (unsigned long)idt,
        .limit = sizeof(bsp_idt) - 1,
    };

    ASSERT(opt_fred == 0);

    /*
     * Set up the TSS.  Warning - may be live, and the NMI/#MC must remain
     * valid on every instruction boundary.  (Note: these are all
     * semantically ACCESS_ONCE() due to tss's volatile qualifier.)
     *
     * rsp0 refers to the primary stack.  #MC, NMI, #DB and #DF handlers
     * each get their own stacks.  No IO Bitmap.
     */
    tss->rsp0 = stack_bottom;
    tss->ist[IST_MCE - 1] = stack_top + (1 + IST_MCE) * PAGE_SIZE;
    tss->ist[IST_NMI - 1] = stack_top + (1 + IST_NMI) * PAGE_SIZE;
    tss->ist[IST_DB  - 1] = stack_top + (1 + IST_DB)  * PAGE_SIZE;
    tss->ist[IST_DF  - 1] = stack_top + (1 + IST_DF)  * PAGE_SIZE;
    tss->bitmap = IOBMP_INVALID_OFFSET;

    /* All other stack pointers poisioned. */
    for ( i = IST_MAX; i < ARRAY_SIZE(tss->ist); ++i )
        tss->ist[i] = 0x8600111111111111UL;
    tss->rsp1 = 0x8600111111111111UL;
    tss->rsp2 = 0x8600111111111111UL;

    /*
     * Set up the shadow stack IST.  Used entries must point at the
     * supervisor stack token.  Unused entries are poisoned.
     *
     * This IST Table may be live, and the NMI/#MC entries must
     * remain valid on every instruction boundary, hence the
     * volatile qualifier.
     */
    if ( cpu_has_xen_shstk )
    {
        volatile uint64_t *ist_ssp = tss_page->ist_ssp;
        unsigned long
            ssp = stack_top + (PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE - 8,
            mce_ssp = stack_top + (IST_MCE * IST_SHSTK_SIZE) - 8,
            nmi_ssp = stack_top + (IST_NMI * IST_SHSTK_SIZE) - 8,
            db_ssp  = stack_top + (IST_DB  * IST_SHSTK_SIZE) - 8,
            df_ssp  = stack_top + (IST_DF  * IST_SHSTK_SIZE) - 8;

        ist_ssp[0] = 0x8600111111111111UL;
        ist_ssp[IST_MCE] = mce_ssp;
        ist_ssp[IST_NMI] = nmi_ssp;
        ist_ssp[IST_DB]  = db_ssp;
        ist_ssp[IST_DF]  = df_ssp;
        for ( i = IST_DF + 1; i < ARRAY_SIZE(tss_page->ist_ssp); ++i )
            ist_ssp[i] = 0x8600111111111111UL;

        if ( IS_ENABLED(CONFIG_XEN_SHSTK) && rdssp() != SSP_NO_SHSTK )
        {
            /*
             * Rewrite supervisor tokens when shadow stacks are
             * active.  This resets any busy bits left across S3.
             */
            wrss(mce_ssp, _p(mce_ssp));
            wrss(nmi_ssp, _p(nmi_ssp));
            wrss(db_ssp,  _p(db_ssp));
            wrss(df_ssp,  _p(df_ssp));
        }

        wrmsrns(MSR_ISST, (unsigned long)ist_ssp);
        wrmsrns(MSR_PL0_SSP, (unsigned long)ssp);
    }

    _set_tssldt_desc(gdt + TSS_ENTRY, (unsigned long)tss,
                     sizeof(*tss) - 1, SYS_DESC_tss_avail);
    if ( IS_ENABLED(CONFIG_PV32) )
        _set_tssldt_desc(
            this_cpu(compat_gdt) - FIRST_RESERVED_GDT_ENTRY + TSS_ENTRY,
            (unsigned long)tss, sizeof(*tss) - 1, SYS_DESC_tss_busy);

    per_cpu(full_gdt_loaded, cpu) = false;
    lgdt(&gdtr);
    lidt(&idtr);
    ltr(TSS_SELECTOR);
    lldt(0);

    enable_each_ist(idt);

    /*
     * tss->rsp0 must be 16-byte aligned.
     */
    BUG_ON(stack_bottom & 15);
}

static unsigned int write_stub_trampoline(
    unsigned char *stub, unsigned long stub_va,
    unsigned long stack_bottom, unsigned long target_va)
{
    unsigned char *p = stub;

    if ( cpu_has_xen_ibt )
    {
        place_endbr64(p);
        p += 4;
    }

    /* Store guest %rax into %ss slot */
    /* movabsq %rax, stack_bottom - 8 */
    *p++ = 0x48;
    *p++ = 0xa3;
    *(uint64_t *)p = stack_bottom - 8;
    p += 8;

    /* Store guest %rsp in %rax */
    /* movq %rsp, %rax */
    *p++ = 0x48;
    *p++ = 0x89;
    *p++ = 0xe0;

    /* Switch to Xen stack */
    /* movabsq $stack_bottom - 8, %rsp */
    *p++ = 0x48;
    *p++ = 0xbc;
    *(uint64_t *)p = stack_bottom - 8;
    p += 8;

    /* jmp target_va */
    *p++ = 0xe9;
    *(int32_t *)p = target_va - (stub_va + (p - stub) + 4);
    p += 4;

    /* Round up to a multiple of 16 bytes. */
    return ROUNDUP(p - stub, 16);
}

static void legacy_syscall_init(void)
{
    unsigned long stack_bottom = get_stack_bottom();
    unsigned long stub_va = this_cpu(stubs.addr);
    unsigned char *stub_page;
    unsigned int offset;

    ASSERT(opt_fred == 0);

    /* No PV guests?  No need to set up SYSCALL/SYSENTER infrastructure. */
    if ( !IS_ENABLED(CONFIG_PV) )
        return;

    stub_page = map_domain_page(_mfn(this_cpu(stubs.mfn)));

    /*
     * Trampoline for SYSCALL entry from 64-bit mode.  The VT-x HVM vcpu
     * context switch logic relies on the SYSCALL trampoline being at the
     * start of the stubs.
     */
    wrmsrns(MSR_LSTAR, stub_va);
    offset = write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                   stub_va, stack_bottom,
                                   (unsigned long)lstar_enter);
    stub_va += offset;

    if ( cpu_has_sep )
    {
        /* SYSENTER entry. */
        wrmsrns(MSR_IA32_SYSENTER_ESP, stack_bottom);
        wrmsrns(MSR_IA32_SYSENTER_EIP, (unsigned long)sysenter_entry);
        wrmsrns(MSR_IA32_SYSENTER_CS,  __HYPERVISOR_CS);
    }

    /* Trampoline for SYSCALL entry from compatibility mode. */
    wrmsrns(MSR_CSTAR, stub_va);
    offset += write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                    stub_va, stack_bottom,
                                    (unsigned long)cstar_enter);

    /* Don't consume more than half of the stub space here. */
    ASSERT(offset <= STUB_BUF_SIZE / 2);

    unmap_domain_page(stub_page);

    /* Common SYSCALL parameters. */
    wrmsrns(MSR_STAR, XEN_MSR_STAR);
    wrmsrns(MSR_SYSCALL_MASK, XEN_SYSCALL_MASK);
}

static void __init init_ler(void)
{
    unsigned int msr = 0;

    if ( !opt_ler )
        return;

    /*
     * Intel Pentium 4 is the only known CPU to not use the architectural MSR
     * indicies.
     */
    switch ( boot_cpu_data.vendor )
    {
    case X86_VENDOR_INTEL:
        if ( boot_cpu_data.family == 0xf )
        {
            msr = MSR_P4_LER_FROM_LIP;
            break;
        }
        fallthrough;
    case X86_VENDOR_AMD:
    case X86_VENDOR_HYGON:
        msr = MSR_IA32_LASTINTFROMIP;
        break;
    }

    if ( msr == 0 )
    {
        printk(XENLOG_WARNING "LER disabled: failed to identify MSRs\n");
        return;
    }

    ler_msr = msr;
    setup_force_cpu_cap(X86_FEATURE_XEN_LBR);
}

/*
 * Set up all MSRs relevant for FRED event delivery.
 *
 * Xen does not use any of the optional config in MSR_FRED_CONFIG, so all that
 * is needed is the entrypoint.
 *
 * Because FRED always provides a good stack, NMI and #DB do not need any
 * special treatment.  Only #DF needs another stack level, and #MC for the
 * off-chance that Xen's main stack suffers an uncorrectable error.
 *
 * This makes Stack Level 1 unused, but we use #DB's stacks, and with the
 * regular and shadow stack pointers reversed as poison to guarantee that any
 * use escalates to #DF.
 *
 * FRED reuses MSR_STAR to provide the segment selector values to load on
 * entry from Ring3.  Entry from Ring0 leave %cs and %ss unmodified.
 */
static void init_fred(void)
{
    unsigned long stack_top = get_stack_bottom() & ~(STACK_SIZE - 1);

    ASSERT(opt_fred == 1);

    wrmsrns(MSR_STAR, XEN_MSR_STAR);
    wrmsrns(MSR_FRED_CONFIG, (unsigned long)entry_FRED_R3);

    /*
     * MSR_FRED_RSP_* all come with an 64-byte alignment check, avoiding the
     * need for an explicit BUG_ON().
     */
    wrmsrns(MSR_FRED_RSP_SL0, (unsigned long)(&get_cpu_info()->_fred + 1));
    wrmsrns(MSR_FRED_RSP_SL1, stack_top + (IST_DB * IST_SHSTK_SIZE)); /* Poison */
    wrmsrns(MSR_FRED_RSP_SL2, stack_top + (1 + IST_MCE)  * PAGE_SIZE);
    wrmsrns(MSR_FRED_RSP_SL3, stack_top + (1 + IST_DF)   * PAGE_SIZE);
    wrmsrns(MSR_FRED_STK_LVLS, ((2UL << (X86_EXC_MC * 2)) |
                                (3UL << (X86_EXC_DF * 2))));

    if ( cpu_has_xen_shstk )
    {
        wrmsrns(MSR_FRED_SSP_SL0, stack_top + (PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE);
        wrmsrns(MSR_FRED_SSP_SL1, stack_top + (1 + IST_DB) * PAGE_SIZE); /* Poison */
        wrmsrns(MSR_FRED_SSP_SL2, stack_top + (IST_MCE * IST_SHSTK_SIZE));
        wrmsrns(MSR_FRED_SSP_SL3, stack_top + (IST_DF  * IST_SHSTK_SIZE));
    }
}

/*
 * Set up a minimal TSS and selector for use in FRED mode.
 *
 * With FRED moving the stack pointers into MSRs, we would like to avoid
 * having a TSS at all, but:
 *  - VT-x VMExit unconditionally sets TR.limit to 0x67, meaning that
 *    HOST_TR_BASE needs to point to a good TSS.
 *  - show_stack_overflow() cross-checks tss->rsp0.
 *
 * Fill in rsp0 and the bitmap offset, and load a zero-length TR.  If VT-x
 * does get used, it will clobber TR to refer to this_cpu(tss_page).tss.
 */
static void init_fred_tss(void)
{
    seg_desc_t *gdt = this_cpu(gdt) - FIRST_RESERVED_GDT_ENTRY;
    struct tss64 *tss = &this_cpu(tss_page).tss;

    tss->rsp0 = get_stack_bottom();
    tss->bitmap = IOBMP_INVALID_OFFSET;

    _set_tssldt_desc(gdt + TSS_ENTRY, 0, 0, SYS_DESC_tss_avail);
    ltr(TSS_SELECTOR);
}

/*
 * Configure basic exception handling.  This is prior to parsing the command
 * line or configuring a console, and needs to be as simple as possible.
 *
 * boot_gdt is already loaded, and bsp_idt[] is constructed without IST
 * settings, so we don't need a TSS configured yet.
 */
void __init bsp_early_traps_init(void)
{
    const struct desc_ptr idtr = {
        .base = (unsigned long)bsp_idt,
        .limit = sizeof(bsp_idt) - 1,
    };

    lidt(&idtr);

    /* Invalidate TR/LDTR as they're not set up yet. */
    _set_tssldt_desc(boot_gdt + TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
                     0, 0, SYS_DESC_tss_avail);

    ltr(TSS_SELECTOR);
    lldt(0);

    /* Set up the BSPs per-cpu references. */
    this_cpu(idt) = bsp_idt;
    this_cpu(gdt) = boot_gdt;
    if ( IS_ENABLED(CONFIG_PV32) )
        this_cpu(compat_gdt) = boot_compat_gdt;
}

/*
 * Configure complete exception, interrupt and syscall handling.
 */
void __init traps_init(void)
{
    /* Replace early pagefault with real pagefault handler. */
    _update_gate_addr_lower(&bsp_idt[X86_EXC_PF], entry_PF);

    /*
     * Xen doesn't use GS like most software does, and doesn't need the LKGS
     * instruction in order to manage PV guests.  No need to check for it.
     */
    if ( !cpu_has_fred )
    {
        if ( opt_fred == 1 )
            printk(XENLOG_WARNING "FRED not available, ignoring\n");
        opt_fred = 0;
    }

    if ( opt_fred == -1 )
        opt_fred = !pv_shim;

    if ( opt_fred )
    {
        const struct desc_ptr idtr = {};

#ifdef CONFIG_PV32
        if ( opt_pv32 )
        {
            opt_pv32 = 0;
            printk(XENLOG_INFO "Disabling PV32 due to FRED\n");
        }
#endif

        init_fred();
        set_in_cr4(X86_CR4_FRED);

        /*
         * Invalidate the IDT as it's not used.  Set up a minimal TSS.  The
         * LDT was configured by bsp_early_traps_init().
         */
        lidt(&idtr);
        init_fred_tss();

        setup_force_cpu_cap(X86_FEATURE_XEN_FRED);
        printk("Using FRED event delivery\n");
    }
    else
    {
        load_system_tables();

        printk("Using IDT event delivery\n");
    }

    init_ler();

    percpu_traps_init();
}

/*
 * Re-initialise all state referencing the early-boot stack.
 *
 * This is called twice during boot, first to ensure legacy_syscall_init() has
 * run (deferred from earlier), and second when the virtual address of the BSP
 * stack changes.
 */
void __init bsp_traps_reinit(void)
{
    if ( opt_fred )
        init_fred();
    else
        load_system_tables();

    percpu_traps_init();
}

/*
 * Set up per-CPU linkage registers for exception, interrupt and syscall
 * handling.
 */
void percpu_traps_init(void)
{
    /*
     * Skip legacy_syscall_init() at early boot.  It requires the stubs being
     * allocated, limiting the placement of the traps_init() call, and gets
     * re-done anyway by bsp_traps_reinit().
     */
    if ( !opt_fred && system_state > SYS_STATE_early_boot )
        legacy_syscall_init();

    if ( cpu_has_xen_lbr )
        wrmsrl(MSR_IA32_DEBUGCTLMSR, IA32_DEBUGCTLMSR_LBR);
}

/*
 * Configure exception handling on APs and S3.  Called before entering C
 * properly, and before shadow stacks are activated.
 *
 * boot_gdt is currently loaded, and we must switch to our local GDT.  The
 * local IDT has unknown IST-ness.
 */
void asmlinkage percpu_early_traps_init(void)
{
    if ( opt_fred )
    {
        seg_desc_t *gdt = this_cpu(gdt) - FIRST_RESERVED_GDT_ENTRY;
        const struct desc_ptr gdtr = {
            .base = (unsigned long)gdt,
            .limit = LAST_RESERVED_GDT_BYTE,
        }, idtr = {};

        lgdt(&gdtr);

        init_fred();
        write_cr4(read_cr4() | X86_CR4_FRED);

        /*
         * Invalidate the IDT (not used) and LDT (not set up yet).  Set up a
         * minimal TSS.
         */
        lidt(&idtr);
        init_fred_tss();
        lldt(0);
    }
    else
        load_system_tables();
}

static void __init __maybe_unused build_assertions(void)
{
    /*
     * This is best-effort (it doesn't cover some padding corner cases), but
     * is preferable to hitting the check at boot time.
     *
     * tss->rsp0, pointing at the end of cpu_info.guest_cpu_user_regs, must be
     * 16-byte aligned.
     *
     * MSR_FRED_RSP_SL0, pointing to the end of cpu_info._fred must be 64-byte
     * aligned.
     */
    BUILD_BUG_ON((sizeof(struct cpu_info) -
                  endof_field(struct cpu_info, guest_cpu_user_regs)) & 15);
    BUILD_BUG_ON((sizeof(struct cpu_info) -
                  endof_field(struct cpu_info, _fred)) & 63);

    /*
     * The x86 architecture is happy with TR.limit being less than 0x67, but
     * VT-x is not.  VMExit unconditionally sets the limit to 0x67, meaning
     * that HOST_TR_BASE needs to refer to a good TSS of at least this size.
     */
    BUILD_BUG_ON(sizeof(struct tss64) <= 0x67);
}
