/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <xen/init.h>
#include <xen/param.h>

#include <asm/idt.h>
#include <asm/msr.h>
#include <asm/shstk.h>
#include <asm/system.h>
#include <asm/traps.h>

DEFINE_PER_CPU_READ_MOSTLY(idt_entry_t *, idt);

/* LastExceptionFromIP on this hardware.  Zero if LER is not in use. */
unsigned int __ro_after_init ler_msr;
static bool __initdata opt_ler;
boolean_param("ler", opt_ler);

void nocall entry_PF(void);

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

static void __init init_ler(void)
{
    unsigned int msr = 0;

    if ( !opt_ler )
        return;

    /*
     * Intel Pentium 4 is the only known CPU to not use the architectural MSR
     * indicies.
     */
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        if ( boot_cpu_data.x86 == 0xf )
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

    load_system_tables();

    init_ler();

    /* Cache {,compat_}gdt_l1e now that physically relocation is done. */
    this_cpu(gdt_l1e) =
        l1e_from_pfn(virt_to_mfn(boot_gdt), __PAGE_HYPERVISOR_RW);
    if ( IS_ENABLED(CONFIG_PV32) )
        this_cpu(compat_gdt_l1e) =
            l1e_from_pfn(virt_to_mfn(boot_compat_gdt), __PAGE_HYPERVISOR_RW);

    percpu_traps_init();
}

/*
 * Re-initialise all state referencing the early-boot stack.
 */
void __init bsp_traps_reinit(void)
{
    load_system_tables();
    percpu_traps_init();
}

/*
 * Set up per-CPU linkage registers for exception, interrupt and syscall
 * handling.
 */
void percpu_traps_init(void)
{
    subarch_percpu_traps_init();

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
     */
    BUILD_BUG_ON((sizeof(struct cpu_info) -
                  endof_field(struct cpu_info, guest_cpu_user_regs)) & 15);
}
