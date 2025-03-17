/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <xen/init.h>
#include <xen/param.h>

#include <asm/idt.h>
#include <asm/msr.h>
#include <asm/system.h>
#include <asm/traps.h>

DEFINE_PER_CPU_READ_MOSTLY(idt_entry_t *, idt);

/* LastExceptionFromIP on this hardware.  Zero if LER is not in use. */
unsigned int __ro_after_init ler_msr;
static bool __initdata opt_ler;
boolean_param("ler", opt_ler);

void nocall entry_PF(void);

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
 * Configure complete exception, interrupt and syscall handling.
 */
void __init traps_init(void)
{
    /* Replace early pagefault with real pagefault handler. */
    _update_gate_addr_lower(&bsp_idt[X86_EXC_PF], entry_PF);

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
 * Set up per-CPU linkage registers for exception, interrupt and syscall
 * handling.
 */
void percpu_traps_init(void)
{
    subarch_percpu_traps_init();

    if ( cpu_has_xen_lbr )
        wrmsrl(MSR_IA32_DEBUGCTLMSR, IA32_DEBUGCTLMSR_LBR);
}
