/*
 * Portions are:
 *  Copyright (c) 2002 Pavel Machek <pavel@suse.cz>
 *  Copyright (c) 2001 Patrick Mochel <mochel@osdl.org>
 */

#include <xen/acpi.h>
#include <xen/smp.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/debugreg.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <xen/hypercall.h>

static unsigned long saved_lstar, saved_cstar;
static unsigned long saved_sysenter_esp, saved_sysenter_eip;
static unsigned long saved_fs_base, saved_gs_base, saved_kernel_gs_base;
static uint64_t saved_xcr0;

void save_rest_processor_state(void)
{
    saved_fs_base = rdfsbase();
    saved_gs_base = rdgsbase();
    rdmsrl(MSR_SHADOW_GS_BASE, saved_kernel_gs_base);
    rdmsrl(MSR_CSTAR, saved_cstar);
    rdmsrl(MSR_LSTAR, saved_lstar);

    if ( cpu_has_sep )
    {
        rdmsrl(MSR_IA32_SYSENTER_ESP, saved_sysenter_esp);
        rdmsrl(MSR_IA32_SYSENTER_EIP, saved_sysenter_eip);
    }

    if ( cpu_has_xsave )
        saved_xcr0 = get_xcr0();
}


void restore_rest_processor_state(void)
{
    load_system_tables();

    /* Restore full CR4 (inc MCE) now that the IDT is in place. */
    write_cr4(mmu_cr4_features);

    /* Recover syscall MSRs */
    wrmsrl(MSR_LSTAR, saved_lstar);
    wrmsrl(MSR_CSTAR, saved_cstar);
    wrmsrl(MSR_STAR, XEN_MSR_STAR);
    wrmsrl(MSR_SYSCALL_MASK, XEN_SYSCALL_MASK);

    wrfsbase(saved_fs_base);
    wrgsbase(saved_gs_base);
    wrmsrl(MSR_SHADOW_GS_BASE, saved_kernel_gs_base);

    if ( cpu_has_sep )
    {
        /* Recover sysenter MSRs */
        wrmsrl(MSR_IA32_SYSENTER_ESP, saved_sysenter_esp);
        wrmsrl(MSR_IA32_SYSENTER_EIP, saved_sysenter_eip);
        wrmsr(MSR_IA32_SYSENTER_CS, __HYPERVISOR_CS, 0);
    }

    if ( cpu_has_xsave && !set_xcr0(saved_xcr0) )
        BUG();

    wrmsrl(MSR_IA32_CR_PAT, XEN_MSR_PAT);

    mtrr_bp_restore();
}
