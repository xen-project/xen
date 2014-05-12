/*
 * Portions are:
 *  Copyright (c) 2002 Pavel Machek <pavel@suse.cz>
 *  Copyright (c) 2001 Patrick Mochel <mochel@osdl.org>
 */

#include <xen/config.h>
#include <xen/acpi.h>
#include <xen/smp.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/debugreg.h>
#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <xen/hypercall.h>

static unsigned long saved_lstar, saved_cstar;
static unsigned long saved_sysenter_esp, saved_sysenter_eip;
static unsigned long saved_fs_base, saved_gs_base, saved_kernel_gs_base;
static uint16_t saved_segs[4];
static uint64_t saved_xcr0;

void save_rest_processor_state(void)
{
    vcpu_save_fpu(current);

    asm volatile (
        "movw %%ds,(%0); movw %%es,2(%0); movw %%fs,4(%0); movw %%gs,6(%0)"
        : : "r" (saved_segs) : "memory" );
    saved_fs_base = rdfsbase();
    saved_gs_base = rdgsbase();
    rdmsrl(MSR_SHADOW_GS_BASE, saved_kernel_gs_base);
    rdmsrl(MSR_CSTAR, saved_cstar);
    rdmsrl(MSR_LSTAR, saved_lstar);
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
         boot_cpu_data.x86_vendor == X86_VENDOR_CENTAUR )
    {
        rdmsrl(MSR_IA32_SYSENTER_ESP, saved_sysenter_esp);
        rdmsrl(MSR_IA32_SYSENTER_EIP, saved_sysenter_eip);
    }
    if ( cpu_has_xsave )
        saved_xcr0 = get_xcr0();
}


void restore_rest_processor_state(void)
{
    struct vcpu *curr = current;

    load_TR();

    /* Recover syscall MSRs */
    wrmsrl(MSR_LSTAR, saved_lstar);
    wrmsrl(MSR_CSTAR, saved_cstar);
    wrmsr(MSR_STAR, 0, (FLAT_RING3_CS32<<16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, XEN_SYSCALL_MASK, 0U);

    wrfsbase(saved_fs_base);
    wrgsbase(saved_gs_base);
    wrmsrl(MSR_SHADOW_GS_BASE, saved_kernel_gs_base);

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
         boot_cpu_data.x86_vendor == X86_VENDOR_CENTAUR )
    {
        /* Recover sysenter MSRs */
        wrmsrl(MSR_IA32_SYSENTER_ESP, saved_sysenter_esp);
        wrmsrl(MSR_IA32_SYSENTER_EIP, saved_sysenter_eip);
        wrmsr(MSR_IA32_SYSENTER_CS, __HYPERVISOR_CS, 0);
    }

    if ( !is_idle_vcpu(curr) )
    {
        asm volatile (
            "movw (%0),%%ds; movw 2(%0),%%es; movw 4(%0),%%fs"
            : : "r" (saved_segs) : "memory" );
        do_set_segment_base(SEGBASE_GS_USER_SEL, saved_segs[3]);
    }

    if ( cpu_has_xsave && !set_xcr0(saved_xcr0) )
        BUG();

    /* Maybe load the debug registers. */
    BUG_ON(!is_pv_vcpu(curr));
    if ( !is_idle_vcpu(curr) && curr->arch.debugreg[7] )
    {
        write_debugreg(0, curr->arch.debugreg[0]);
        write_debugreg(1, curr->arch.debugreg[1]);
        write_debugreg(2, curr->arch.debugreg[2]);
        write_debugreg(3, curr->arch.debugreg[3]);
        write_debugreg(6, curr->arch.debugreg[6]);
        write_debugreg(7, curr->arch.debugreg[7]);
    }

    /* Reload FPU state on next FPU use. */
    stts();

    if (cpu_has_pat)
        wrmsrl(MSR_IA32_CR_PAT, host_pat);

    mtrr_bp_restore();
}
