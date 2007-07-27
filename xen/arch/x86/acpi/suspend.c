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
#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>

#if defined(CONFIG_X86_64)
static unsigned long saved_lstar, saved_cstar;
#endif

void save_rest_processor_state(void)
{
    if ( !is_idle_vcpu(current) )
        unlazy_fpu(current);

#if defined(CONFIG_X86_64)
    rdmsrl(MSR_CSTAR, saved_cstar);
    rdmsrl(MSR_LSTAR, saved_lstar);
#endif
}

#define loaddebug(_v,_reg) \
    __asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_v)->debugreg[_reg]))

void restore_rest_processor_state(void)
{
    int cpu = smp_processor_id();
    struct tss_struct *t = &init_tss[cpu];
    struct vcpu *v = current;

    /* Rewriting the TSS desc is necessary to clear the Busy flag. */
    set_tss_desc(cpu, t);
    load_TR(cpu);

#if defined(CONFIG_X86_64)
    /* Recover syscall MSRs */
    wrmsrl(MSR_LSTAR, saved_lstar);
    wrmsrl(MSR_CSTAR, saved_cstar);
    wrmsr(MSR_STAR, 0, (FLAT_RING3_CS32<<16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, EF_VM|EF_RF|EF_NT|EF_DF|EF_IE|EF_TF, 0U);    
#else /* !defined(CONFIG_X86_64) */
    if ( supervisor_mode_kernel && cpu_has_sep )
        wrmsr(MSR_IA32_SYSENTER_ESP, &t->esp1, 0);
#endif

    /* Maybe load the debug registers. */
    if ( !is_idle_vcpu(v) && unlikely(v->arch.guest_context.debugreg[7]) )
    {
        loaddebug(&v->arch.guest_context, 0);
        loaddebug(&v->arch.guest_context, 1);
        loaddebug(&v->arch.guest_context, 2);
        loaddebug(&v->arch.guest_context, 3);
        /* no 4 and 5 */
        loaddebug(&v->arch.guest_context, 6);
        loaddebug(&v->arch.guest_context, 7);
    }

    /* Reload FPU state on next FPU use. */
    stts();

    mtrr_ap_init();
    mcheck_init(&boot_cpu_data);
}
