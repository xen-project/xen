/******************************************************************************
 * crash.c
 *
 * Based heavily on arch/i386/kernel/crash.c from Linux 2.6.16
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <asm/atomic.h>
#include <asm/elf.h>
#include <asm/percpu.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <asm/nmi.h>
#include <xen/string.h>
#include <xen/elf.h>
#include <xen/elfcore.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/perfc.h>
#include <xen/kexec.h>
#include <xen/sched.h>
#include <xen/keyhandler.h>
#include <public/xen.h>
#include <asm/shared.h>
#include <asm/hvm/support.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <xen/iommu.h>
#include <asm/hpet.h>

static cpumask_t waiting_to_crash;
static unsigned int crashing_cpu;
static DEFINE_PER_CPU_READ_MOSTLY(bool_t, crash_save_done);

/* This becomes the NMI handler for non-crashing CPUs, when Xen is crashing. */
static void noreturn do_nmi_crash(const struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();

    stac();

    /* nmi_shootdown_cpus() should ensure that this assertion is correct. */
    ASSERT(cpu != crashing_cpu);

    /* Save crash information and shut down CPU.  Attempt only once. */
    if ( !this_cpu(crash_save_done) )
    {
        /* Disable the interrupt stack table for the MCE handler.  This
         * prevents race conditions between clearing MCIP and receving a
         * new MCE, during which the exception frame would be clobbered
         * and the MCE handler fall into an infinite loop.  We are soon
         * going to disable the NMI watchdog, so the loop would not be
         * caught.
         *
         * We do not need to change the NMI IST, as the nmi_crash
         * handler is immue to corrupt exception frames, by virtue of
         * being designed never to return.
         *
         * This update is safe from a security point of view, as this
         * pcpu is never going to try to sysret back to a PV vcpu.
         */
        set_ist(&idt_tables[cpu][TRAP_machine_check], IST_NONE);

        kexec_crash_save_cpu();
        __stop_this_cpu();

        this_cpu(crash_save_done) = 1;
        cpumask_clear_cpu(cpu, &waiting_to_crash);
    }

    /* Poor mans self_nmi().  __stop_this_cpu() has reverted the LAPIC
     * back to its boot state, so we are unable to rely on the regular
     * apic_* functions, due to 'x2apic_enabled' being possibly wrong.
     * (The likely scenario is that we have reverted from x2apic mode to
     * xapic, at which point #GPFs will occur if we use the apic_*
     * functions)
     *
     * The ICR and APIC ID of the LAPIC are still valid even during
     * software disable (Intel SDM Vol 3, 10.4.7.2).  As a result, we
     * can deliberately queue up another NMI at the LAPIC which will not
     * be delivered as the hardware NMI latch is currently in effect.
     * This means that if NMIs become unlatched (e.g. following a
     * non-fatal MCE), the LAPIC will force us back here rather than
     * wandering back into regular Xen code.
     */
    switch ( current_local_apic_mode() )
    {
        u32 apic_id;

    case APIC_MODE_X2APIC:
        apic_id = apic_rdmsr(APIC_ID);

        apic_wrmsr(APIC_ICR, APIC_DM_NMI | APIC_DEST_PHYSICAL
                   | ((u64)apic_id << 32));
        break;

    case APIC_MODE_XAPIC:
        apic_id = GET_xAPIC_ID(apic_mem_read(APIC_ID));

        while ( apic_mem_read(APIC_ICR) & APIC_ICR_BUSY )
            cpu_relax();

        apic_mem_write(APIC_ICR2, apic_id << 24);
        apic_mem_write(APIC_ICR, APIC_DM_NMI | APIC_DEST_PHYSICAL);
        break;

    default:
        break;
    }

    for ( ; ; )
        halt();
}

static void nmi_shootdown_cpus(void)
{
    unsigned long msecs;
    unsigned int cpu = smp_processor_id();

    disable_lapic_nmi_watchdog();
    local_irq_disable();

    crashing_cpu = cpu;
    local_irq_count(crashing_cpu) = 0;

    cpumask_andnot(&waiting_to_crash, &cpu_online_map, cpumask_of(cpu));

    /*
     * Disable IST for MCEs to avoid stack corruption race conditions, and
     * change the NMI handler to a nop to avoid deviation from this codepath.
     */
    _set_gate_lower(&idt_tables[cpu][TRAP_nmi],
                    SYS_DESC_irq_gate, 0, &trap_nop);
    set_ist(&idt_tables[cpu][TRAP_machine_check], IST_NONE);

    /*
     * Ideally would be:
     *   exception_table[TRAP_nmi] = &do_nmi_crash;
     *
     * but the exception_table is read only.  Access it via its directmap
     * mappings.
     */
    write_atomic((unsigned long *)__va(__pa(&exception_table[TRAP_nmi])),
                 (unsigned long)&do_nmi_crash);

    /* Ensure the new callback function is set before sending out the NMI. */
    wmb();

    smp_send_nmi_allbutself();

    msecs = 1000; /* Wait at most a second for the other cpus to stop */
    while ( !cpumask_empty(&waiting_to_crash) && msecs )
    {
        mdelay(1);
        msecs--;
    }

    /* Leave a hint of how well we did trying to shoot down the other cpus */
    if ( cpumask_empty(&waiting_to_crash) )
        printk("Shot down all CPUs\n");
    else
    {
        cpulist_scnprintf(keyhandler_scratch, sizeof keyhandler_scratch,
                          &waiting_to_crash);
        printk("Failed to shoot down CPUs {%s}\n", keyhandler_scratch);
    }

    /* Crash shutdown any IOMMU functionality as the crashdump kernel is not
     * happy when booting if interrupt/dma remapping is still enabled */
    iommu_crash_shutdown();

    __stop_this_cpu();

    /* This is a bit of a hack due to the problems with the x2apic_enabled
     * variable, but we can't do any better without a significant refactoring
     * of the APIC code */
    x2apic_enabled = (current_local_apic_mode() == APIC_MODE_X2APIC);

    disable_IO_APIC();
    hpet_disable();
}

void machine_crash_shutdown(void)
{
    crash_xen_info_t *info;

    nmi_shootdown_cpus();

    info = kexec_crash_save_info();
    info->xen_phys_start = xen_phys_start;
    info->dom0_pfn_to_mfn_frame_list_list =
        arch_get_pfn_to_mfn_frame_list_list(hardware_domain);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
