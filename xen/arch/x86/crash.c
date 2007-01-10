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
#include <asm/kexec.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <asm/ipi.h>
#include <asm/nmi.h>
#include <xen/string.h>
#include <xen/elf.h>
#include <xen/elfcore.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/perfc.h>
#include <xen/kexec.h>
#include <xen/sched.h>
#include <public/xen.h>
#include <asm/shared.h>
#include <asm/hvm/hvm.h>

static atomic_t waiting_for_crash_ipi;
static unsigned int crashing_cpu;

static int crash_nmi_callback(struct cpu_user_regs *regs, int cpu)
{
    /* Don't do anything if this handler is invoked on crashing cpu.
     * Otherwise, system will completely hang. Crashing cpu can get
     * an NMI if system was initially booted with nmi_watchdog parameter.
     */
    if ( cpu == crashing_cpu )
        return 1;
    local_irq_disable();

    kexec_crash_save_cpu();
    disable_local_APIC();
    atomic_dec(&waiting_for_crash_ipi);
    hvm_disable();

    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );

    return 1;
}

/*
 * By using the NMI code instead of a vector we just sneak thru the
 * word generator coming out with just what we want.  AND it does
 * not matter if clustered_apic_mode is set or not.
 */
static void smp_send_nmi_allbutself(void)
{
    cpumask_t allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);
    if ( !cpus_empty(allbutself) )
        send_IPI_mask(allbutself, APIC_DM_NMI);
}

static void nmi_shootdown_cpus(void)
{
    unsigned long msecs;

    crashing_cpu = smp_processor_id();

    atomic_set(&waiting_for_crash_ipi, num_online_cpus() - 1);
    /* Would it be better to replace the trap vector here? */
    set_nmi_callback(crash_nmi_callback);
    /* Ensure the new callback function is set before sending out the NMI. */
    wmb();

    smp_send_nmi_allbutself();

    msecs = 1000; /* Wait at most a second for the other cpus to stop */
    while ( (atomic_read(&waiting_for_crash_ipi) > 0) && msecs )
    {
        mdelay(1);
        msecs--;
    }

    /* Leave the nmi callback set */
    disable_local_APIC();
}

void machine_crash_shutdown(void)
{
    crash_xen_info_t *info;

    local_irq_disable();

    nmi_shootdown_cpus();

    disable_IO_APIC();

    hvm_disable();

    info = kexec_crash_save_info();
    info->dom0_pfn_to_mfn_frame_list_list =
        arch_get_pfn_to_mfn_frame_list_list(dom0);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
