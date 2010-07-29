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
#include <public/xen.h>
#include <asm/shared.h>
#include <asm/hvm/support.h>
#include <asm/apic.h>
#include <asm/io_apic.h>

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

    __stop_this_cpu();

    atomic_dec(&waiting_for_crash_ipi);

    for ( ; ; )
        halt();

    return 1;
}

static void nmi_shootdown_cpus(void)
{
    unsigned long msecs;

    local_irq_disable();

    crashing_cpu = smp_processor_id();
    local_irq_count(crashing_cpu) = 0;

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

    __stop_this_cpu();
    disable_IO_APIC();

    local_irq_enable();
}

void machine_crash_shutdown(void)
{
    crash_xen_info_t *info;

    nmi_shootdown_cpus();

    info = kexec_crash_save_info();
    info->xen_phys_start = xen_phys_start;
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
