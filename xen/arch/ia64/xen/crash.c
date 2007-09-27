/******************************************************************************
 * crash.c
 *
 * Based heavily on arch/ia64/kernel/crash.c from Linux 2.6.20-rc1
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <xen/types.h>         /* Should be included by xen/kexec.h ? */
#include <linux/thread_info.h> /* Should be included by linux/preempt.h ? */

#include <xen/kexec.h>
#include <linux/hardirq.h>
#include <linux/smp.h>
#include <asm/processor.h>

void machine_crash_shutdown(void)
{
    //printk("machine_crash_shutdown: %d\n", smp_processor_id());
    if (in_interrupt())
        ia64_eoi();
    kexec_crash_save_info();
    printk(__FILE__ ": %s: save the eqivalent of x86's "
           "dom0->shared_info->arch.pfn_to_mfn_frame_list_list?\n",
           __FUNCTION__);
#ifdef CONFIG_SMP
    smp_send_stop();
#endif
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

