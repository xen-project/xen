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
#include <asm/kexec.h>
#include <xen/sched.h>

void machine_crash_shutdown(void)
{
    crash_xen_info_t *info;
    unsigned long dom0_mm_pgd_mfn;

    if (in_interrupt())
        ia64_eoi();
    kexec_crash_save_info();
    info = kexec_crash_save_info();
    /* Info is not word aligned on ia64 */
    dom0_mm_pgd_mfn = __pa(dom0->arch.mm.pgd) >> PAGE_SHIFT;
    memcpy((char *)info + offsetof(crash_xen_info_t, dom0_mm_pgd_mfn),
	   &dom0_mm_pgd_mfn, sizeof(dom0_mm_pgd_mfn));
    kexec_disable_iosapic();
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

