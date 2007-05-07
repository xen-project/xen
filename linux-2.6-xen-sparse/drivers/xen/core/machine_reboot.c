#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <linux/stringify.h>
#include <linux/stop_machine.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <xen/evtchn.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <xen/gnttab.h>
#include <xen/xencons.h>
#include <xen/cpu_hotplug.h>
#include <xen/interface/vcpu.h>

#if defined(__i386__) || defined(__x86_64__)

/*
 * Power off function, if any
 */
void (*pm_power_off)(void);
EXPORT_SYMBOL(pm_power_off);

void machine_emergency_restart(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	HYPERVISOR_shutdown(SHUTDOWN_reboot);
}

void machine_restart(char * __unused)
{
	machine_emergency_restart();
}

void machine_halt(void)
{
	machine_power_off();
}

void machine_power_off(void)
{
	/* We really want to get pending console data out before we die. */
	xencons_force_flush();
	if (pm_power_off)
		pm_power_off();
	HYPERVISOR_shutdown(SHUTDOWN_poweroff);
}

int reboot_thru_bios = 0;	/* for dmi_scan.c */
EXPORT_SYMBOL(machine_restart);
EXPORT_SYMBOL(machine_halt);
EXPORT_SYMBOL(machine_power_off);

static void pre_suspend(void)
{
	HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
	HYPERVISOR_update_va_mapping(fix_to_virt(FIX_SHARED_INFO),
				     __pte_ma(0), 0);

	xen_start_info->store_mfn = mfn_to_pfn(xen_start_info->store_mfn);
	xen_start_info->console.domU.mfn =
		mfn_to_pfn(xen_start_info->console.domU.mfn);
}

static void post_suspend(int suspend_cancelled)
{
	int i, j, k, fpp;
	unsigned long shinfo_mfn;
	extern unsigned long max_pfn;
	extern unsigned long *pfn_to_mfn_frame_list_list;
	extern unsigned long *pfn_to_mfn_frame_list[];

	if (suspend_cancelled) {
		xen_start_info->store_mfn =
			pfn_to_mfn(xen_start_info->store_mfn);
		xen_start_info->console.domU.mfn =
			pfn_to_mfn(xen_start_info->console.domU.mfn);
	} else {
#ifdef CONFIG_SMP
		cpu_initialized_map = cpu_online_map;
#endif
	}

	shinfo_mfn = xen_start_info->shared_info >> PAGE_SHIFT;
	HYPERVISOR_update_va_mapping(fix_to_virt(FIX_SHARED_INFO),
				     pfn_pte_ma(shinfo_mfn, PAGE_KERNEL), 0);
	HYPERVISOR_shared_info = (shared_info_t *)fix_to_virt(FIX_SHARED_INFO);

	memset(empty_zero_page, 0, PAGE_SIZE);

	fpp = PAGE_SIZE/sizeof(unsigned long);
	for (i = 0, j = 0, k = -1; i < max_pfn; i += fpp, j++) {
		if ((j % fpp) == 0) {
			k++;
			pfn_to_mfn_frame_list_list[k] =
				virt_to_mfn(pfn_to_mfn_frame_list[k]);
			j = 0;
		}
		pfn_to_mfn_frame_list[k][j] =
			virt_to_mfn(&phys_to_machine_mapping[i]);
	}
	HYPERVISOR_shared_info->arch.max_pfn = max_pfn;
	HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
		virt_to_mfn(pfn_to_mfn_frame_list_list);
}

#else /* !(defined(__i386__) || defined(__x86_64__)) */

#ifndef HAVE_XEN_PRE_SUSPEND
#define xen_pre_suspend()	((void)0)
#endif

#ifndef HAVE_XEN_POST_SUSPEND
#define xen_post_suspend(x)	((void)0)
#endif

#define switch_idle_mm()	((void)0)
#define mm_pin_all()		((void)0)
#define pre_suspend()		xen_pre_suspend()
#define post_suspend(x)		xen_post_suspend(x)

#endif

static int take_machine_down(void *p_fast_suspend)
{
	int fast_suspend = *(int *)p_fast_suspend;
	int suspend_cancelled, err;
	extern void time_resume(void);

	if (fast_suspend) {
		BUG_ON(!irqs_disabled());
	} else {
		BUG_ON(irqs_disabled());

		for (;;) {
			err = smp_suspend();
			if (err)
				return err;

			xenbus_suspend();
			preempt_disable();

			if (num_online_cpus() == 1)
				break;

			preempt_enable();
			xenbus_suspend_cancel();
		}

		local_irq_disable();
	}

	mm_pin_all();
	gnttab_suspend();
	pre_suspend();

	/*
	 * This hypercall returns 1 if suspend was cancelled or the domain was
	 * merely checkpointed, and 0 if it is resuming in a new domain.
	 */
	suspend_cancelled = HYPERVISOR_suspend(virt_to_mfn(xen_start_info));

	post_suspend(suspend_cancelled);
	gnttab_resume();
	if (!suspend_cancelled) {
		irq_resume();
#ifdef __x86_64__
		/*
		 * Older versions of Xen do not save/restore the user %cr3.
		 * We do it here just in case, but there's no need if we are
		 * in fast-suspend mode as that implies a new enough Xen.
		 */
		if (!fast_suspend) {
			struct mmuext_op op;
			op.cmd = MMUEXT_NEW_USER_BASEPTR;
			op.arg1.mfn = pfn_to_mfn(__pa(__user_pgd(
				current->active_mm->pgd)) >> PAGE_SHIFT);
			if (HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF))
				BUG();
		}
#endif
	}
	time_resume();

	if (!fast_suspend)
		local_irq_enable();

	return suspend_cancelled;
}

int __xen_suspend(int fast_suspend)
{
	int err, suspend_cancelled;

	BUG_ON(smp_processor_id() != 0);
	BUG_ON(in_interrupt());

#if defined(__i386__) || defined(__x86_64__)
	if (xen_feature(XENFEAT_auto_translated_physmap)) {
		printk(KERN_WARNING "Cannot suspend in "
		       "auto_translated_physmap mode.\n");
		return -EOPNOTSUPP;
	}
#endif

	/* If we are definitely UP then 'slow mode' is actually faster. */
	if (num_possible_cpus() == 1)
		fast_suspend = 0;

	if (fast_suspend) {
		xenbus_suspend();
		err = stop_machine_run(take_machine_down, &fast_suspend, 0);
		if (err < 0)
			xenbus_suspend_cancel();
	} else {
		err = take_machine_down(&fast_suspend);
	}

	if (err < 0)
		return err;

	suspend_cancelled = err;
	if (!suspend_cancelled) {
		xencons_resume();
		xenbus_resume();
	} else {
		xenbus_suspend_cancel();
	}

	if (!fast_suspend)
		smp_resume();

	return 0;
}
