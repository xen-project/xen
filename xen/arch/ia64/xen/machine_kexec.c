/******************************************************************************
 * machine_kexec.c
 *
 * Based on arch/ia64/kernel/machine_kexec.c from Linux 2.6.20-rc1
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <asm/smp.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/smp.h>
#include <xen/acpi.h>
#include <public/kexec.h>
#include <linux/efi.h>
#include <asm/delay.h>
#include <asm/meminit.h>
#include <asm/hw_irq.h>
#include <asm/kexec.h>
#include <asm/vhpt.h>
#include <linux/cpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <asm/dom_fw_dom0.h>

typedef asmlinkage NORET_TYPE void (*relocate_new_kernel_t)(
					unsigned long indirection_page,
					unsigned long start_address,
					struct ia64_boot_param *boot_param,
					unsigned long pal_addr,
					unsigned long cpu_data_pa,
					unsigned long kernel_start,
					unsigned long page_offset,
					unsigned long vhpt)
					ATTRIB_NORET;

#define kexec_flush_icache_page(page)					\
do {									\
	unsigned long page_addr = (unsigned long)page_address(page);	\
	flush_icache_range(page_addr, page_addr + PAGE_SIZE);		\
} while(0)

int machine_kexec_load(int type, int slot, xen_kexec_image_t *image)
{
	return 0;
}

void machine_kexec_unload(int type, int slot, xen_kexec_image_t *image)
{
}

static void ia64_machine_kexec(struct unw_frame_info *info, void *arg)
{
	xen_kexec_image_t *image = arg;
	relocate_new_kernel_t rnk;
	unsigned long code_addr = (unsigned long)
				  __va(image->reboot_code_buffer);
	unsigned long cpu_data_pa = (unsigned long)
				  __pa(cpu_data(smp_processor_id()));
	unsigned long vhpt;
	int ii;

	/* Interrupts aren't acceptable while we reboot */
	local_irq_disable();

	/* Mask CMC and Performance Monitor interrupts */
	ia64_setreg(_IA64_REG_CR_PMV, 1 << 16);
	ia64_setreg(_IA64_REG_CR_CMCV, 1 << 16);

	/* Mask ITV and Local Redirect Registers */
	ia64_set_itv(1 << 16);
	ia64_set_lrr0(1 << 16);
	ia64_set_lrr1(1 << 16);

	/* terminate possible nested in-service interrupts */
	for (ii = 0; ii < 16; ii++)
		ia64_eoi();

	/* unmask TPR and clear any pending interrupts */
	ia64_setreg(_IA64_REG_CR_TPR, 0);
	ia64_srlz_d();
	while (ia64_get_ivr() != IA64_SPURIOUS_INT_VECTOR)
		ia64_eoi();
	platform_kernel_launch_event();
	vhpt = __va_ul(vcpu_vhpt_maddr(current));
	BUG_ON(!vhpt);
	rnk = (relocate_new_kernel_t)&code_addr;
	(*rnk)(image->indirection_page, image->start_address, ia64_boot_param,
	       GRANULEROUNDDOWN((unsigned long) pal_vaddr), cpu_data_pa,
	       KERNEL_START, PAGE_OFFSET, vhpt);
	BUG();
}

#if CONFIG_SMP
/* Need to implement some subset of hotplug-cpu - enough to
 * send a cpu into rendevouz */

/* N.B: The tasks frozen parameter can probably be dropped
 *      This can probably be rolled into cpu_down
 */
static int _cpu_down(unsigned int cpu, int tasks_frozen)
{
	if (num_online_cpus() == 1)
		return -EBUSY;

	if (!cpu_online(cpu))
		return -EINVAL;

#ifndef XEN
	/* XXX: What, if anything, should Xen do here? */
	/* Ensure that we are not runnable on dying cpu */
	old_affinity = current->cpus_allowed;
	tmp = CPU_MASK_ALL;
	cpu_clear(cpu, tmp);
       set_cpus_allowed(current, tmp);
#endif

	cpu_clear(cpu, cpu_online_map);

	__cpu_die(cpu);

	return 0;
}

static int cpu_down(unsigned int cpu)
{
	int err;

	/* Unlike Linux there is no lock, as there are no other callers
	 * and no other CPUS. */
	err = _cpu_down(cpu, 0);

	return 0;
}
#endif /* SMP */

/* This should probably be an arch-hook called from kexec_exec()
 * Its also likely that it should be in the xen equivalent of
 * arch/ia64/kernel/process.c */
static void machine_shutdown(void)
{
#ifdef CONFIG_SMP
	unsigned int cpu;

	for_each_online_cpu(cpu) {
		if (cpu != smp_processor_id())
			cpu_down(cpu);
	}
#endif
	kexec_disable_iosapic();
	acpi_restore_tables();
}

void machine_kexec(xen_kexec_image_t *image)
{
	machine_shutdown();
	unw_init_running(ia64_machine_kexec, image);
	for(;;);
}

void machine_reboot_kexec(xen_kexec_image_t *image)
{
	machine_kexec(image);
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
