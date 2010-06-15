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
#include <asm-generic/sections.h>

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
	relocate_new_kernel(image->indirection_page, image->start_address,
			    __pa(ia64_boot_param), image->reboot_code_buffer);
	BUG();
}

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

static int machine_kexec_get_xen(xen_kexec_range_t *range)
{
	range->start = range->start = ia64_tpa(_text);
	range->size = (unsigned long)_end - (unsigned long)_text;
	return 0;
}

#define ELF_PAGE_SHIFT 16
#define ELF_PAGE_SIZE  (__IA64_UL_CONST(1) << ELF_PAGE_SHIFT)
#define ELF_PAGE_MASK  (~(ELF_PAGE_SIZE - 1))

static int machine_kexec_get_xenheap(xen_kexec_range_t *range)
{
	range->start = (ia64_tpa(_end) + (ELF_PAGE_SIZE - 1)) & ELF_PAGE_MASK;
	range->size =
		(((unsigned long)range->start + KERNEL_TR_PAGE_SIZE) &
         ~(KERNEL_TR_PAGE_SIZE - 1))
		- (unsigned long)range->start;
	return 0;
}

static int machine_kexec_get_boot_param(xen_kexec_range_t *range)
{
	range->start = __pa(ia64_boot_param);
	range->size = sizeof(*ia64_boot_param);
	return 0;
}

static int machine_kexec_get_efi_memmap(xen_kexec_range_t *range)
{
	range->start = ia64_boot_param->efi_memmap;
	range->size = ia64_boot_param->efi_memmap_size;
	return 0;
}

int machine_kexec_get(xen_kexec_range_t *range)
{
	switch (range->range) {
	case KEXEC_RANGE_MA_XEN:
		return machine_kexec_get_xen(range);
	case KEXEC_RANGE_MA_XENHEAP:
		return machine_kexec_get_xenheap(range);
	case KEXEC_RANGE_MA_BOOT_PARAM:
		return machine_kexec_get_boot_param(range);
	case KEXEC_RANGE_MA_EFI_MEMMAP:
		return machine_kexec_get_efi_memmap(range);
	}
	return -EINVAL;
}

void arch_crash_save_vmcoreinfo(void)
{
	VMCOREINFO_SYMBOL(dom_xen);
	VMCOREINFO_SYMBOL(dom_io);
	VMCOREINFO_SYMBOL(xen_pstart);
	VMCOREINFO_SYMBOL(frametable_pg_dir);
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
