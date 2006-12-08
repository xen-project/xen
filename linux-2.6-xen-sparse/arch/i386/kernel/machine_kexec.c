/*
 * machine_kexec.c - handle transition of Linux booting another kernel
 * Copyright (C) 2002-2005 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#include <asm/system.h>

#ifdef CONFIG_XEN
#include <xen/interface/kexec.h>
#endif

#define PAGE_ALIGNED __attribute__ ((__aligned__(PAGE_SIZE)))
static u32 kexec_pgd[1024] PAGE_ALIGNED;
#ifdef CONFIG_X86_PAE
static u32 kexec_pmd0[1024] PAGE_ALIGNED;
static u32 kexec_pmd1[1024] PAGE_ALIGNED;
#endif
static u32 kexec_pte0[1024] PAGE_ALIGNED;
static u32 kexec_pte1[1024] PAGE_ALIGNED;

#ifdef CONFIG_XEN

#define __ma(x) (pfn_to_mfn(__pa((x)) >> PAGE_SHIFT) << PAGE_SHIFT)

#if PAGES_NR > KEXEC_XEN_NO_PAGES
#error PAGES_NR is greater than KEXEC_XEN_NO_PAGES - Xen support will break
#endif

#if PA_CONTROL_PAGE != 0
#error PA_CONTROL_PAGE is non zero - Xen support will break
#endif

void machine_kexec_setup_load_arg(xen_kexec_image_t *xki, struct kimage *image)
{
	void *control_page;

	memset(xki->page_list, 0, sizeof(xki->page_list));

	control_page = page_address(image->control_code_page);
	memcpy(control_page, relocate_kernel, PAGE_SIZE);

	xki->page_list[PA_CONTROL_PAGE] = __ma(control_page);
	xki->page_list[PA_PGD] = __ma(kexec_pgd);
#ifdef CONFIG_X86_PAE
	xki->page_list[PA_PMD_0] = __ma(kexec_pmd0);
	xki->page_list[PA_PMD_1] = __ma(kexec_pmd1);
#endif
	xki->page_list[PA_PTE_0] = __ma(kexec_pte0);
	xki->page_list[PA_PTE_1] = __ma(kexec_pte1);

}

#endif /* CONFIG_XEN */

/*
 * A architecture hook called to validate the
 * proposed image and prepare the control pages
 * as needed.  The pages for KEXEC_CONTROL_CODE_SIZE
 * have been allocated, but the segments have yet
 * been copied into the kernel.
 *
 * Do what every setup is needed on image and the
 * reboot code buffer to allow us to avoid allocations
 * later.
 *
 * Currently nothing.
 */
int machine_kexec_prepare(struct kimage *image)
{
	return 0;
}

/*
 * Undo anything leftover by machine_kexec_prepare
 * when an image is freed.
 */
void machine_kexec_cleanup(struct kimage *image)
{
}

/*
 * Do not allocate memory (or fail in any way) in machine_kexec().
 * We are past the point of no return, committed to rebooting now.
 */
NORET_TYPE void machine_kexec(struct kimage *image)
{
	unsigned long page_list[PAGES_NR];
	void *control_page;

	/* Interrupts aren't acceptable while we reboot */
	local_irq_disable();

	control_page = page_address(image->control_code_page);
	memcpy(control_page, relocate_kernel, PAGE_SIZE);

	page_list[PA_CONTROL_PAGE] = __pa(control_page);
	page_list[VA_CONTROL_PAGE] = (unsigned long)relocate_kernel;
	page_list[PA_PGD] = __pa(kexec_pgd);
	page_list[VA_PGD] = (unsigned long)kexec_pgd;
#ifdef CONFIG_X86_PAE
	page_list[PA_PMD_0] = __pa(kexec_pmd0);
	page_list[VA_PMD_0] = (unsigned long)kexec_pmd0;
	page_list[PA_PMD_1] = __pa(kexec_pmd1);
	page_list[VA_PMD_1] = (unsigned long)kexec_pmd1;
#endif
	page_list[PA_PTE_0] = __pa(kexec_pte0);
	page_list[VA_PTE_0] = (unsigned long)kexec_pte0;
	page_list[PA_PTE_1] = __pa(kexec_pte1);
	page_list[VA_PTE_1] = (unsigned long)kexec_pte1;

	relocate_kernel((unsigned long)image->head, (unsigned long)page_list,
			image->start, cpu_has_pae);
}
