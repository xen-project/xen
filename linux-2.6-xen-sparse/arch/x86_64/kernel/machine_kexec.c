/*
 * machine_kexec.c - handle transition of Linux booting another kernel
 * Copyright (C) 2002-2005 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/string.h>
#include <linux/reboot.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/io.h>

#define PAGE_ALIGNED __attribute__ ((__aligned__(PAGE_SIZE)))
static u64 kexec_pgd[512] PAGE_ALIGNED;
static u64 kexec_pud0[512] PAGE_ALIGNED;
static u64 kexec_pmd0[512] PAGE_ALIGNED;
static u64 kexec_pte0[512] PAGE_ALIGNED;
static u64 kexec_pud1[512] PAGE_ALIGNED;
static u64 kexec_pmd1[512] PAGE_ALIGNED;
static u64 kexec_pte1[512] PAGE_ALIGNED;

static void init_level2_page(pmd_t *level2p, unsigned long addr)
{
	unsigned long end_addr;

	addr &= PAGE_MASK;
	end_addr = addr + PUD_SIZE;
	while (addr < end_addr) {
		set_pmd(level2p++, __pmd(addr | __PAGE_KERNEL_LARGE_EXEC));
		addr += PMD_SIZE;
	}
}

static int init_level3_page(struct kimage *image, pud_t *level3p,
				unsigned long addr, unsigned long last_addr)
{
	unsigned long end_addr;
	int result;

	result = 0;
	addr &= PAGE_MASK;
	end_addr = addr + PGDIR_SIZE;
	while ((addr < last_addr) && (addr < end_addr)) {
		struct page *page;
		pmd_t *level2p;

		page = kimage_alloc_control_pages(image, 0);
		if (!page) {
			result = -ENOMEM;
			goto out;
		}
		level2p = (pmd_t *)page_address(page);
		init_level2_page(level2p, addr);
		set_pud(level3p++, __pud(__pa(level2p) | _KERNPG_TABLE));
		addr += PUD_SIZE;
	}
	/* clear the unused entries */
	while (addr < end_addr) {
		pud_clear(level3p++);
		addr += PUD_SIZE;
	}
out:
	return result;
}


static int init_level4_page(struct kimage *image, pgd_t *level4p,
				unsigned long addr, unsigned long last_addr)
{
	unsigned long end_addr;
	int result;

	result = 0;
	addr &= PAGE_MASK;
	end_addr = addr + (PTRS_PER_PGD * PGDIR_SIZE);
	while ((addr < last_addr) && (addr < end_addr)) {
		struct page *page;
		pud_t *level3p;

		page = kimage_alloc_control_pages(image, 0);
		if (!page) {
			result = -ENOMEM;
			goto out;
		}
		level3p = (pud_t *)page_address(page);
		result = init_level3_page(image, level3p, addr, last_addr);
		if (result) {
			goto out;
		}
		set_pgd(level4p++, __pgd(__pa(level3p) | _KERNPG_TABLE));
		addr += PGDIR_SIZE;
	}
	/* clear the unused entries */
	while (addr < end_addr) {
		pgd_clear(level4p++);
		addr += PGDIR_SIZE;
	}
out:
	return result;
}


static int init_pgtable(struct kimage *image, unsigned long start_pgtable)
{
	pgd_t *level4p;
	level4p = (pgd_t *)__va(start_pgtable);
 	return init_level4_page(image, level4p, 0, end_pfn << PAGE_SHIFT);
}

int machine_kexec_prepare(struct kimage *image)
{
	unsigned long start_pgtable;
	int result;

	/* Calculate the offsets */
	start_pgtable = page_to_pfn(image->control_code_page) << PAGE_SHIFT;

	/* Setup the identity mapped 64bit page table */
	result = init_pgtable(image, start_pgtable);
	if (result)
		return result;

	return 0;
}

void machine_kexec_cleanup(struct kimage *image)
{
	return;
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

	control_page = page_address(image->control_code_page) + PAGE_SIZE;
	memcpy(control_page, relocate_kernel, PAGE_SIZE);

	page_list[PA_CONTROL_PAGE] = __pa(control_page);
	page_list[VA_CONTROL_PAGE] = (unsigned long)relocate_kernel;
	page_list[PA_PGD] = __pa(kexec_pgd);
	page_list[VA_PGD] = (unsigned long)kexec_pgd;
	page_list[PA_PUD_0] = __pa(kexec_pud0);
	page_list[VA_PUD_0] = (unsigned long)kexec_pud0;
	page_list[PA_PMD_0] = __pa(kexec_pmd0);
	page_list[VA_PMD_0] = (unsigned long)kexec_pmd0;
	page_list[PA_PTE_0] = __pa(kexec_pte0);
	page_list[VA_PTE_0] = (unsigned long)kexec_pte0;
	page_list[PA_PUD_1] = __pa(kexec_pud1);
	page_list[VA_PUD_1] = (unsigned long)kexec_pud1;
	page_list[PA_PMD_1] = __pa(kexec_pmd1);
	page_list[VA_PMD_1] = (unsigned long)kexec_pmd1;
	page_list[PA_PTE_1] = __pa(kexec_pte1);
	page_list[VA_PTE_1] = (unsigned long)kexec_pte1;

	page_list[PA_TABLE_PAGE] =
	  (unsigned long)__pa(page_address(image->control_code_page));

	relocate_kernel((unsigned long)image->head, (unsigned long)page_list,
			image->start);
}
