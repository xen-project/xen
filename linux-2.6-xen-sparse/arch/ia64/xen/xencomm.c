/*
 * Copyright (C) 2006 Hollis Blanchard <hollisb@us.ibm.com>, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/gfp.h>
#include <linux/mm.h>
#include <xen/interface/xen.h>
#include <asm/page.h>
#include <asm/xen/xencomm.h>

static int xencomm_debug = 0;

static unsigned long kernel_start_pa;

void
xencomm_init (void)
{
	kernel_start_pa = KERNEL_START - ia64_tpa(KERNEL_START);
}

/* Translate virtual address to physical address.  */
unsigned long
xencomm_vaddr_to_paddr(unsigned long vaddr)
{
	struct page *page;
	struct vm_area_struct *vma;

	if (vaddr == 0)
		return 0;

#ifdef __ia64__
	if (REGION_NUMBER(vaddr) == 5) {
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *ptep;

		/* On ia64, TASK_SIZE refers to current.  It is not initialized
		   during boot.
		   Furthermore the kernel is relocatable and __pa() doesn't
		   work on  addresses.  */
		if (vaddr >= KERNEL_START
		    && vaddr < (KERNEL_START + KERNEL_TR_PAGE_SIZE)) {
			return vaddr - kernel_start_pa;
		}

		/* In kernel area -- virtually mapped.  */
		pgd = pgd_offset_k(vaddr);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			return ~0UL;

		pud = pud_offset(pgd, vaddr);
		if (pud_none(*pud) || pud_bad(*pud))
			return ~0UL;

		pmd = pmd_offset(pud, vaddr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			return ~0UL;

		ptep = pte_offset_kernel(pmd, vaddr);
		if (!ptep)
			return ~0UL;

		return (pte_val(*ptep) & _PFN_MASK) | (vaddr & ~PAGE_MASK);
	}
#endif

	if (vaddr > TASK_SIZE) {
		/* kernel address */
		return __pa(vaddr);
	}


#ifdef CONFIG_VMX_GUEST
	/* No privcmd within vmx guest.  */
	return ~0UL;
#else
	/* XXX double-check (lack of) locking */
	vma = find_extend_vma(current->mm, vaddr);
	if (!vma)
		return ~0UL;

	/* We assume the page is modified.  */
	page = follow_page(vma, vaddr, FOLL_WRITE | FOLL_TOUCH);
	if (!page)
		return ~0UL;

	return (page_to_pfn(page) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
#endif
}

static int
xencomm_init_desc(struct xencomm_desc *desc, void *buffer, unsigned long bytes)
{
	unsigned long recorded = 0;
	int i = 0;

	BUG_ON((buffer == NULL) && (bytes > 0));

	/* record the physical pages used */
	if (buffer == NULL)
		desc->nr_addrs = 0;

	while ((recorded < bytes) && (i < desc->nr_addrs)) {
		unsigned long vaddr = (unsigned long)buffer + recorded;
		unsigned long paddr;
		int offset;
		int chunksz;

		offset = vaddr % PAGE_SIZE; /* handle partial pages */
		chunksz = min(PAGE_SIZE - offset, bytes - recorded);

		paddr = xencomm_vaddr_to_paddr(vaddr);
		if (paddr == ~0UL) {
			printk("%s: couldn't translate vaddr %lx\n",
			       __func__, vaddr);
			return -EINVAL;
		}

		desc->address[i++] = paddr;
		recorded += chunksz;
	}

	if (recorded < bytes) {
		printk("%s: could only translate %ld of %ld bytes\n",
		       __func__, recorded, bytes);
		return -ENOSPC;
	}

	/* mark remaining addresses invalid (just for safety) */
	while (i < desc->nr_addrs)
		desc->address[i++] = XENCOMM_INVALID;

	desc->magic = XENCOMM_MAGIC;

	return 0;
}

static struct xencomm_desc *
xencomm_alloc(gfp_t gfp_mask)
{
	struct xencomm_desc *desc;

	desc = (struct xencomm_desc *)__get_free_page(gfp_mask);
	if (desc == NULL)
		panic("%s: page allocation failed\n", __func__);

	desc->nr_addrs = (PAGE_SIZE - sizeof(struct xencomm_desc)) /
	                 sizeof(*desc->address);

	return desc;
}

void
xencomm_free(struct xencomm_handle *desc)
{
	if (desc)
		free_page((unsigned long)__va(desc));
}

int
xencomm_create(void *buffer, unsigned long bytes,
               struct xencomm_handle **ret, gfp_t gfp_mask)
{
	struct xencomm_desc *desc;
	struct xencomm_handle *handle;
	int rc;

	if (xencomm_debug)
		printk("%s: %p[%ld]\n", __func__, buffer, bytes);

	if (buffer == NULL || bytes == 0) {
		*ret = (struct xencomm_handle *)NULL;
		return 0;
	}

	desc = xencomm_alloc(gfp_mask);
	if (!desc) {
		printk("%s failure\n", "xencomm_alloc");
		return -ENOMEM;
	}
	handle = (struct xencomm_handle *)__pa(desc);

	rc = xencomm_init_desc(desc, buffer, bytes);
	if (rc) {
		printk("%s failure: %d\n", "xencomm_init_desc", rc);
		xencomm_free(handle);
		return rc;
	}

	*ret = handle;
	return 0;
}

/* "mini" routines, for stack-based communications: */

static void *
xencomm_alloc_mini(struct xencomm_mini *area, int *nbr_area)
{
	unsigned long base;
	unsigned int pageoffset;

	while (*nbr_area >= 0) {
		/* Allocate an area.  */
		(*nbr_area)--;

		base = (unsigned long)(area + *nbr_area);
		pageoffset = base % PAGE_SIZE;

		/* If the area does not cross a page, use it.  */
		if ((PAGE_SIZE - pageoffset) >= sizeof(struct xencomm_mini))
			return &area[*nbr_area];
	}
	/* No more area.  */
	return NULL;
}

int
xencomm_create_mini(struct xencomm_mini *area, int *nbr_area,
                    void *buffer, unsigned long bytes,
                    struct xencomm_handle **ret)
{
	struct xencomm_desc *desc;
	int rc;
	unsigned long res;

	desc = xencomm_alloc_mini(area, nbr_area);
	if (!desc)
		return -ENOMEM;
	desc->nr_addrs = XENCOMM_MINI_ADDRS;

	rc = xencomm_init_desc(desc, buffer, bytes);
	if (rc)
		return rc;

	res = xencomm_vaddr_to_paddr((unsigned long)desc);
	if (res == ~0UL)
		return -EINVAL;

	*ret = (struct xencomm_handle*)res;
	return 0;
}
