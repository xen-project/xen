/*
 *  Originally from linux/drivers/char/mem.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Added devfs support. 
 *    Jan-11-1998, C. Scott Ananian <cananian@alumni.princeton.edu>
 *  Shared /dev/zero mmaping support, Feb 2000, Kanoj Sarcar <kanoj@sgi.com>
 */
/*
 * taken from
 * linux/drivers/char/mem.c and linux-2.6-xen-sparse/drivers/xen/char/mem.c.
 * adjusted for IA64 and made transparent.
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 */

#include <linux/mm.h>
#include <linux/efi.h>

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
static inline int uncached_access(struct file *file, unsigned long addr)
{
	/*
	 * On ia64, we ignore O_SYNC because we cannot tolerate memory attribute aliases.
	 */
	return !(efi_mem_attributes(addr) & EFI_MEMORY_WB);
}

int xen_mmap_mem(struct file * file, struct vm_area_struct * vma)
{
	unsigned long addr = vma->vm_pgoff << PAGE_SHIFT;
	size_t size = vma->vm_end - vma->vm_start;


#if 0
	/*
	 *XXX FIXME: linux-2.6.16.29, linux-2.6.17
	 *    valid_mmap_phys_addr_range() in linux/arch/ia64/kernel/efi.c
	 *    fails checks.
	 *    linux-2.6.18.1's returns always 1. 
	 *    Its comments says
	 *
         * MMIO regions are often missing from the EFI memory map.
         * We must allow mmap of them for programs like X, so we
         * currently can't do any useful validation.
         */
	if (!valid_mmap_phys_addr_range(addr, &size))
		return -EINVAL;
	if (size < vma->vm_end - vma->vm_start)
		return -EINVAL;
#endif

	if (is_running_on_xen()) {
		unsigned long offset = HYPERVISOR_ioremap(addr, size);
		if (IS_ERR_VALUE(offset))
			return offset;
	}

	if (uncached_access(file, vma->vm_pgoff << PAGE_SHIFT))
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

        /* Remap-pfn-range will mark the range VM_IO and VM_RESERVED */
        if (remap_pfn_range(vma,
                            vma->vm_start,
                            vma->vm_pgoff,
                            size,
                            vma->vm_page_prot))
                return -EAGAIN;
        return 0;
}
