/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 *
 * Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 */

#ifndef _ASM_FIXMAP_H
#define _ASM_FIXMAP_H

#include <linux/config.h>
#include <linux/kernel.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#ifdef CONFIG_HIGHMEM
#include <linux/threads.h>
#include <asm/kmap_types.h>
#endif

/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process. We allocate these special  addresses
 * from the end of virtual memory (0xfffff000) backwards.
 * Also this lets us do fail-safe vmalloc(), we
 * can guarantee that these special addresses and
 * vmalloc()-ed addresses never overlap.
 *
 * these 'compile-time allocated' memory buffers are
 * fixed-size 4k pages. (or larger if used with an increment
 * highger than 1) use fixmap_set(idx,phys) to associate
 * physical memory with fixmap indices.
 *
 * TLB entries of such buffers will not be flushed across
 * task switches.
 */

enum fixed_addresses {
#ifdef CONFIG_HIGHMEM
	FIX_KMAP_BEGIN,	/* reserved pte's for temporary kernel mappings */
	FIX_KMAP_END = FIX_KMAP_BEGIN+(KM_TYPE_NR*NR_CPUS)-1,
#endif
	FIX_BLKRING_BASE,
	FIX_NETRING0_BASE,
	FIX_NETRING1_BASE,
	FIX_NETRING2_BASE,
	FIX_NETRING3_BASE,
        FIX_SHARED_INFO,
	FIX_GNTTAB,
#ifdef CONFIG_VGA_CONSOLE
#define NR_FIX_BTMAPS   32  /* 128KB For the Dom0 VGA Console A0000-C0000 */
#else
#define NR_FIX_BTMAPS   1   /* in case anyone wants it in future... */
#endif
        FIX_BTMAP_END,
        FIX_BTMAP_BEGIN = FIX_BTMAP_END + NR_FIX_BTMAPS - 1,
	/* our bt_ioremap is permanent, unlike other architectures */
	
	__end_of_permanent_fixed_addresses,
	__end_of_fixed_addresses = __end_of_permanent_fixed_addresses
};

extern void __set_fixmap (enum fixed_addresses idx,
					unsigned long phys, pgprot_t flags);

#define set_fixmap(idx, phys) \
		__set_fixmap(idx, phys, PAGE_KERNEL)
/*
 * Some hardware wants to get fixmapped without caching.
 */
#define set_fixmap_nocache(idx, phys) \
		__set_fixmap(idx, phys, PAGE_KERNEL_NOCACHE)

extern void clear_fixmap(enum fixed_addresses idx);

/*
 * used by vmalloc.c.
 *
 * Leave one empty page between vmalloc'ed areas and
 * the start of the fixmap, and leave one page empty
 * at the top of mem..
 */
#define FIXADDR_TOP   (HYPERVISOR_VIRT_START - 2*PAGE_SIZE)
#define __FIXADDR_SIZE        (__end_of_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START (FIXADDR_TOP - __FIXADDR_SIZE)

#define __fix_to_virt(x)	(FIXADDR_TOP - ((x) << PAGE_SHIFT))

/*
 * 'index to address' translation. If anyone tries to use the idx
 * directly without tranlation, we catch the bug with a NULL-deference
 * kernel oops. Illegal ranges of incoming indices are caught too.
 */
static inline unsigned long fix_to_virt(unsigned int idx)
{
        return __fix_to_virt(idx);
}

#endif
