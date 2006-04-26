#ifndef _ASM_IA64_XENSYSTEM_H
#define _ASM_IA64_XENSYSTEM_H
/*
 * xen specific context definition
 *
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 * Copyright (C) 2005 Intel Co.
 * 	Kun Tian (Kevin Tian) <kevin.tian@intel.com>
 *
 */
#include <asm/config.h>
#include <linux/kernel.h>

/* Define HV space hierarchy.
   VMM memory space is protected by CPL for paravirtualized domains and
   by VA for VTi domains.  VTi imposes VA bit 60 != VA bit 59 for VMM.  */
#define XEN_VIRT_SPACE_LOW	 0xe800000000000000
#define XEN_VIRT_SPACE_HIGH	 0xf800000000000000	

#define __IA64_UNCACHED_OFFSET	 0xe800000000000000UL

#define XEN_START_ADDR		 0xf000000000000000
#define HYPERVISOR_VIRT_START	 0xf000000000000000
#define KERNEL_START		 0xf000000004000000
#define SHAREDINFO_ADDR		 0xf100000000000000
#define XSI_OFS 		 PAGE_SIZE
#define SHARED_ARCHINFO_ADDR	 (SHAREDINFO_ADDR + XSI_OFS)
#define PERCPU_ADDR		 (SHAREDINFO_ADDR - PERCPU_PAGE_SIZE)
#define VHPT_ADDR		 0xf200000000000000
#ifdef CONFIG_VIRTUAL_FRAME_TABLE
#define VIRT_FRAME_TABLE_ADDR	 0xf300000000000000
#define VIRT_FRAME_TABLE_END	 0xf400000000000000
#endif
#define XEN_END_ADDR		 0xf400000000000000

#define PAGE_OFFSET	__IA64_UL_CONST(0xf000000000000000)

#define IS_VMM_ADDRESS(addr) ((((addr) >> 60) ^ ((addr) >> 59)) & 1)

#endif // _ASM_IA64_XENSYSTEM_H
