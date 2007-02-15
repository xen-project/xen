/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2005, 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __PPC_CONFIG_H__
#define __PPC_CONFIG_H__

#define CONFIG_SYSTEMSIM 1
#define HYPERVISOR_VIRT_START 0x0 /* XXX temp hack for common/kernel.c */


#ifdef __ASSEMBLY__
/* older assemblers do not like UL */
#define U(x) (x)
#define UL(x) (x)

#else /* __ASSEMBLY__ */

#define U(x) (x ## U)
#define UL(x) (x ## UL)
extern char __bss_start[];
#endif

/* align addr on a size boundary - adjust address up/down if needed */
#define ALIGN_UP(addr,size) (((addr)+((size)-1))&(~((size)-1)))
#define ALIGN_DOWN(addr,size) ((addr)&(~((size)-1)))

/* 256M - 64M of Xen space seems like a nice number */
#define CONFIG_MIN_DOM0_PAGES (192 << (20 - PAGE_SHIFT))
#define CONFIG_SHADOW 1
#define CONFIG_GDB 1
#define CONFIG_SMP 1
#define CONFIG_PCI 1
#define CONFIG_NUMA 1
#define CONFIG_CMDLINE_SIZE 512
#define NR_CPUS 16

#ifndef ELFSIZE
#define ELFSIZE 64
#endif

#define asmlinkage

#define NO_UART_CONFIG_OK
#define OPT_CONSOLE_STR "com1"

#define __user

#define LINEAR_PT_VIRT_START (0xdeadbeefUL)
#define XENHEAP_DEFAULT_MB (16)

#define NR_hypercalls 64

#define supervisor_mode_kernel (0)

#define CONFIG_DMA_BITSIZE 64

#include <asm/powerpc64/config.h>

#endif
