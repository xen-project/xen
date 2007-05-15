/*
 * vmx_platform.h: VMX platform support
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#ifndef __ASM_IA64_VMX_PLATFORM_H__
#define __ASM_IA64_VMX_PLATFORM_H__

#include <public/xen.h>
#include <public/hvm/params.h>
#include <asm/viosapic.h>


/* Value of guest os type */
#define OS_BASE     0xB0
#define OS_UNKNOWN  0xB0
#define OS_WINDOWS  0xB1
#define OS_LINUX    0xB2
#define OS_END      0xB3

#define GOS_WINDOWS(_v) \
    ((_v)->domain->arch.vmx_platform.gos_type == OS_WINDOWS)

#define GOS_LINUX(_v) \
    ((_v)->domain->arch.vmx_platform.gos_type == OS_LINUX)

/* port guest Firmware use to indicate os type 
 * this port is used to trigger SMI on x86,
 * it is not used on ia64 */
#define OS_TYPE_PORT    0xB2

struct mmio_list;
typedef struct virtual_platform_def {
    unsigned long       gos_type;
    unsigned long       buffered_io_va;
    spinlock_t          buffered_io_lock;
    unsigned long       buffered_pio_va;
    unsigned long       shared_page_va;
    unsigned long       pib_base;
    unsigned long       params[HVM_NR_PARAMS];
    struct mmio_list    *mmio;
    /* One IOSAPIC now... */
    struct viosapic     viosapic;
} vir_plat_t;

static inline int __fls(uint32_t word)
{
    long double d = word;
    long exp;

    __asm__ __volatile__ ("getf.exp %0=%1" : "=r"(exp) : "f"(d));
    return word ? (exp - 0xffff) : -1;
}
#endif
