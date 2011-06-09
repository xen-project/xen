
/*
 * vvmx.h: Support virtual VMX for nested virtualization.
 *
 * Copyright (c) 2010, Intel Corporation.
 * Author: Qing He <qing.he@intel.com>
 *         Eddie Dong <eddie.dong@intel.com>
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
#ifndef __ASM_X86_HVM_VVMX_H__
#define __ASM_X86_HVM_VVMX_H__

struct nestedvmx {
    paddr_t    vmxon_region_pa;
    void       *iobitmap[2];		/* map (va) of L1 guest I/O bitmap */
    /* deferred nested interrupt */
    struct {
        unsigned long intr_info;
        u32           error_code;
    } intr;
};

#define vcpu_2_nvmx(v)	(vcpu_nestedhvm(v).u.nvmx)
#endif /* __ASM_X86_HVM_VVMX_H__ */

