/*
 * vvmx.c: Support virtual VMX for nested virtualization.
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

#include <xen/config.h>
#include <asm/types.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vvmx.h>

int nvmx_vcpu_initialise(struct vcpu *v)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    nvcpu->nv_n2vmcx = alloc_xenheap_page();
    if ( !nvcpu->nv_n2vmcx )
    {
        gdprintk(XENLOG_ERR, "nest: allocation for shadow vmcs failed\n");
	goto out;
    }
    nvmx->vmxon_region_pa = 0;
    nvcpu->nv_vvmcx = NULL;
    nvcpu->nv_vvmcxaddr = VMCX_EADDR;
    nvmx->intr.intr_info = 0;
    nvmx->intr.error_code = 0;
    nvmx->iobitmap[0] = NULL;
    nvmx->iobitmap[1] = NULL;
    return 0;
out:
    return -ENOMEM;
}
 
void nvmx_vcpu_destroy(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    if ( nvcpu->nv_n2vmcx ) {
        __vmpclear(virt_to_maddr(nvcpu->nv_n2vmcx));
        free_xenheap_page(nvcpu->nv_n2vmcx);
        nvcpu->nv_n2vmcx = NULL;
    }
}
 
int nvmx_vcpu_reset(struct vcpu *v)
{
    return 0;
}

uint64_t nvmx_vcpu_guestcr3(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

uint64_t nvmx_vcpu_hostcr3(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

uint32_t nvmx_vcpu_asid(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

