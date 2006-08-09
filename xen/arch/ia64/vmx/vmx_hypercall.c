/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_hyparcall.c: handling hypercall from domain
 * Copyright (c) 2005, Intel Corporation.
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
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <asm/vmx_vcpu.h>
#include <xen/guest_access.h>
#include <public/event_channel.h>
#include <asm/vmmu.h>
#include <asm/tlb.h>
#include <asm/regionreg.h>
#include <asm/page.h>
#include <xen/mm.h>
#include <xen/multicall.h>
#include <xen/hypercall.h>
#include <public/version.h>
#include <asm/dom_fw.h>
#include <xen/domain.h>

long
do_hvm_op(unsigned long op, XEN_GUEST_HANDLE(void) arg)
{
    long rc = 0;

    switch (op) {
    case HVMOP_set_param:
    case HVMOP_get_param:
    {
        struct xen_hvm_param a;
        struct domain *d;

        if (copy_from_guest(&a, arg, 1))
            return -EFAULT;

        if (a.index > HVM_NR_PARAMS)
            return -EINVAL;

        if (a.domid == DOMID_SELF) {
            get_knownalive_domain(current->domain);
            d = current->domain;
        }
        else if (IS_PRIV(current->domain)) {
            d = find_domain_by_id(a.domid);
            if (!d)
                return -ESRCH;
        }
        else
            return -EPERM;

        if (op == HVMOP_set_param) {
            rc = 0;
            d->arch.hvm_domain.params[a.index] = a.value;
        }
        else
            rc = d->arch.hvm_domain.params[a.index];

        put_domain(d);
        return rc;
    }

    default:
        DPRINTK("Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
    }
    return rc;
}
