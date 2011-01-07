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
#include <asm/vmx.h> 
#include <asm/viosapic.h> 

static int hvmop_set_isa_irq_level(
    XEN_GUEST_HANDLE(xen_hvm_set_isa_irq_level_t) uop)
{
    struct xen_hvm_set_isa_irq_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( op.isa_irq > 15 )
        return -EINVAL;

    rc = rcu_lock_target_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = 0;
    viosapic_set_irq(d, op.isa_irq, op.level);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_set_pci_intx_level(
    XEN_GUEST_HANDLE(xen_hvm_set_pci_intx_level_t) uop)
{
    struct xen_hvm_set_pci_intx_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.domain > 0) || (op.bus > 0) || (op.device > 31) || (op.intx > 3) )
        return -EINVAL;

    rc = rcu_lock_target_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = 0;
    viosapic_set_pci_irq(d, op.device, op.intx, op.level);

 out:
    rcu_unlock_domain(d);
    return rc;
}



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

        if (a.index >= HVM_NR_PARAMS)
            return -EINVAL;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if (rc != 0)
            return rc;

        if (op == HVMOP_set_param) {
            struct vmx_ioreq_page *iorp;
            struct vcpu *v;

            switch (a.index) {
            case HVM_PARAM_IOREQ_PFN:
                iorp = &d->arch.hvm_domain.ioreq;
                rc = vmx_set_ioreq_page(d, iorp, a.value);
                spin_lock(&iorp->lock);
                if (rc == 0 && iorp->va != NULL)
                    /* Initialise evtchn port info if VCPUs already created. */
                    for_each_vcpu(d, v)
                        get_vio(v)->vp_eport = v->arch.arch_vmx.xen_port;
                spin_unlock(&iorp->lock);
                break;
            case HVM_PARAM_BUFIOREQ_PFN: 
                iorp = &d->arch.hvm_domain.buf_ioreq;
                rc = vmx_set_ioreq_page(d, iorp, a.value);
                break;
            case HVM_PARAM_BUFPIOREQ_PFN: 
                iorp = &d->arch.hvm_domain.buf_pioreq;
                rc = vmx_set_ioreq_page(d, iorp, a.value);
                break;
            case HVM_PARAM_DM_DOMAIN:
                if (a.value == DOMID_SELF)
                    a.value = current->domain->domain_id;
                rc = a.value ? -EINVAL : 0; /* no stub domain support */
                break;
            default:
                /* nothing */
                break;
            }
            if (rc == 0)
                d->arch.hvm_domain.params[a.index] = a.value;
        }
        else {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_set_pci_intx_level:
        rc = hvmop_set_pci_intx_level(
            guest_handle_cast(arg, xen_hvm_set_pci_intx_level_t));
        break;

    case HVMOP_set_isa_irq_level:
        rc = hvmop_set_isa_irq_level(
            guest_handle_cast(arg, xen_hvm_set_isa_irq_level_t));
        break;

    case HVMOP_set_pci_link_route:
        rc = 0;
        break;

    case HVMOP_track_dirty_vram:
        rc = -ENOSYS;
        break;

    case HVMOP_modified_memory:
    {
        struct xen_hvm_modified_memory a;
        struct domain *d;
        unsigned long pfn;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            break;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail3;

        rc = -EINVAL;
        if ( a.first_pfn > domain_get_maximum_gpfn(d)
                || a.first_pfn + a.nr - 1 < a.first_pfn
                || a.first_pfn + a.nr - 1 > domain_get_maximum_gpfn(d))
            goto param_fail3;

        rc = 0;
        if ( !d->arch.shadow_bitmap )
            goto param_fail3;

        for (pfn = a.first_pfn; pfn < a.first_pfn + a.nr; pfn++)
            if (pfn < d->arch.shadow_bitmap_size)
                set_bit(pfn, d->arch.shadow_bitmap);

    param_fail3:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_set_mem_type:
    case HVMOP_set_mem_access:
    case HVMOP_get_mem_access:

        rc = -ENOSYS;
        break;

    default:
        gdprintk(XENLOG_INFO, "Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
    }
    return rc;
}
