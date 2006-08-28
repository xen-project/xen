/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_hyparcall.c: handling hypercall from domain
 * Copyright (c) 2005, Intel Corporation.
 * Copyright (c) 2006, Fujitsu Limited.
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
 *  Tsunehisa Doi (Doi.Tsunehisa@jp.fujitsu.com)
 *  Tomonari Horikoshi (t.horikoshi@jp.fujitsu.com)
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
#include <xen/compile.h>
#include <xen/event.h>

static void
vmx_free_pages(unsigned long pgaddr, int npg)
{
    for (; npg > 0; npg--, pgaddr += PAGE_SIZE) {
        /* If original page belongs to xen heap, then relinguish back
         * to xen heap. Or else, leave to domain itself to decide.
         */
        if (likely(IS_XEN_HEAP_FRAME(virt_to_page(pgaddr)))) {
            free_domheap_page(virt_to_page(pgaddr));
            free_xenheap_page((void *)pgaddr);
        }
        else {
            put_page(virt_to_page(pgaddr));
        }
    }
}

static int
vmx_gnttab_setup_table(unsigned long frame_pa, unsigned long nr_frames)
{
    struct domain *d = current->domain;
    struct grant_entry *pgaddr;
    unsigned long o_grant_shared;

    if ((nr_frames != NR_GRANT_FRAMES) || (frame_pa & (PAGE_SIZE - 1))) {
        return -EINVAL;
    }

    pgaddr = domain_mpa_to_imva(d, frame_pa);
    if (pgaddr == NULL) {
        return -EFAULT;
    }

    o_grant_shared = (unsigned long)d->grant_table->shared;
    d->grant_table->shared = pgaddr;

    /* Copy existing grant table into new page */
    if (o_grant_shared) {
        memcpy((void *)d->grant_table->shared,
               (void *)o_grant_shared, PAGE_SIZE * nr_frames);
        vmx_free_pages(o_grant_shared, nr_frames);
    }
    else {
        memset((void *)d->grant_table->shared, 0, PAGE_SIZE * nr_frames);
    }
    return 0;
}

static int
vmx_setup_shared_info_page(unsigned long gpa)
{
    VCPU *vcpu = current;
    struct domain *d = vcpu->domain;
    unsigned long o_info;
    shared_info_t *pgaddr;
    struct vcpu *v;

    if (gpa & ~PAGE_MASK) {
        return -EINVAL;
    }

    pgaddr = domain_mpa_to_imva(d, gpa);
    if (pgaddr == NULL) {
        return -EFAULT;
    }

    o_info = (u64)d->shared_info;
    d->shared_info = pgaddr;

    /* Copy existing shared info into new page */
    if (o_info) {
        memcpy((void*)d->shared_info, (void*)o_info, PAGE_SIZE);
        for_each_vcpu(d, v) {
            v->vcpu_info = &d->shared_info->vcpu_info[v->vcpu_id];
        }
        vmx_free_pages(o_info, 1);
    }
    else {
        memset((void *)d->shared_info, 0, PAGE_SIZE);
    }
    return 0;
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

        if (a.index > HVM_NR_PARAMS)
            return -EINVAL;

        if (a.domid == DOMID_SELF) {
            get_knownalive_domain(current->domain);
            d = current->domain;
        }
        else if (IS_PRIV(current->domain)) {
            d = find_domain_by_id(a.domid);
            if (d == NULL)
                return -ESRCH;
        }
        else
            return -EPERM;

        if (op == HVMOP_set_param) {
            d->arch.hvm_domain.params[a.index] = a.value;
            rc = 0;
        }
        else {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

        put_domain(d);
        break;
    }

    case HVMOP_setup_gnttab_table:
    case HVMOP_setup_shared_info_page:
    {
        struct xen_hvm_setup a;

        if (copy_from_guest(&a, arg, 1))
            return -EFAULT;

        switch (op) {
        case HVMOP_setup_gnttab_table:
            printk("vmx_gnttab_setup_table: frame_pa=%#lx,"
                            "nr_frame=%ld\n", a.arg1, a.arg2);
            return vmx_gnttab_setup_table(a.arg1, a.arg2);
        case HVMOP_setup_shared_info_page:
            printk("vmx_setup_shared_info_page: gpa=0x%lx\n", a.arg1);
            return vmx_setup_shared_info_page(a.arg1);
        }
    }

    default:
        DPRINTK("Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
    }
    return rc;
}
