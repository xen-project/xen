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
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Ryan Harper <ryanh@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/guest_access.h>
#include <xen/shadow.h>
#include <public/xen.h>
#include <public/domctl.h>
#include <public/sysctl.h>
#include <asm/processor.h>

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{ 
    memcpy(&c.nat->user_regs, &v->arch.ctxt, sizeof(struct cpu_user_regs));
    /* XXX fill in rest of vcpu_guest_context_t */
}

long arch_do_domctl(struct xen_domctl *domctl,
                    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl);
long arch_do_domctl(struct xen_domctl *domctl,
                    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    long ret = 0;

    switch (domctl->cmd) {
    case XEN_DOMCTL_getmemlist:
    {
        int i;
        struct domain *d = get_domain_by_id(domctl->domain);
        unsigned long max_pfns = domctl->u.getmemlist.max_pfns;
        uint64_t mfn;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            spin_lock(&d->page_alloc_lock);
            for (i = 0; i < max_pfns; i++) {
                /* bail if index is beyond p2m size */
                if (i >= d->arch.p2m_entries)
                    break;

                /* translate */
                mfn = d->arch.p2m[i];

                if (copy_to_guest_offset(domctl->u.getmemlist.buffer,
                                          i, &mfn, 1))
                {
                    ret = -EFAULT;
                    break;
                }
            }
            spin_unlock(&d->page_alloc_lock);

            domctl->u.getmemlist.num_pfns = i;
            copy_to_guest(u_domctl, domctl, 1);
            
            put_domain(d);
        }
    }
    break;
    case XEN_DOMCTL_shadow_op:
    {
        struct domain *d;
        ret = -ESRCH;
        d = get_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = shadow_domctl(d, &domctl->u.shadow_op, u_domctl);
            put_domain(d);
            copy_to_guest(u_domctl, domctl, 1);
        } 
    }
    break;
    case XEN_DOMCTL_real_mode_area:
    {
        struct domain *d;
        unsigned int order = domctl->u.real_mode_area.log - PAGE_SHIFT;

        ret = -ESRCH;
        d = get_domain_by_id(domctl->domain);
        if (d != NULL) {
            ret = -EINVAL;
            if (cpu_rma_valid(order))
                ret = allocate_rma(d, order);
            put_domain(d);
        }
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}
