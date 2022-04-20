/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/event.h>

#include <asm/gdbsx.h>
#include <asm/p2m.h>

typedef unsigned long dbgva_t;
typedef unsigned char dbgbyte_t;

/* Returns: mfn for the given (hvm guest) vaddr */
static mfn_t
dbg_hvm_va2mfn(dbgva_t vaddr, struct domain *dp, int toaddr, gfn_t *gfn)
{
    mfn_t mfn;
    uint32_t pfec = PFEC_page_present;
    p2m_type_t gfntype;

    *gfn = _gfn(paging_gva_to_gfn(dp->vcpu[0], vaddr, &pfec));
    if ( gfn_eq(*gfn, INVALID_GFN) )
        return INVALID_MFN;

    mfn = get_gfn(dp, gfn_x(*gfn), &gfntype);
    if ( p2m_is_readonly(gfntype) && toaddr )
        mfn = INVALID_MFN;

    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        put_gfn(dp, gfn_x(*gfn));
        *gfn = INVALID_GFN;
    }

    return mfn;
}

/* 
 * pgd3val: this is the value of init_mm.pgd[3] in a PV guest. It is optional.
 *          This to assist debug of modules in the guest. The kernel address 
 *          space seems is always mapped, but modules are not necessarily 
 *          mapped in any arbitraty guest cr3 that we pick if pgd3val is 0. 
 *          Modules should always be addressible if we use cr3 from init_mm. 
 *          Since pgd3val is already a pgd value, cr3->pgd[3], we just need to 
 *          do 2 level lookups.
 *
 * NOTE: 4 level paging works for 32 PAE guests also because cpu runs in IA32-e
 *       mode.
 * Returns: mfn for the given (pv guest) vaddr 
 */
static mfn_t
dbg_pv_va2mfn(dbgva_t vaddr, struct domain *dp, uint64_t pgd3val)
{
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;
    unsigned long cr3 = (pgd3val ? pgd3val : dp->vcpu[0]->arch.cr3);
    mfn_t mfn = maddr_to_mfn(cr3_pa(cr3));

    if ( pgd3val == 0 )
    {
        l4t = map_domain_page(mfn);
        l4e = l4t[l4_table_offset(vaddr)];
        unmap_domain_page(l4t);
        mfn = l4e_get_mfn(l4e);
        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
            return INVALID_MFN;

        l3t = map_domain_page(mfn);
        l3e = l3t[l3_table_offset(vaddr)];
        unmap_domain_page(l3t);
        mfn = l3e_get_mfn(l3e);
        if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) ||
             (l3e_get_flags(l3e) & _PAGE_PSE) )
            return INVALID_MFN;
    }

    l2t = map_domain_page(mfn);
    l2e = l2t[l2_table_offset(vaddr)];
    unmap_domain_page(l2t);
    mfn = l2e_get_mfn(l2e);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) )
        return INVALID_MFN;

    l1t = map_domain_page(mfn);
    l1e = l1t[l1_table_offset(vaddr)];
    unmap_domain_page(l1t);
    mfn = l1e_get_mfn(l1e);

    return mfn_valid(mfn) ? mfn : INVALID_MFN;
}

/* Returns: number of bytes remaining to be copied */
static unsigned int dbg_rw_guest_mem(struct domain *dp, unsigned long addr,
                                     XEN_GUEST_HANDLE_PARAM(void) buf,
                                     unsigned int len, bool toaddr,
                                     uint64_t pgd3)
{
    while ( len > 0 )
    {
        char *va;
        mfn_t mfn;
        gfn_t gfn = INVALID_GFN;
        unsigned long pagecnt;

        pagecnt = min_t(long, PAGE_SIZE - (addr & ~PAGE_MASK), len);

        mfn = (is_hvm_domain(dp)
               ? dbg_hvm_va2mfn(addr, dp, toaddr, &gfn)
               : dbg_pv_va2mfn(addr, dp, pgd3));
        if ( mfn_eq(mfn, INVALID_MFN) )
            break;

        va = map_domain_page(mfn);
        va = va + (addr & (PAGE_SIZE-1));

        if ( toaddr )
        {
            copy_from_guest(va, buf, pagecnt);
            paging_mark_dirty(dp, mfn);
        }
        else
            copy_to_guest(buf, va, pagecnt);

        unmap_domain_page(va);
        if ( !gfn_eq(gfn, INVALID_GFN) )
            put_gfn(dp, gfn_x(gfn));

        addr += pagecnt;
        guest_handle_add_offset(buf, pagecnt);
        len -= pagecnt;
    }

    return len;
}

static int gdbsx_guest_mem_io(
    struct domain *d, struct xen_domctl_gdbsx_memio *iop)
{
    if ( d && !d->is_dying )
    {
        iop->remain = dbg_rw_guest_mem(
            d, iop->gva, guest_handle_from_ptr(iop->uva, void),
            iop->len, iop->gwr, iop->pgd3val);
    }
    else
        iop->remain = iop->len;

    return iop->remain ? -EFAULT : 0;
}

void domain_pause_for_debugger(void)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;

    domain_pause_by_systemcontroller_nosync(d);

    /* if gdbsx active, we just need to pause the domain */
    if ( curr->arch.gdbsx_vcpu_event == 0 )
        send_global_virq(VIRQ_DEBUGGER);
}

int gdbsx_domctl(struct domain *d, struct xen_domctl *domctl, bool *copyback)
{
    struct vcpu *v;
    int ret;

    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_gdbsx_guestmemio:
        ret = gdbsx_guest_mem_io(d, &domctl->u.gdbsx_guest_memio);
        if ( !ret )
            *copyback = true;
        break;

    case XEN_DOMCTL_gdbsx_pausevcpu:
        ret = -EBUSY;
        if ( !d->controller_pause_count )
            break;
        ret = -EINVAL;
        if ( (v = domain_vcpu(d, domctl->u.gdbsx_pauseunp_vcpu.vcpu)) == NULL )
            break;
        ret = vcpu_pause_by_systemcontroller(v);
        break;

    case XEN_DOMCTL_gdbsx_unpausevcpu:
        ret = -EBUSY;
        if ( !d->controller_pause_count )
            break;
        ret = -EINVAL;
        if ( (v = domain_vcpu(d, domctl->u.gdbsx_pauseunp_vcpu.vcpu)) == NULL )
            break;
        ret = vcpu_unpause_by_systemcontroller(v);
        if ( ret == -EINVAL )
            printk(XENLOG_G_WARNING
                   "WARN: %pd attempting to unpause %pv which is not paused\n",
                   current->domain, v);
        break;

    case XEN_DOMCTL_gdbsx_domstatus:
        ret = 0;
        domctl->u.gdbsx_domstatus.vcpu_id = -1;
        domctl->u.gdbsx_domstatus.paused = d->controller_pause_count > 0;
        if ( domctl->u.gdbsx_domstatus.paused )
        {
            for_each_vcpu ( d, v )
            {
                if ( v->arch.gdbsx_vcpu_event )
                {
                    domctl->u.gdbsx_domstatus.vcpu_id = v->vcpu_id;
                    domctl->u.gdbsx_domstatus.vcpu_ev =
                        v->arch.gdbsx_vcpu_event;
                    v->arch.gdbsx_vcpu_event = 0;
                    break;
                }
            }
        }
        *copyback = true;
        break;

    default:
        ASSERT_UNREACHABLE();
        ret = -ENOSYS;
        break;
    }

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
