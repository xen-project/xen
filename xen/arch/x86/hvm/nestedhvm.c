/*
 * Nested HVM
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/msr.h>
#include <asm/hvm/support.h>
#include <asm/hvm/hvm.h>
#include <asm/p2m.h>    /* for struct p2m_domain */
#include <asm/hvm/nestedhvm.h>
#include <asm/event.h>  /* for local_event_delivery_(en|dis)able */
#include <asm/paging.h> /* for paging_mode_hap() */

static unsigned long *shadow_io_bitmap[3];

/* Nested HVM on/off per domain */
bool nestedhvm_enabled(const struct domain *d)
{
    return is_hvm_domain(d) && d->arch.hvm_domain.params &&
        d->arch.hvm_domain.params[HVM_PARAM_NESTEDHVM];
}

/* Nested VCPU */
bool_t
nestedhvm_vcpu_in_guestmode(struct vcpu *v)
{
    return vcpu_nestedhvm(v).nv_guestmode;
}

void
nestedhvm_vcpu_reset(struct vcpu *v)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);

    nv->nv_vmentry_pending = 0;
    nv->nv_vmexit_pending = 0;
    nv->nv_vmswitch_in_progress = 0;
    nv->nv_ioport80 = 0;
    nv->nv_ioportED = 0;

    hvm_unmap_guest_frame(nv->nv_vvmcx, 1);
    nv->nv_vvmcx = NULL;
    nv->nv_vvmcxaddr = INVALID_PADDR;
    nv->nv_flushp2m = 0;
    nv->nv_p2m = NULL;
    nv->stale_np2m = false;
    nv->np2m_generation = 0;

    hvm_asid_flush_vcpu_asid(&nv->nv_n2asid);

    if ( hvm_funcs.nhvm_vcpu_reset )
        hvm_funcs.nhvm_vcpu_reset(v);

    /* vcpu is in host mode */
    nestedhvm_vcpu_exit_guestmode(v);
}

int
nestedhvm_vcpu_initialise(struct vcpu *v)
{
    int rc = -EOPNOTSUPP;

    if ( !shadow_io_bitmap[0] )
        return -ENOMEM;

    if ( !hvm_funcs.nhvm_vcpu_initialise ||
         ((rc = hvm_funcs.nhvm_vcpu_initialise(v)) != 0) )
         return rc;

    nestedhvm_vcpu_reset(v);
    return 0;
}

void
nestedhvm_vcpu_destroy(struct vcpu *v)
{
    if ( hvm_funcs.nhvm_vcpu_destroy )
        hvm_funcs.nhvm_vcpu_destroy(v);
}

static void
nestedhvm_flushtlb_ipi(void *info)
{
    struct vcpu *v = current;
    struct domain *d = info;

    ASSERT(d != NULL);
    if (v->domain != d) {
        /* This cpu doesn't belong to the domain */
        return;
    }

    /* Just flush the ASID (or request a new one).
     * This is cheaper than flush_tlb_local() and has
     * the same desired effect.
     */
    hvm_asid_flush_core();
    vcpu_nestedhvm(v).nv_p2m = NULL;
    vcpu_nestedhvm(v).stale_np2m = true;
}

void
nestedhvm_vmcx_flushtlb(struct p2m_domain *p2m)
{
    on_selected_cpus(p2m->dirty_cpumask, nestedhvm_flushtlb_ipi,
        p2m->domain, 1);
    cpumask_clear(p2m->dirty_cpumask);
}

bool_t
nestedhvm_is_n2(struct vcpu *v)
{
    if (!nestedhvm_enabled(v->domain)
      || nestedhvm_vmswitch_in_progress(v)
      || !nestedhvm_paging_mode_hap(v))
        return 0;

    if (nestedhvm_vcpu_in_guestmode(v))
        return 1;

    return 0;
}

/* Common shadow IO Permission bitmap */

/* There four global patterns of io bitmap each guest can
 * choose depending on interception of io port 0x80 and/or
 * 0xED (shown in table below).
 * The users of the bitmap patterns are in SVM/VMX specific code.
 *
 * bitmap        port 0x80  port 0xed
 * hvm_io_bitmap cleared    cleared
 * iomap[0]      cleared    set
 * iomap[1]      set        cleared
 * iomap[2]      set        set
 */

static int __init
nestedhvm_setup(void)
{
    /* Same format and size as hvm_io_bitmap (Intel needs only 2 pages). */
    unsigned nr = cpu_has_vmx ? 2 : 3;
    unsigned int i, order = get_order_from_pages(nr);

    if ( !hvm_funcs.name )
        return 0;

    /* shadow_io_bitmaps can't be declared static because
     *   they must fulfill hw requirements (page aligned section)
     *   and doing so triggers the ASSERT(va >= XEN_VIRT_START)
     *   in __virt_to_maddr()
     *
     * So as a compromise pre-allocate them when xen boots.
     * This function must be called from within start_xen() when
     * it is valid to use _xmalloc()
     */

    for ( i = 0; i < ARRAY_SIZE(shadow_io_bitmap); i++ )
    {
        shadow_io_bitmap[i] = alloc_xenheap_pages(order, 0);
        if ( !shadow_io_bitmap[i] )
        {
            while ( i-- )
            {
                free_xenheap_pages(shadow_io_bitmap[i], order);
                shadow_io_bitmap[i] = NULL;
            }
            return -ENOMEM;
        }
        memset(shadow_io_bitmap[i], ~0U, nr << PAGE_SHIFT);
    }

    __clear_bit(0x80, shadow_io_bitmap[0]);
    __clear_bit(0xed, shadow_io_bitmap[1]);

    return 0;
}
__initcall(nestedhvm_setup);

unsigned long *
nestedhvm_vcpu_iomap_get(bool_t port_80, bool_t port_ed)
{
    int i;

    if (!hvm_port80_allowed)
        port_80 = 1;

    if (port_80 == 0) {
        if (port_ed == 0)
            return hvm_io_bitmap;
        i = 0;
    } else {
        if (port_ed == 0)
            i = 1;
        else
            i = 2;
    }

    return shadow_io_bitmap[i];
}
