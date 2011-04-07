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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <asm/msr.h>
#include <asm/hvm/support.h>	/* for HVM_DELIVER_NO_ERROR_CODE */
#include <asm/hvm/hvm.h>
#include <asm/p2m.h>    /* for struct p2m_domain */
#include <asm/hvm/nestedhvm.h>
#include <asm/event.h>  /* for local_event_delivery_(en|dis)able */
#include <asm/paging.h> /* for paging_mode_hap() */


/* Nested HVM on/off per domain */
bool_t
nestedhvm_enabled(struct domain *d)
{
    bool_t enabled;

    enabled = !!(d->arch.hvm_domain.params[HVM_PARAM_NESTEDHVM]);
    BUG_ON(enabled && !is_hvm_domain(d));
    
    return enabled;
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

    if (nv->nv_vvmcx)
        hvm_unmap_guest_frame(nv->nv_vvmcx);
    nv->nv_vvmcx = NULL;
    nv->nv_vvmcxaddr = VMCX_EADDR;
    nv->nv_flushp2m = 0;
    nv->nv_p2m = NULL;

    nhvm_vcpu_reset(v);

    /* vcpu is in host mode */
    nestedhvm_vcpu_exit_guestmode(v);
}

int
nestedhvm_vcpu_initialise(struct vcpu *v)
{
    int rc;

    if ( (rc = nhvm_vcpu_initialise(v)) )
    {
        nhvm_vcpu_destroy(v);
        return rc;
    }

    nestedhvm_vcpu_reset(v);
    return 0;
}

void
nestedhvm_vcpu_destroy(struct vcpu *v)
{
    if ( nestedhvm_enabled(v->domain) )
        nhvm_vcpu_destroy(v);
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
}

void
nestedhvm_vmcx_flushtlb(struct p2m_domain *p2m)
{
    on_selected_cpus(&p2m->p2m_dirty_cpumask, nestedhvm_flushtlb_ipi,
        p2m->domain, 1);
    cpus_clear(p2m->p2m_dirty_cpumask);
}

void
nestedhvm_vmcx_flushtlbdomain(struct domain *d)
{
    on_selected_cpus(d->domain_dirty_cpumask, nestedhvm_flushtlb_ipi, d, 1);
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

/* same format and size as hvm_io_bitmap */
#define IOBITMAP_SIZE		3*PAGE_SIZE/BYTES_PER_LONG
/* same format as hvm_io_bitmap */
#define IOBITMAP_VMX_SIZE	2*PAGE_SIZE/BYTES_PER_LONG

static unsigned long *shadow_io_bitmap[3];

void
nestedhvm_setup(void)
{
    /* shadow_io_bitmaps can't be declared static because
     *   they must fulfill hw requirements (page aligned section)
     *   and doing so triggers the ASSERT(va >= XEN_VIRT_START)
     *   in __virt_to_maddr()
     *
     * So as a compromise pre-allocate them when xen boots.
     * This function must be called from within start_xen() when
     * it is valid to use _xmalloc()
     */

    /* shadow I/O permission bitmaps */
    if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
        /* Same format as hvm_io_bitmap */
        shadow_io_bitmap[0] = _xmalloc(IOBITMAP_VMX_SIZE, PAGE_SIZE);
        shadow_io_bitmap[1] = _xmalloc(IOBITMAP_VMX_SIZE, PAGE_SIZE);
        shadow_io_bitmap[2] = _xmalloc(IOBITMAP_VMX_SIZE, PAGE_SIZE);
        memset(shadow_io_bitmap[0], ~0U, IOBITMAP_VMX_SIZE);
        memset(shadow_io_bitmap[1], ~0U, IOBITMAP_VMX_SIZE);
        memset(shadow_io_bitmap[2], ~0U, IOBITMAP_VMX_SIZE);
    } else {
        /* Same size and format as hvm_io_bitmap */
        shadow_io_bitmap[0] = _xmalloc(IOBITMAP_SIZE, PAGE_SIZE);
        shadow_io_bitmap[1] = _xmalloc(IOBITMAP_SIZE, PAGE_SIZE);
        shadow_io_bitmap[2] = _xmalloc(IOBITMAP_SIZE, PAGE_SIZE);
        memset(shadow_io_bitmap[0], ~0U, IOBITMAP_SIZE);
        memset(shadow_io_bitmap[1], ~0U, IOBITMAP_SIZE);
        memset(shadow_io_bitmap[2], ~0U, IOBITMAP_SIZE);
    }

    __clear_bit(0x80, shadow_io_bitmap[0]);
    __clear_bit(0xed, shadow_io_bitmap[1]);
}

unsigned long *
nestedhvm_vcpu_iomap_get(bool_t port_80, bool_t port_ed)
{
    int i;
    extern int hvm_port80_allowed;

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
