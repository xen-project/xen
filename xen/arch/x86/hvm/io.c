/*
 * io.c: Handling I/O and interrupts.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>

#include <xen/hypercall.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/trace.h>

#include <public/sched.h>
#include <xen/iocap.h>
#include <public/hvm/ioreq.h>

static void hvm_pio_assist(
    struct cpu_user_regs *regs, ioreq_t *p, struct hvm_io_op *pio_opp)
{
    if ( p->data_is_ptr || (pio_opp->flags & OVERLAP) )
    {
        int sign = p->df ? -1 : 1;

        if ( pio_opp->flags & REPZ )
            regs->ecx -= p->count;

        if ( p->dir == IOREQ_READ )
        {
            if ( pio_opp->flags & OVERLAP )
            {
                unsigned long addr = pio_opp->addr;
                if ( hvm_paging_enabled(current) )
                {
                    int rv = hvm_copy_to_guest_virt(addr, &p->data, p->size);
                    if ( rv == HVMCOPY_bad_gva_to_gfn )
                        return; /* exception already injected */
                }
                else
                    (void)hvm_copy_to_guest_phys(addr, &p->data, p->size);
            }
            regs->edi += sign * p->count * p->size;
        }
        else /* p->dir == IOREQ_WRITE */
        {
            ASSERT(p->dir == IOREQ_WRITE);
            regs->esi += sign * p->count * p->size;
        }
    }
    else if ( p->dir == IOREQ_READ )
    {
        unsigned long old_eax = regs->eax;

        switch ( p->size )
        {
        case 1:
            regs->eax = (old_eax & ~0xff) | (p->data & 0xff);
            break;
        case 2:
            regs->eax = (old_eax & ~0xffff) | (p->data & 0xffff);
            break;
        case 4:
            regs->eax = (p->data & 0xffffffff);
            break;
        default:
            printk("Error: %s unknown port size\n", __FUNCTION__);
            domain_crash_synchronous();
        }
        HVMTRACE_1D(IO_ASSIST, current, p->data);
    }
}

void hvm_io_assist(void)
{
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct cpu_user_regs *regs;
    struct hvm_io_op *io_opp;
    struct vcpu *v = current;

    io_opp = &v->arch.hvm_vcpu.io_op;
    regs   = &io_opp->io_context;
    vio    = get_ioreq(v);

    p = &vio->vp_ioreq;
    if ( p->state != STATE_IORESP_READY )
    {
        gdprintk(XENLOG_ERR, "Unexpected HVM iorequest state %d.\n", p->state);
        domain_crash(v->domain);
        goto out;
    }

    rmb(); /* see IORESP_READY /then/ read contents of ioreq */

    p->state = STATE_IOREQ_NONE;

    if ( v->arch.hvm_vcpu.io_in_progress )
    {
        v->arch.hvm_vcpu.io_in_progress = 0;
        if ( p->dir == IOREQ_READ )
        {
            v->arch.hvm_vcpu.io_completed = 1;
            v->arch.hvm_vcpu.io_data = p->data;
        }
        if ( v->arch.hvm_vcpu.mmio_in_progress )
            (void)handle_mmio();
        goto out;
    }

    switch ( p->type )
    {
    case IOREQ_TYPE_INVALIDATE:
        goto out;
    case IOREQ_TYPE_PIO:
        hvm_pio_assist(regs, p, io_opp);
        break;
    default:
        gdprintk(XENLOG_ERR, "Unexpected HVM iorequest state %d.\n", p->state);
        domain_crash(v->domain);
        goto out;
    }

    /* Copy register changes back into current guest state. */
    regs->eflags &= ~X86_EFLAGS_RF;
    memcpy(guest_cpu_user_regs(), regs, HVM_CONTEXT_STACK_BYTES);
    if ( regs->eflags & X86_EFLAGS_TF )
        hvm_inject_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE, 0);

 out:
    vcpu_end_shutdown_deferral(v);
}

void dpci_ioport_read(uint32_t mport, ioreq_t *p)
{
    uint64_t i;
    uint64_t z_data;
    uint64_t length = (p->count * p->size);

    for ( i = 0; i < length; i += p->size )
    {
        z_data = ~0ULL;
        
        switch ( p->size )
        {
        case BYTE:
            z_data = (uint64_t)inb(mport);
            break;
        case WORD:
            z_data = (uint64_t)inw(mport);
            break;
        case LONG:
            z_data = (uint64_t)inl(mport);
            break;
        default:
            gdprintk(XENLOG_ERR, "Error: unable to handle size: %"
                     PRId64 "\n", p->size);
            return;
        }

        p->data = z_data;
        if ( p->data_is_ptr &&
             hvm_copy_to_guest_phys(p->data + i, (void *)&z_data,
                                    (int)p->size) )
        {
            gdprintk(XENLOG_ERR, "Error: couldn't copy to hvm phys\n");
            return;
        }
    }
}

void dpci_ioport_write(uint32_t mport, ioreq_t *p)
{
    uint64_t i;
    uint64_t z_data = 0;
    uint64_t length = (p->count * p->size);

    for ( i = 0; i < length; i += p->size )
    {
        z_data = p->data;
        if ( p->data_is_ptr &&
             hvm_copy_from_guest_phys((void *)&z_data,
                                      p->data + i, (int)p->size) )
        {
            gdprintk(XENLOG_ERR, "Error: couldn't copy from hvm phys\n");
            return;
        }

        switch ( p->size )
        {
        case BYTE:
            outb((uint8_t) z_data, mport);
            break;
        case WORD:
            outw((uint16_t) z_data, mport);
            break;
        case LONG:
            outl((uint32_t) z_data, mport);
            break;
        default:
            gdprintk(XENLOG_ERR, "Error: unable to handle size: %"
                     PRId64 "\n", p->size);
            break;
        }
    }
}

int dpci_ioport_intercept(ioreq_t *p)
{
    struct domain *d = current->domain;
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct g2m_ioport *g2m_ioport;
    unsigned int mport, gport = p->addr;
    unsigned int s = 0, e = 0;

    list_for_each_entry( g2m_ioport, &hd->g2m_ioport_list, list )
    {
        s = g2m_ioport->gport;
        e = s + g2m_ioport->np;
        if ( (gport >= s) && (gport < e) )
            goto found;
    }

    return 0;

 found:
    mport = (gport - s) + g2m_ioport->mport;

    if ( !ioports_access_permitted(d, mport, mport + p->size - 1) ) 
    {
        gdprintk(XENLOG_ERR, "Error: access to gport=0x%x denied!\n",
                 (uint32_t)p->addr);
        return 0;
    }

    switch ( p->dir )
    {
    case IOREQ_READ:
        dpci_ioport_read(mport, p);
        break;
    case IOREQ_WRITE:
        dpci_ioport_write(mport, p);
        break;
    default:
        gdprintk(XENLOG_ERR, "Error: couldn't handle p->dir = %d", p->dir);
    }

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
