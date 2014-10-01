/*
 * io.c: Handling I/O and interrupts.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
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
#include <asm/hvm/emulate.h>
#include <public/sched.h>
#include <xen/iocap.h>
#include <public/hvm/ioreq.h>

void send_timeoffset_req(unsigned long timeoff)
{
    ioreq_t p = {
        .type = IOREQ_TYPE_TIMEOFFSET,
        .size = 8,
        .count = 1,
        .dir = IOREQ_WRITE,
        .data = timeoff,
        .state = STATE_IOREQ_READY,
    };

    if ( timeoff == 0 )
        return;

    if ( !hvm_buffered_io_send(&p) )
        printk("Unsuccessful timeoffset update\n");
}

/* Ask ioemu mapcache to invalidate mappings. */
void send_invalidate_req(void)
{
    ioreq_t p = {
        .type = IOREQ_TYPE_INVALIDATE,
        .size = 4,
        .dir = IOREQ_WRITE,
        .data = ~0UL, /* flush all */
    };

    hvm_broadcast_assist_req(&p);
}

int handle_mmio(void)
{
    struct hvm_emulate_ctxt ctxt;
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    ASSERT(!is_pvh_vcpu(curr));

    hvm_emulate_prepare(&ctxt, guest_cpu_user_regs());

    rc = hvm_emulate_one(&ctxt);

    if ( rc != X86EMUL_RETRY )
        vio->io_state = HVMIO_none;
    if ( vio->io_state == HVMIO_awaiting_completion )
        vio->io_state = HVMIO_handle_mmio_awaiting_completion;
    else
        vio->mmio_access = (struct npfec){};

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_WARNING "MMIO", &ctxt);
        return 0;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_trap(&ctxt.trap);
        break;
    default:
        break;
    }

    hvm_emulate_writeback(&ctxt);

    return 1;
}

int handle_mmio_with_translation(unsigned long gva, unsigned long gpfn,
                                 struct npfec access)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;

    vio->mmio_access = access.gla_valid &&
                       access.kind == npfec_kind_with_gla
                       ? access : (struct npfec){};
    vio->mmio_gva = gva & PAGE_MASK;
    vio->mmio_gpfn = gpfn;
    return handle_mmio();
}

int handle_pio(uint16_t port, unsigned int size, int dir)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    unsigned long data, reps = 1;
    int rc;

    ASSERT((size - 1) < 4 && size != 3);

    if ( dir == IOREQ_WRITE )
        data = guest_cpu_user_regs()->eax;

    rc = hvmemul_do_pio(port, &reps, size, 0, dir, 0, &data);

    switch ( rc )
    {
    case X86EMUL_OKAY:
        if ( dir == IOREQ_READ )
        {
            if ( size == 4 ) /* Needs zero extension. */
                guest_cpu_user_regs()->rax = (uint32_t)data;
            else
                memcpy(&guest_cpu_user_regs()->rax, &data, size);
        }
        break;
    case X86EMUL_RETRY:
        if ( vio->io_state != HVMIO_awaiting_completion )
            return 0;
        /* Completion in hvm_io_assist() with no re-emulation required. */
        ASSERT(dir == IOREQ_READ);
        vio->io_state = HVMIO_handle_pio_awaiting_completion;
        break;
    default:
        gdprintk(XENLOG_ERR, "Weird HVM ioemulation status %d.\n", rc);
        domain_crash(curr->domain);
        break;
    }

    return 1;
}

void hvm_io_assist(ioreq_t *p)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    enum hvm_io_state io_state;

    p->state = STATE_IOREQ_NONE;

    io_state = vio->io_state;
    vio->io_state = HVMIO_none;

    switch ( io_state )
    {
    case HVMIO_awaiting_completion:
        vio->io_state = HVMIO_completed;
        vio->io_data = p->data;
        break;
    case HVMIO_handle_mmio_awaiting_completion:
        vio->io_state = HVMIO_completed;
        vio->io_data = p->data;
        (void)handle_mmio();
        break;
    case HVMIO_handle_pio_awaiting_completion:
        if ( vio->io_size == 4 ) /* Needs zero extension. */
            guest_cpu_user_regs()->rax = (uint32_t)p->data;
        else
            memcpy(&guest_cpu_user_regs()->rax, &p->data, vio->io_size);
        break;
    default:
        break;
    }

    if ( p->state == STATE_IOREQ_NONE )
    {
        msix_write_completion(curr);
        vcpu_end_shutdown_deferral(curr);
    }
}

static int dpci_ioport_read(uint32_t mport, ioreq_t *p)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    int rc = X86EMUL_OKAY, i, step = p->df ? -p->size : p->size;
    uint32_t data = 0;

    for ( i = 0; i < p->count; i++ )
    {
        if ( vio->mmio_retrying )
        {
            if ( vio->mmio_large_read_bytes != p->size )
                return X86EMUL_UNHANDLEABLE;
            memcpy(&data, vio->mmio_large_read, p->size);
            vio->mmio_large_read_bytes = 0;
            vio->mmio_retrying = 0;
        }
        else switch ( p->size )
        {
        case 1:
            data = inb(mport);
            break;
        case 2:
            data = inw(mport);
            break;
        case 4:
            data = inl(mport);
            break;
        default:
            BUG();
        }

        if ( p->data_is_ptr )
        {
            switch ( hvm_copy_to_guest_phys(p->data + step * i,
                                            &data, p->size) )
            {
            case HVMCOPY_okay:
                break;
            case HVMCOPY_gfn_paged_out:
            case HVMCOPY_gfn_shared:
                rc = X86EMUL_RETRY;
                break;
            case HVMCOPY_bad_gfn_to_mfn:
                /* Drop the write as real hardware would. */
                continue;
            case HVMCOPY_bad_gva_to_gfn:
                ASSERT(0);
                /* fall through */
            default:
                rc = X86EMUL_UNHANDLEABLE;
                break;
            }
            if ( rc != X86EMUL_OKAY)
                break;
        }
        else
            p->data = data;
    }

    if ( rc == X86EMUL_RETRY )
    {
        vio->mmio_retry = 1;
        vio->mmio_large_read_bytes = p->size;
        memcpy(vio->mmio_large_read, &data, p->size);
    }

    if ( i != 0 )
    {
        p->count = i;
        rc = X86EMUL_OKAY;
    }

    return rc;
}

static int dpci_ioport_write(uint32_t mport, ioreq_t *p)
{
    int rc = X86EMUL_OKAY, i, step = p->df ? -p->size : p->size;
    uint32_t data;

    for ( i = 0; i < p->count; i++ )
    {
        data = p->data;
        if ( p->data_is_ptr )
        {
            switch ( hvm_copy_from_guest_phys(&data, p->data + step * i,
                                              p->size) )
            {
            case HVMCOPY_okay:
                break;
            case HVMCOPY_gfn_paged_out:
            case HVMCOPY_gfn_shared:
                rc = X86EMUL_RETRY;
                break;
            case HVMCOPY_bad_gfn_to_mfn:
                data = ~0;
                break;
            case HVMCOPY_bad_gva_to_gfn:
                ASSERT(0);
                /* fall through */
            default:
                rc = X86EMUL_UNHANDLEABLE;
                break;
            }
            if ( rc != X86EMUL_OKAY)
                break;
        }

        switch ( p->size )
        {
        case 1:
            outb(data, mport);
            break;
        case 2:
            outw(data, mport);
            break;
        case 4:
            outl(data, mport);
            break;
        default:
            BUG();
        }
    }

    if ( rc == X86EMUL_RETRY )
        current->arch.hvm_vcpu.hvm_io.mmio_retry = 1;

    if ( i != 0 )
    {
        p->count = i;
        rc = X86EMUL_OKAY;
    }

    return rc;
}

int dpci_ioport_intercept(ioreq_t *p)
{
    struct domain *d = current->domain;
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct g2m_ioport *g2m_ioport;
    unsigned int mport, gport = p->addr;
    unsigned int s = 0, e = 0;
    int rc;

    list_for_each_entry( g2m_ioport, &hd->arch.g2m_ioport_list, list )
    {
        s = g2m_ioport->gport;
        e = s + g2m_ioport->np;
        if ( (gport >= s) && (gport < e) )
            goto found;
    }

    return X86EMUL_UNHANDLEABLE;

 found:
    mport = (gport - s) + g2m_ioport->mport;

    if ( !ioports_access_permitted(d, mport, mport + p->size - 1) ) 
    {
        gdprintk(XENLOG_ERR, "Error: access to gport=%#x denied!\n",
                 (uint32_t)p->addr);
        return X86EMUL_UNHANDLEABLE;
    }

    switch ( p->dir )
    {
    case IOREQ_READ:
        rc = dpci_ioport_read(mport, p);
        break;
    case IOREQ_WRITE:
        rc = dpci_ioport_write(mport, p);
        break;
    default:
        gdprintk(XENLOG_ERR, "Error: couldn't handle p->dir = %d", p->dir);
        rc = X86EMUL_UNHANDLEABLE;
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
