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

int hvm_buffered_io_send(ioreq_t *p)
{
    struct vcpu *v = current;
    struct hvm_ioreq_page *iorp = &v->domain->arch.hvm_domain.buf_ioreq;
    buffered_iopage_t *pg = iorp->va;
    buf_ioreq_t bp;
    /* Timeoffset sends 64b data, but no address. Use two consecutive slots. */
    int qw = 0;

    /* Ensure buffered_iopage fits in a page */
    BUILD_BUG_ON(sizeof(buffered_iopage_t) > PAGE_SIZE);

    /*
     * Return 0 for the cases we can't deal with:
     *  - 'addr' is only a 20-bit field, so we cannot address beyond 1MB
     *  - we cannot buffer accesses to guest memory buffers, as the guest
     *    may expect the memory buffer to be synchronously accessed
     *  - the count field is usually used with data_is_ptr and since we don't
     *    support data_is_ptr we do not waste space for the count field either
     */
    if ( (p->addr > 0xffffful) || p->data_is_ptr || (p->count != 1) )
        return 0;

    bp.type = p->type;
    bp.dir  = p->dir;
    switch ( p->size )
    {
    case 1:
        bp.size = 0;
        break;
    case 2:
        bp.size = 1;
        break;
    case 4:
        bp.size = 2;
        break;
    case 8:
        bp.size = 3;
        qw = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "unexpected ioreq size: %u\n", p->size);
        return 0;
    }
    
    bp.data = p->data;
    bp.addr = p->addr;
    
    spin_lock(&iorp->lock);

    if ( (pg->write_pointer - pg->read_pointer) >=
         (IOREQ_BUFFER_SLOT_NUM - qw) )
    {
        /* The queue is full: send the iopacket through the normal path. */
        spin_unlock(&iorp->lock);
        return 0;
    }
    
    memcpy(&pg->buf_ioreq[pg->write_pointer % IOREQ_BUFFER_SLOT_NUM],
           &bp, sizeof(bp));
    
    if ( qw )
    {
        bp.data = p->data >> 32;
        memcpy(&pg->buf_ioreq[(pg->write_pointer+1) % IOREQ_BUFFER_SLOT_NUM],
               &bp, sizeof(bp));
    }

    /* Make the ioreq_t visible /before/ write_pointer. */
    wmb();
    pg->write_pointer += qw ? 2 : 1;

    notify_via_xen_event_channel(v->domain,
            v->domain->arch.hvm_domain.params[HVM_PARAM_BUFIOREQ_EVTCHN]);
    spin_unlock(&iorp->lock);
    
    return 1;
}

void send_timeoffset_req(unsigned long timeoff)
{
    ioreq_t p[1];

    if ( timeoff == 0 )
        return;

    memset(p, 0, sizeof(*p));

    p->type = IOREQ_TYPE_TIMEOFFSET;
    p->size = 8;
    p->count = 1;
    p->dir = IOREQ_WRITE;
    p->data = timeoff;

    p->state = STATE_IOREQ_READY;

    if ( !hvm_buffered_io_send(p) )
        printk("Unsuccessful timeoffset update\n");
}

/* Ask ioemu mapcache to invalidate mappings. */
void send_invalidate_req(void)
{
    struct vcpu *v = current;
    ioreq_t *p = get_ioreq(v);

    if ( p->state != STATE_IOREQ_NONE )
    {
        gdprintk(XENLOG_ERR, "WARNING: send invalidate req with something "
                 "already pending (%d)?\n", p->state);
        domain_crash(v->domain);
        return;
    }

    p->type = IOREQ_TYPE_INVALIDATE;
    p->size = 4;
    p->dir = IOREQ_WRITE;
    p->data = ~0UL; /* flush all */

    (void)hvm_send_assist_req(v);
}

int handle_mmio(void)
{
    struct hvm_emulate_ctxt ctxt;
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    hvm_emulate_prepare(&ctxt, guest_cpu_user_regs());

    rc = hvm_emulate_one(&ctxt);

    if ( rc != X86EMUL_RETRY )
        vio->io_state = HVMIO_none;
    if ( vio->io_state == HVMIO_awaiting_completion )
        vio->io_state = HVMIO_handle_mmio_awaiting_completion;
    else
        vio->mmio_gva = 0;

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        gdprintk(XENLOG_WARNING,
                 "MMIO emulation failed @ %04x:%lx: "
                 "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                 hvmemul_get_seg_reg(x86_seg_cs, &ctxt)->sel,
                 ctxt.insn_buf_eip,
                 ctxt.insn_buf[0], ctxt.insn_buf[1],
                 ctxt.insn_buf[2], ctxt.insn_buf[3],
                 ctxt.insn_buf[4], ctxt.insn_buf[5],
                 ctxt.insn_buf[6], ctxt.insn_buf[7],
                 ctxt.insn_buf[8], ctxt.insn_buf[9]);
        return 0;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_hw_exception(ctxt.exn_vector, ctxt.exn_error_code);
        break;
    default:
        break;
    }

    hvm_emulate_writeback(&ctxt);

    return 1;
}

int handle_mmio_with_translation(unsigned long gva, unsigned long gpfn)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
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
#ifdef __x86_64__
            if ( size == 4 ) /* Needs zero extension. */
                guest_cpu_user_regs()->rax = (uint32_t)data;
            else
#endif
                memcpy(&guest_cpu_user_regs()->eax, &data, size);
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

void hvm_io_assist(void)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    ioreq_t *p = get_ioreq(curr);
    enum hvm_io_state io_state;

    rmb(); /* see IORESP_READY /then/ read contents of ioreq */

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
#ifdef __x86_64__
        if ( vio->io_size == 4 ) /* Needs zero extension. */
            guest_cpu_user_regs()->rax = (uint32_t)p->data;
        else
#endif
            memcpy(&guest_cpu_user_regs()->eax, &p->data, vio->io_size);
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
    int i, sign = p->df ? -1 : 1;
    uint32_t data = 0;

    for ( i = 0; i < p->count; i++ )
    {
        switch ( p->size )
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
            int ret;
            ret = hvm_copy_to_guest_phys(p->data + (sign * i * p->size), &data,
                                         p->size);
            if ( (ret == HVMCOPY_gfn_paged_out) ||
                 (ret == HVMCOPY_gfn_shared) )
                return X86EMUL_RETRY;
        }
        else
            p->data = data;
    }
    
    return X86EMUL_OKAY;
}

static int dpci_ioport_write(uint32_t mport, ioreq_t *p)
{
    int i, sign = p->df ? -1 : 1;
    uint32_t data;

    for ( i = 0; i < p->count; i++ )
    {
        data = p->data;
        if ( p->data_is_ptr )
        {
            switch ( hvm_copy_from_guest_phys(&data,
                                              p->data + sign * i * p->size,
                                              p->size) )
            {
            case HVMCOPY_okay:
                break;
            case HVMCOPY_gfn_paged_out:
            case HVMCOPY_gfn_shared:
                return X86EMUL_RETRY;
            case HVMCOPY_bad_gfn_to_mfn:
                data = ~0;
                break;
            case HVMCOPY_bad_gva_to_gfn:
                ASSERT(0);
                /* fall through */
            default:
                return X86EMUL_UNHANDLEABLE;
            }
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

    return X86EMUL_OKAY;
}

int dpci_ioport_intercept(ioreq_t *p)
{
    struct domain *d = current->domain;
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct g2m_ioport *g2m_ioport;
    unsigned int mport, gport = p->addr;
    unsigned int s = 0, e = 0;
    int rc;

    list_for_each_entry( g2m_ioport, &hd->g2m_ioport_list, list )
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
        gdprintk(XENLOG_ERR, "Error: access to gport=0x%x denied!\n",
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
