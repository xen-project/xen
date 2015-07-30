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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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

    if ( hvm_broadcast_ioreq(&p, 1) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful timeoffset update\n");
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

    if ( hvm_broadcast_ioreq(&p, 0) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful map-cache invalidate\n");
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

    if ( hvm_vcpu_io_need_completion(vio) || vio->mmio_retry )
        vio->io_completion = HVMIO_mmio_completion;
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
    unsigned long data;
    int rc;

    ASSERT((size - 1) < 4 && size != 3);

    if ( dir == IOREQ_WRITE )
        data = guest_cpu_user_regs()->eax;

    rc = hvmemul_do_pio_buffer(port, size, dir, &data);

    if ( hvm_vcpu_io_need_completion(vio) )
        vio->io_completion = HVMIO_pio_completion;

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
        /* We should not advance RIP/EIP if the domain is shutting down */
        if ( curr->domain->is_shutting_down )
            return 0;

        break;
    default:
        gdprintk(XENLOG_ERR, "Weird HVM ioemulation status %d.\n", rc);
        domain_crash(curr->domain);
        break;
    }

    return 1;
}

static bool_t dpci_portio_accept(const struct hvm_io_handler *handler,
                                 const ioreq_t *p)
{
    struct vcpu *curr = current;
    struct hvm_iommu *hd = domain_hvm_iommu(curr->domain);
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    struct g2m_ioport *g2m_ioport;
    unsigned int start, end;

    list_for_each_entry( g2m_ioport, &hd->arch.g2m_ioport_list, list )
    {
        start = g2m_ioport->gport;
        end = start + g2m_ioport->np;
        if ( (p->addr >= start) && (p->addr + p->size <= end) )
        {
            vio->g2m_ioport = g2m_ioport;
            return 1;
        }
    }

    return 0;
}

static int dpci_portio_read(const struct hvm_io_handler *handler,
                            uint64_t addr,
                            uint32_t size,
                            uint64_t *data)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    const struct g2m_ioport *g2m_ioport = vio->g2m_ioport;
    unsigned int mport = (addr - g2m_ioport->gport) + g2m_ioport->mport;

    switch ( size )
    {
    case 1:
        *data = inb(mport);
        break;
    case 2:
        *data = inw(mport);
        break;
    case 4:
        *data = inl(mport);
        break;
    default:
        BUG();
    }

    return X86EMUL_OKAY;
}

static int dpci_portio_write(const struct hvm_io_handler *handler,
                             uint64_t addr,
                             uint32_t size,
                             uint64_t data)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    const struct g2m_ioport *g2m_ioport = vio->g2m_ioport;
    unsigned int mport = (addr - g2m_ioport->gport) + g2m_ioport->mport;

    switch ( size )
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

    return X86EMUL_OKAY;
}

static const struct hvm_io_ops dpci_portio_ops = {
    .accept = dpci_portio_accept,
    .read = dpci_portio_read,
    .write = dpci_portio_write
};

void register_dpci_portio_handler(struct domain *d)
{
    struct hvm_io_handler *handler = hvm_next_io_handler(d);

    if ( handler == NULL )
        return;

    handler->type = IOREQ_TYPE_PIO;
    handler->ops = &dpci_portio_ops;
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
