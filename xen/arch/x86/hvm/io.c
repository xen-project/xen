/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * io.c: Handling I/O and interrupts.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 */

#include <xen/init.h>
#include <xen/ioreq.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>
#include <xen/hypercall.h>
#include <xen/vpci.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
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

    if ( ioreq_broadcast(&p, true) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful timeoffset update\n");
}

bool hvm_emulate_one_insn(hvm_emulate_validate_t *validate, const char *descr)
{
    struct hvm_emulate_ctxt ctxt;
    int rc;

    hvm_emulate_init_once(&ctxt, validate, guest_cpu_user_regs());

    switch ( rc = hvm_emulate_one(&ctxt, VIO_no_completion) )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_WARNING, descr, &ctxt, rc);
        return false;

    case X86EMUL_UNRECOGNIZED:
        hvm_dump_emulation_state(XENLOG_G_WARNING, descr, &ctxt, rc);
        hvm_inject_hw_exception(X86_EXC_UD, X86_EVENT_NO_EC);
        break;

    case X86EMUL_EXCEPTION:
        hvm_inject_event(&ctxt.ctxt.event);
        break;
    }

    hvm_emulate_writeback(&ctxt);

    return true;
}

bool handle_mmio_with_translation(unsigned long gla, unsigned long gpfn,
                                  struct npfec access)
{
    struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;

    hvio->mmio_access = access.gla_valid &&
                        access.kind == npfec_kind_with_gla
                        ? access : (struct npfec){};
    hvio->mmio_gla = gla & PAGE_MASK;
    hvio->mmio_gpfn = gpfn;
    return handle_mmio();
}

bool handle_pio(uint16_t port, unsigned int size, int dir)
{
    struct vcpu *curr = current;
    struct vcpu_io *vio = &curr->io;
    unsigned int data;
    int rc;

    ASSERT((size - 1) < 4 && size != 3);

    if ( dir == IOREQ_WRITE )
        data = guest_cpu_user_regs()->eax;
    else
        data = ~0; /* Avoid any risk of stack rubble. */

    rc = hvmemul_do_pio_buffer(port, size, dir, &data);

    if ( ioreq_needs_completion(&vio->req) )
        vio->completion = VIO_pio_completion;

    switch ( rc )
    {
    case X86EMUL_OKAY:
        if ( dir == IOREQ_READ )
        {
            if ( size == 4 ) /* Needs zero extension. */
                guest_cpu_user_regs()->rax = data;
            else
                memcpy(&guest_cpu_user_regs()->rax, &data, size);
        }
        break;

    case X86EMUL_RETRY:
        /*
         * We should not advance RIP/EIP if the vio was suspended (e.g.
         * because the domain is shutting down) or if X86EMUL_RETRY has
         * been returned by an internal handler.
         */
        if ( vio->suspended || !vcpu_ioreq_pending(curr) )
            return false;
        break;

    default:
        gprintk(XENLOG_ERR, "Unexpected PIO status %d, port %#x %s 0x%0*x\n",
                rc, port, dir == IOREQ_WRITE ? "write" : "read",
                size * 2, data & ((1u << (size * 8)) - 1));
        domain_crash(curr->domain);
        return false;
    }

    return true;
}

static bool cf_check g2m_portio_accept(
    const struct hvm_io_handler *handler, const ioreq_t *p)
{
    struct vcpu *curr = current;
    const struct hvm_domain *hvm = &curr->domain->arch.hvm;
    struct hvm_vcpu_io *hvio = &curr->arch.hvm.hvm_io;
    struct g2m_ioport *g2m_ioport;
    unsigned int start, end;

    list_for_each_entry( g2m_ioport, &hvm->g2m_ioport_list, list )
    {
        start = g2m_ioport->gport;
        end = start + g2m_ioport->np;
        if ( (p->addr >= start) && (p->addr + p->size <= end) )
        {
            hvio->g2m_ioport = g2m_ioport;
            return 1;
        }
    }

    return 0;
}

static int cf_check g2m_portio_read(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
    uint64_t *data)
{
    struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;
    const struct g2m_ioport *g2m_ioport = hvio->g2m_ioport;
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

static int cf_check g2m_portio_write(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
    uint64_t data)
{
    struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;
    const struct g2m_ioport *g2m_ioport = hvio->g2m_ioport;
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

static const struct hvm_io_ops g2m_portio_ops = {
    .accept = g2m_portio_accept,
    .read = g2m_portio_read,
    .write = g2m_portio_write
};

void register_g2m_portio_handler(struct domain *d)
{
    struct hvm_io_handler *handler = hvm_next_io_handler(d);

    if ( handler == NULL )
        return;

    handler->type = IOREQ_TYPE_PIO;
    handler->ops = &g2m_portio_ops;
}

unsigned int hvm_pci_decode_addr(unsigned int cf8, unsigned int addr,
                                 pci_sbdf_t *sbdf)
{
    ASSERT(CF8_ENABLED(cf8));

    sbdf->bdf = CF8_BDF(cf8);
    sbdf->seg = 0;
    /*
     * NB: the lower 2 bits of the register address are fetched from the
     * offset into the 0xcfc register when reading/writing to it.
     */
    return CF8_ADDR_LO(cf8) | (addr & 3);
}

/* vPCI config space IO ports handlers (0xcf8/0xcfc). */
static bool cf_check vpci_portio_accept(
    const struct hvm_io_handler *handler, const ioreq_t *p)
{
    return (p->addr == 0xcf8 && p->size == 4) || (p->addr & ~3) == 0xcfc;
}

static int cf_check vpci_portio_read(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
    uint64_t *data)
{
    const struct domain *d = current->domain;
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t cf8;

    *data = ~(uint64_t)0;

    if ( addr == 0xcf8 )
    {
        ASSERT(size == 4);
        *data = d->arch.hvm.pci_cf8;
        return X86EMUL_OKAY;
    }

    ASSERT((addr & ~3) == 0xcfc);
    cf8 = ACCESS_ONCE(d->arch.hvm.pci_cf8);
    if ( !CF8_ENABLED(cf8) )
        return X86EMUL_UNHANDLEABLE;

    reg = hvm_pci_decode_addr(cf8, addr, &sbdf);

    if ( !vpci_access_allowed(reg, size) )
        return X86EMUL_OKAY;

    *data = vpci_read(sbdf, reg, size);

    return X86EMUL_OKAY;
}

static int cf_check vpci_portio_write(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
    uint64_t data)
{
    struct domain *d = current->domain;
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t cf8;

    if ( addr == 0xcf8 )
    {
        ASSERT(size == 4);
        d->arch.hvm.pci_cf8 = data;
        return X86EMUL_OKAY;
    }

    ASSERT((addr & ~3) == 0xcfc);
    cf8 = ACCESS_ONCE(d->arch.hvm.pci_cf8);
    if ( !CF8_ENABLED(cf8) )
        return X86EMUL_UNHANDLEABLE;

    reg = hvm_pci_decode_addr(cf8, addr, &sbdf);

    if ( !vpci_access_allowed(reg, size) )
        return X86EMUL_OKAY;

    vpci_write(sbdf, reg, size, data);

    return X86EMUL_OKAY;
}

static const struct hvm_io_ops vpci_portio_ops = {
    .accept = vpci_portio_accept,
    .read = vpci_portio_read,
    .write = vpci_portio_write,
};

void register_vpci_portio_handler(struct domain *d)
{
    struct hvm_io_handler *handler;

    if ( !has_vpci(d) )
        return;

    handler = hvm_next_io_handler(d);
    if ( !handler )
        return;

    handler->type = IOREQ_TYPE_PIO;
    handler->ops = &vpci_portio_ops;
}

struct hvm_mmcfg {
    struct list_head next;
    paddr_t addr;
    unsigned int size;
    uint16_t segment;
    uint8_t start_bus;
};

/* Handlers to trap PCI MMCFG config accesses. */
static const struct hvm_mmcfg *vpci_mmcfg_find(const struct domain *d,
                                               paddr_t addr)
{
    const struct hvm_mmcfg *mmcfg;

    list_for_each_entry ( mmcfg, &d->arch.hvm.mmcfg_regions, next )
        if ( addr >= mmcfg->addr && addr < mmcfg->addr + mmcfg->size )
            return mmcfg;

    return NULL;
}

int __hwdom_init vpci_subtract_mmcfg(const struct domain *d, struct rangeset *r)
{
    const struct hvm_mmcfg *mmcfg;

    list_for_each_entry ( mmcfg, &d->arch.hvm.mmcfg_regions, next )
    {
        int rc = rangeset_remove_range(r, PFN_DOWN(mmcfg->addr),
                                       PFN_DOWN(mmcfg->addr + mmcfg->size - 1));

        if ( rc )
            return rc;
    }

    return 0;
}

static unsigned int vpci_mmcfg_decode_addr(const struct hvm_mmcfg *mmcfg,
                                           paddr_t addr, pci_sbdf_t *sbdf)
{
    addr -= mmcfg->addr;
    sbdf->bdf = VPCI_ECAM_BDF(addr);
    sbdf->bus += mmcfg->start_bus;
    sbdf->seg = mmcfg->segment;

    return addr & (PCI_CFG_SPACE_EXP_SIZE - 1);
}

static int cf_check vpci_mmcfg_accept(struct vcpu *v, unsigned long addr)
{
    struct domain *d = v->domain;
    bool found;

    read_lock(&d->arch.hvm.mmcfg_lock);
    found = vpci_mmcfg_find(d, addr);
    read_unlock(&d->arch.hvm.mmcfg_lock);

    return found;
}

static int cf_check vpci_mmcfg_read(
    struct vcpu *v, unsigned long addr, unsigned int len, unsigned long *data)
{
    struct domain *d = v->domain;
    const struct hvm_mmcfg *mmcfg;
    unsigned int reg;
    pci_sbdf_t sbdf;

    *data = ~0UL;

    read_lock(&d->arch.hvm.mmcfg_lock);
    mmcfg = vpci_mmcfg_find(d, addr);
    if ( !mmcfg )
    {
        read_unlock(&d->arch.hvm.mmcfg_lock);
        return X86EMUL_RETRY;
    }

    reg = vpci_mmcfg_decode_addr(mmcfg, addr, &sbdf);
    read_unlock(&d->arch.hvm.mmcfg_lock);

    /* Failed reads are not propagated to the caller */
    vpci_ecam_read(sbdf, reg, len, data);

    return X86EMUL_OKAY;
}

static int cf_check vpci_mmcfg_write(
    struct vcpu *v, unsigned long addr, unsigned int len, unsigned long data)
{
    struct domain *d = v->domain;
    const struct hvm_mmcfg *mmcfg;
    unsigned int reg;
    pci_sbdf_t sbdf;

    read_lock(&d->arch.hvm.mmcfg_lock);
    mmcfg = vpci_mmcfg_find(d, addr);
    if ( !mmcfg )
    {
        read_unlock(&d->arch.hvm.mmcfg_lock);
        return X86EMUL_RETRY;
    }

    reg = vpci_mmcfg_decode_addr(mmcfg, addr, &sbdf);
    read_unlock(&d->arch.hvm.mmcfg_lock);

    /* Failed writes are not propagated to the caller */
    vpci_ecam_write(sbdf, reg, len, data);

    return X86EMUL_OKAY;
}

static const struct hvm_mmio_ops vpci_mmcfg_ops = {
    .check = vpci_mmcfg_accept,
    .read = vpci_mmcfg_read,
    .write = vpci_mmcfg_write,
};

int register_vpci_mmcfg_handler(struct domain *d, paddr_t addr,
                                unsigned int start_bus, unsigned int end_bus,
                                unsigned int seg)
{
    struct hvm_mmcfg *mmcfg, *new;

    ASSERT(is_hardware_domain(d));

    if ( start_bus > end_bus )
        return -EINVAL;

    new = xmalloc(struct hvm_mmcfg);
    if ( !new )
        return -ENOMEM;

    new->addr = addr + (start_bus << 20);
    new->start_bus = start_bus;
    new->segment = seg;
    new->size = (end_bus - start_bus + 1) << 20;

    write_lock(&d->arch.hvm.mmcfg_lock);
    list_for_each_entry ( mmcfg, &d->arch.hvm.mmcfg_regions, next )
        if ( new->addr < mmcfg->addr + mmcfg->size &&
             mmcfg->addr < new->addr + new->size )
        {
            int ret = -EEXIST;

            if ( new->addr == mmcfg->addr &&
                 new->start_bus == mmcfg->start_bus &&
                 new->segment == mmcfg->segment &&
                 new->size == mmcfg->size )
                ret = 0;
            write_unlock(&d->arch.hvm.mmcfg_lock);
            xfree(new);
            return ret;
        }

    if ( list_empty(&d->arch.hvm.mmcfg_regions) )
        register_mmio_handler(d, &vpci_mmcfg_ops);

    list_add(&new->next, &d->arch.hvm.mmcfg_regions);
    write_unlock(&d->arch.hvm.mmcfg_lock);

    return 0;
}

void destroy_vpci_mmcfg(struct domain *d)
{
    struct list_head *mmcfg_regions = &d->arch.hvm.mmcfg_regions;

    write_lock(&d->arch.hvm.mmcfg_lock);
    while ( !list_empty(mmcfg_regions) )
    {
        struct hvm_mmcfg *mmcfg = list_first_entry(mmcfg_regions,
                                                   struct hvm_mmcfg, next);

        list_del(&mmcfg->next);
        xfree(mmcfg);
    }
    write_unlock(&d->arch.hvm.mmcfg_lock);
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
