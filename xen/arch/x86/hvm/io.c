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

#include <xen/init.h>
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
#include <asm/hvm/ioreq.h>
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

    if ( hvm_broadcast_ioreq(&p, true) != 0 )
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

    if ( hvm_broadcast_ioreq(&p, false) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful map-cache invalidate\n");
}

bool hvm_emulate_one_insn(hvm_emulate_validate_t *validate, const char *descr)
{
    struct hvm_emulate_ctxt ctxt;
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    hvm_emulate_init_once(&ctxt, validate, guest_cpu_user_regs());

    rc = hvm_emulate_one(&ctxt);

    if ( hvm_vcpu_io_need_completion(vio) )
        vio->io_completion = HVMIO_mmio_completion;
    else
        vio->mmio_access = (struct npfec){};

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_WARNING, descr, &ctxt, rc);
        return false;

    case X86EMUL_UNRECOGNIZED:
        hvm_dump_emulation_state(XENLOG_G_WARNING, descr, &ctxt, rc);
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
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
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;

    vio->mmio_access = access.gla_valid &&
                       access.kind == npfec_kind_with_gla
                       ? access : (struct npfec){};
    vio->mmio_gla = gla & PAGE_MASK;
    vio->mmio_gpfn = gpfn;
    return handle_mmio();
}

bool handle_pio(uint16_t port, unsigned int size, int dir)
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
        /*
         * We should not advance RIP/EIP if the domain is shutting down or
         * if X86EMUL_RETRY has been returned by an internal handler.
         */
        if ( curr->domain->is_shutting_down || !hvm_io_pending(curr) )
            return false;
        break;

    default:
        gdprintk(XENLOG_ERR, "Weird HVM ioemulation status %d.\n", rc);
        domain_crash(curr->domain);
        return false;
    }

    return true;
}

static bool_t g2m_portio_accept(const struct hvm_io_handler *handler,
                                const ioreq_t *p)
{
    struct vcpu *curr = current;
    const struct hvm_domain *hvm_domain = &curr->domain->arch.hvm_domain;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    struct g2m_ioport *g2m_ioport;
    unsigned int start, end;

    list_for_each_entry( g2m_ioport, &hvm_domain->g2m_ioport_list, list )
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

static int g2m_portio_read(const struct hvm_io_handler *handler,
                           uint64_t addr, uint32_t size, uint64_t *data)
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

static int g2m_portio_write(const struct hvm_io_handler *handler,
                            uint64_t addr, uint32_t size, uint64_t data)
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

/* Do some sanity checks. */
static bool vpci_access_allowed(unsigned int reg, unsigned int len)
{
    /* Check access size. */
    if ( len != 1 && len != 2 && len != 4 && len != 8 )
        return false;

    /* Check that access is size aligned. */
    if ( (reg & (len - 1)) )
        return false;

    return true;
}

/* vPCI config space IO ports handlers (0xcf8/0xcfc). */
static bool vpci_portio_accept(const struct hvm_io_handler *handler,
                               const ioreq_t *p)
{
    return (p->addr == 0xcf8 && p->size == 4) || (p->addr & ~3) == 0xcfc;
}

static int vpci_portio_read(const struct hvm_io_handler *handler,
                            uint64_t addr, uint32_t size, uint64_t *data)
{
    const struct domain *d = current->domain;
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t cf8;

    *data = ~(uint64_t)0;

    if ( addr == 0xcf8 )
    {
        ASSERT(size == 4);
        *data = d->arch.hvm_domain.pci_cf8;
        return X86EMUL_OKAY;
    }

    ASSERT((addr & ~3) == 0xcfc);
    cf8 = ACCESS_ONCE(d->arch.hvm_domain.pci_cf8);
    if ( !CF8_ENABLED(cf8) )
        return X86EMUL_UNHANDLEABLE;

    reg = hvm_pci_decode_addr(cf8, addr, &sbdf);

    if ( !vpci_access_allowed(reg, size) )
        return X86EMUL_OKAY;

    *data = vpci_read(sbdf, reg, size);

    return X86EMUL_OKAY;
}

static int vpci_portio_write(const struct hvm_io_handler *handler,
                             uint64_t addr, uint32_t size, uint64_t data)
{
    struct domain *d = current->domain;
    unsigned int reg;
    pci_sbdf_t sbdf;
    uint32_t cf8;

    if ( addr == 0xcf8 )
    {
        ASSERT(size == 4);
        d->arch.hvm_domain.pci_cf8 = data;
        return X86EMUL_OKAY;
    }

    ASSERT((addr & ~3) == 0xcfc);
    cf8 = ACCESS_ONCE(d->arch.hvm_domain.pci_cf8);
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

    list_for_each_entry ( mmcfg, &d->arch.hvm_domain.mmcfg_regions, next )
        if ( addr >= mmcfg->addr && addr < mmcfg->addr + mmcfg->size )
            return mmcfg;

    return NULL;
}

static unsigned int vpci_mmcfg_decode_addr(const struct hvm_mmcfg *mmcfg,
                                           paddr_t addr, pci_sbdf_t *sbdf)
{
    addr -= mmcfg->addr;
    sbdf->bdf = MMCFG_BDF(addr);
    sbdf->bus += mmcfg->start_bus;
    sbdf->seg = mmcfg->segment;

    return addr & (PCI_CFG_SPACE_EXP_SIZE - 1);
}

static int vpci_mmcfg_accept(struct vcpu *v, unsigned long addr)
{
    struct domain *d = v->domain;
    bool found;

    read_lock(&d->arch.hvm_domain.mmcfg_lock);
    found = vpci_mmcfg_find(d, addr);
    read_unlock(&d->arch.hvm_domain.mmcfg_lock);

    return found;
}

static int vpci_mmcfg_read(struct vcpu *v, unsigned long addr,
                           unsigned int len, unsigned long *data)
{
    struct domain *d = v->domain;
    const struct hvm_mmcfg *mmcfg;
    unsigned int reg;
    pci_sbdf_t sbdf;

    *data = ~0ul;

    read_lock(&d->arch.hvm_domain.mmcfg_lock);
    mmcfg = vpci_mmcfg_find(d, addr);
    if ( !mmcfg )
    {
        read_unlock(&d->arch.hvm_domain.mmcfg_lock);
        return X86EMUL_RETRY;
    }

    reg = vpci_mmcfg_decode_addr(mmcfg, addr, &sbdf);
    read_unlock(&d->arch.hvm_domain.mmcfg_lock);

    if ( !vpci_access_allowed(reg, len) ||
         (reg + len) > PCI_CFG_SPACE_EXP_SIZE )
        return X86EMUL_OKAY;

    /*
     * According to the PCIe 3.1A specification:
     *  - Configuration Reads and Writes must usually be DWORD or smaller
     *    in size.
     *  - Because Root Complex implementations are not required to support
     *    accesses to a RCRB that cross DW boundaries [...] software
     *    should take care not to cause the generation of such accesses
     *    when accessing a RCRB unless the Root Complex will support the
     *    access.
     *  Xen however supports 8byte accesses by splitting them into two
     *  4byte accesses.
     */
    *data = vpci_read(sbdf, reg, min(4u, len));
    if ( len == 8 )
        *data |= (uint64_t)vpci_read(sbdf, reg + 4, 4) << 32;

    return X86EMUL_OKAY;
}

static int vpci_mmcfg_write(struct vcpu *v, unsigned long addr,
                            unsigned int len, unsigned long data)
{
    struct domain *d = v->domain;
    const struct hvm_mmcfg *mmcfg;
    unsigned int reg;
    pci_sbdf_t sbdf;

    read_lock(&d->arch.hvm_domain.mmcfg_lock);
    mmcfg = vpci_mmcfg_find(d, addr);
    if ( !mmcfg )
    {
        read_unlock(&d->arch.hvm_domain.mmcfg_lock);
        return X86EMUL_RETRY;
    }

    reg = vpci_mmcfg_decode_addr(mmcfg, addr, &sbdf);
    read_unlock(&d->arch.hvm_domain.mmcfg_lock);

    if ( !vpci_access_allowed(reg, len) ||
         (reg + len) > PCI_CFG_SPACE_EXP_SIZE )
        return X86EMUL_OKAY;

    vpci_write(sbdf, reg, min(4u, len), data);
    if ( len == 8 )
        vpci_write(sbdf, reg + 4, 4, data >> 32);

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
    struct hvm_mmcfg *mmcfg, *new = xmalloc(struct hvm_mmcfg);

    ASSERT(is_hardware_domain(d));

    if ( !new )
        return -ENOMEM;

    if ( start_bus > end_bus )
    {
        xfree(new);
        return -EINVAL;
    }

    new->addr = addr + (start_bus << 20);
    new->start_bus = start_bus;
    new->segment = seg;
    new->size = (end_bus - start_bus + 1) << 20;

    write_lock(&d->arch.hvm_domain.mmcfg_lock);
    list_for_each_entry ( mmcfg, &d->arch.hvm_domain.mmcfg_regions, next )
        if ( new->addr < mmcfg->addr + mmcfg->size &&
             mmcfg->addr < new->addr + new->size )
        {
            int ret = -EEXIST;

            if ( new->addr == mmcfg->addr &&
                 new->start_bus == mmcfg->start_bus &&
                 new->segment == mmcfg->segment &&
                 new->size == mmcfg->size )
                ret = 0;
            write_unlock(&d->arch.hvm_domain.mmcfg_lock);
            xfree(new);
            return ret;
        }

    if ( list_empty(&d->arch.hvm_domain.mmcfg_regions) )
        register_mmio_handler(d, &vpci_mmcfg_ops);

    list_add(&new->next, &d->arch.hvm_domain.mmcfg_regions);
    write_unlock(&d->arch.hvm_domain.mmcfg_lock);

    return 0;
}

void destroy_vpci_mmcfg(struct domain *d)
{
    struct list_head *mmcfg_regions = &d->arch.hvm_domain.mmcfg_regions;

    write_lock(&d->arch.hvm_domain.mmcfg_lock);
    while ( !list_empty(mmcfg_regions) )
    {
        struct hvm_mmcfg *mmcfg = list_first_entry(mmcfg_regions,
                                                   struct hvm_mmcfg, next);

        list_del(&mmcfg->next);
        xfree(mmcfg);
    }
    write_unlock(&d->arch.hvm_domain.mmcfg_lock);
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
