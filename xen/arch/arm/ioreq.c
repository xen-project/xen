/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arm/ioreq.c: hardware virtual machine I/O emulation
 *
 * Copyright (c) 2019 Arm ltd.
 */

#include <xen/domain.h>
#include <xen/ioreq.h>

#include <asm/traps.h>
#include <asm/ioreq.h>

#include <public/hvm/ioreq.h>

enum io_state handle_ioserv(struct cpu_user_regs *regs, struct vcpu *v)
{
    const union hsr hsr = { .bits = regs->hsr };
    const struct hsr_dabt dabt = hsr.dabt;
    const uint8_t access_size = (1U << dabt.size) * 8;
    const uint64_t access_mask = GENMASK_ULL(access_size - 1, 0);
    /* Code is similar to handle_read */
    register_t r = v->io.req.data;

    /* We are done with the IO */
    v->io.req.state = STATE_IOREQ_NONE;

    if ( dabt.write )
        return IO_HANDLED;

    /*
     * The Arm Arm requires the value to be zero-extended to the size
     * of the register. The Device Model is not meant to touch the bits
     * outside of the access size, but let's not trust that.
     */
    r &= access_mask;
    r = sign_extend(dabt, r);

    set_user_reg(regs, dabt.reg, r);

    return IO_HANDLED;
}

enum io_state try_fwd_ioserv(struct cpu_user_regs *regs,
                             struct vcpu *v, mmio_info_t *info)
{
    struct vcpu_io *vio = &v->io;
    const struct instr_details instr = info->dabt_instr;
    struct hsr_dabt dabt = info->dabt;
    const uint8_t access_size = (1U << dabt.size) * 8;
    const uint64_t access_mask = GENMASK_ULL(access_size - 1, 0);
    ioreq_t p = {
        .type = IOREQ_TYPE_COPY,
        .addr = info->gpa,
        .count = 1,
        .dir = !info->dabt.write,
        /*
         * On x86, df is used by 'rep' instruction to tell the direction
         * to iterate (forward or backward).
         * On Arm, all the accesses to MMIO region will do a single
         * memory access. So for now, we can safely always set to 0.
         */
        .df = 0,
        .state = STATE_IOREQ_READY,
    };
    struct ioreq_server *s = NULL;
    enum io_state rc;

    if ( vio->req.state != STATE_IOREQ_NONE )
    {
        gdprintk(XENLOG_ERR, "wrong state %u\n", vio->req.state);
        return IO_ABORT;
    }

    if ( instr.state == INSTR_CACHE )
        p.size = dcache_line_bytes;
    else
        p.size = 1U << info->dabt.size;

    s = ioreq_server_select(v->domain, &p);
    if ( !s )
        return IO_UNHANDLED;

    /*
     * When the data abort is caused due to cache maintenance and the address
     * belongs to an emulated region, Xen should ignore this instruction.
     */
    if ( instr.state == INSTR_CACHE )
        return IO_HANDLED;

    ASSERT(dabt.valid);

    /*
     * During a write access, the Device Model only need to know the content
     * of the bits associated with the access size (e.g. for 8-bit, the lower 8-bits).
     * During a read access, the Device Model don't need to know any value.
     * So restrict the value it can access.
     */
    p.data = p.dir ? 0 : get_user_reg(regs, info->dabt.reg) & access_mask;
    vio->req = p;
    vio->suspended = false;
    vio->info.dabt_instr = instr;

    rc = ioreq_send(s, &p, 0);
    if ( rc != IO_RETRY || vio->suspended )
        vio->req.state = STATE_IOREQ_NONE;
    else if ( !ioreq_needs_completion(&vio->req) )
        rc = IO_HANDLED;
    else
        vio->completion = VIO_mmio_completion;

    return rc;
}

bool arch_ioreq_complete_mmio(void)
{
    struct vcpu *v = current;
    struct instr_details dabt_instr = v->io.info.dabt_instr;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    const union hsr hsr = { .bits = regs->hsr };

    if ( v->io.req.state != STATE_IORESP_READY )
    {
        ASSERT_UNREACHABLE();
        return false;
    }

    if ( handle_ioserv(regs, v) == IO_HANDLED )
    {
        finalize_instr_emulation(&dabt_instr);
        advance_pc(regs, hsr);
        return true;
    }

    return false;
}

/*
 * The "legacy" mechanism of mapping magic pages for the IOREQ servers
 * is x86 specific, so the following hooks don't need to be implemented on Arm:
 * - arch_ioreq_server_map_pages
 * - arch_ioreq_server_unmap_pages
 * - arch_ioreq_server_enable
 * - arch_ioreq_server_disable
 */
int arch_ioreq_server_map_pages(struct ioreq_server *s)
{
    return -EOPNOTSUPP;
}

void arch_ioreq_server_unmap_pages(struct ioreq_server *s)
{
}

void arch_ioreq_server_enable(struct ioreq_server *s)
{
}

void arch_ioreq_server_disable(struct ioreq_server *s)
{
}

void arch_ioreq_server_destroy(struct ioreq_server *s)
{
}

int arch_ioreq_server_map_mem_type(struct domain *d,
                                   struct ioreq_server *s,
                                   uint32_t flags)
{
    return -EOPNOTSUPP;
}

void arch_ioreq_server_map_mem_type_completed(struct domain *d,
                                              struct ioreq_server *s,
                                              uint32_t flags)
{
}

bool arch_ioreq_server_destroy_all(struct domain *d)
{
    return true;
}

bool arch_ioreq_server_get_type_addr(const struct domain *d,
                                     const ioreq_t *p,
                                     uint8_t *type,
                                     uint64_t *addr)
{
    if ( p->type != IOREQ_TYPE_COPY && p->type != IOREQ_TYPE_PIO )
        return false;

    *type = (p->type == IOREQ_TYPE_PIO) ?
             XEN_DMOP_IO_RANGE_PORT : XEN_DMOP_IO_RANGE_MEMORY;
    *addr = p->addr;

    return true;
}

void arch_ioreq_domain_init(struct domain *d)
{
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
