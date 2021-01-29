/*
 * arm/ioreq.c: hardware virtual machine I/O emulation
 *
 * Copyright (c) 2019 Arm ltd.
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

#include <xen/domain.h>
#include <xen/ioreq.h>

#include <asm/traps.h>

#include <public/hvm/ioreq.h>

enum io_state handle_ioserv(struct cpu_user_regs *regs, struct vcpu *v)
{
    const union hsr hsr = { .bits = regs->hsr };
    const struct hsr_dabt dabt = hsr.dabt;
    /* Code is similar to handle_read */
    register_t r = v->io.req.data;

    /* We are done with the IO */
    v->io.req.state = STATE_IOREQ_NONE;

    if ( dabt.write )
        return IO_HANDLED;

    r = sign_extend(dabt, r);

    set_user_reg(regs, dabt.reg, r);

    return IO_HANDLED;
}

enum io_state try_fwd_ioserv(struct cpu_user_regs *regs,
                             struct vcpu *v, mmio_info_t *info)
{
    struct vcpu_io *vio = &v->io;
    ioreq_t p = {
        .type = IOREQ_TYPE_COPY,
        .addr = info->gpa,
        .size = 1 << info->dabt.size,
        .count = 1,
        .dir = !info->dabt.write,
        /*
         * On x86, df is used by 'rep' instruction to tell the direction
         * to iterate (forward or backward).
         * On Arm, all the accesses to MMIO region will do a single
         * memory access. So for now, we can safely always set to 0.
         */
        .df = 0,
        .data = get_user_reg(regs, info->dabt.reg),
        .state = STATE_IOREQ_READY,
    };
    struct ioreq_server *s = NULL;
    enum io_state rc;

    if ( vio->req.state != STATE_IOREQ_NONE )
    {
        gdprintk(XENLOG_ERR, "wrong state %u\n", vio->req.state);
        return IO_ABORT;
    }

    s = ioreq_server_select(v->domain, &p);
    if ( !s )
        return IO_UNHANDLED;

    if ( !info->dabt.valid )
        return IO_ABORT;

    vio->req = p;

    rc = ioreq_send(s, &p, 0);
    if ( rc != IO_RETRY || v->domain->is_shutting_down )
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
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    const union hsr hsr = { .bits = regs->hsr };

    if ( v->io.req.state != STATE_IORESP_READY )
    {
        ASSERT_UNREACHABLE();
        return false;
    }

    if ( handle_ioserv(regs, v) == IO_HANDLED )
    {
        advance_pc(regs, hsr);
        return true;
    }

    return false;
}

bool arch_vcpu_ioreq_completion(enum vio_completion completion)
{
    ASSERT_UNREACHABLE();
    return true;
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
