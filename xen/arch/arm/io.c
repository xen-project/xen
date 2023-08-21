/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/io.c
 *
 * ARM I/O handlers
 *
 * Copyright (c) 2011 Citrix Systems.
 */

#include <xen/ioreq.h>
#include <xen/lib.h>
#include <xen/spinlock.h>
#include <xen/sched.h>
#include <xen/sort.h>
#include <asm/cpuerrata.h>
#include <asm/current.h>
#include <asm/ioreq.h>
#include <asm/mmio.h>
#include <asm/traps.h>

#include "decode.h"

static enum io_state handle_read(const struct mmio_handler *handler,
                                 struct vcpu *v,
                                 mmio_info_t *info)
{
    const struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    /*
     * Initialize to zero to avoid leaking data if there is an
     * implementation error in the emulation (such as not correctly
     * setting r).
     */
    register_t r = 0;

    if ( !handler->ops->read(v, info, &r, handler->priv) )
        return IO_ABORT;

    r = sign_extend(dabt, r);

    set_user_reg(regs, dabt.reg, r);

    return IO_HANDLED;
}

static enum io_state handle_write(const struct mmio_handler *handler,
                                  struct vcpu *v,
                                  mmio_info_t *info)
{
    const struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    int ret;

    ret = handler->ops->write(v, info, get_user_reg(regs, dabt.reg),
                              handler->priv);
    return ret ? IO_HANDLED : IO_ABORT;
}

/* This function assumes that mmio regions are not overlapped */
static int cmp_mmio_handler(const void *key, const void *elem)
{
    const struct mmio_handler *handler0 = key;
    const struct mmio_handler *handler1 = elem;

    if ( handler0->addr < handler1->addr )
        return -1;

    if ( handler0->addr >= (handler1->addr + handler1->size) )
        return 1;

    return 0;
}

static void swap_mmio_handler(void *_a, void *_b, size_t size)
{
    struct mmio_handler *a = _a, *b = _b;

    SWAP(*a, *b);
}

static const struct mmio_handler *find_mmio_handler(struct domain *d,
                                                    paddr_t gpa)
{
    struct vmmio *vmmio = &d->arch.vmmio;
    struct mmio_handler key = {.addr = gpa};
    const struct mmio_handler *handler;

    read_lock(&vmmio->lock);
    handler = bsearch(&key, vmmio->handlers, vmmio->num_entries,
                      sizeof(*handler), cmp_mmio_handler);
    read_unlock(&vmmio->lock);

    return handler;
}

void try_decode_instruction(const struct cpu_user_regs *regs,
                            mmio_info_t *info)
{
    int rc;

    if ( info->dabt.valid )
    {
        info->dabt_instr.state = INSTR_VALID;

        /*
         * Erratum 766422: Thumb store translation fault to Hypervisor may
         * not have correct HSR Rt value.
         */
        if ( check_workaround_766422() && (regs->cpsr & PSR_THUMB) &&
             info->dabt.write )
        {
            rc = decode_instruction(regs, info);
            if ( rc )
            {
                gprintk(XENLOG_DEBUG, "Unable to decode instruction\n");
                info->dabt_instr.state = INSTR_ERROR;
            }
        }
        return;
    }

    /*
     * At this point, we know that the stage1 translation table is either in an
     * emulated MMIO region or its address is invalid . This is not expected by
     * Xen and thus it forwards the abort to the guest.
     */
    if ( info->dabt.s1ptw )
    {
        info->dabt_instr.state = INSTR_ERROR;
        return;
    }

    /*
     * When the data abort is caused due to cache maintenance, Xen should check
     * if the address belongs to an emulated MMIO region or not. The behavior
     * will differ accordingly.
     */
    if ( info->dabt.cache )
    {
        info->dabt_instr.state = INSTR_CACHE;
        return;
    }

    /*
     * Armv8 processor does not provide a valid syndrome for decoding some
     * instructions. So in order to process these instructions, Xen must
     * decode them.
     */
    rc = decode_instruction(regs, info);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Unable to decode instruction\n");
        info->dabt_instr.state = INSTR_ERROR;
    }
}

enum io_state try_handle_mmio(struct cpu_user_regs *regs,
                              mmio_info_t *info)
{
    struct vcpu *v = current;
    const struct mmio_handler *handler = NULL;
    int rc;

    ASSERT(info->dabt.ec == HSR_EC_DATA_ABORT_LOWER_EL);

    if ( !(info->dabt.valid || (info->dabt_instr.state == INSTR_CACHE)) )
    {
        ASSERT_UNREACHABLE();
        return IO_ABORT;
    }

    handler = find_mmio_handler(v->domain, info->gpa);
    if ( !handler )
    {
        rc = try_fwd_ioserv(regs, v, info);
        if ( rc == IO_HANDLED )
            return handle_ioserv(regs, v);

        return rc;
    }

    /*
     * When the data abort is caused due to cache maintenance and the address
     * belongs to an emulated region, Xen should ignore this instruction.
     */
    if ( info->dabt_instr.state == INSTR_CACHE )
        return IO_HANDLED;

    /*
     * At this point, we know that the instruction is either valid or has been
     * decoded successfully. Thus, Xen should be allowed to execute the
     * instruction on the emulated MMIO region.
     */
    if ( info->dabt.write )
        return handle_write(handler, v, info);
    else
        return handle_read(handler, v, info);
}

void register_mmio_handler(struct domain *d,
                           const struct mmio_handler_ops *ops,
                           paddr_t addr, paddr_t size, void *priv)
{
    struct vmmio *vmmio = &d->arch.vmmio;
    struct mmio_handler *handler;

    BUG_ON(vmmio->num_entries >= vmmio->max_num_entries);

    write_lock(&vmmio->lock);

    handler = &vmmio->handlers[vmmio->num_entries];

    handler->ops = ops;
    handler->addr = addr;
    handler->size = size;
    handler->priv = priv;

    vmmio->num_entries++;

    /* Sort mmio handlers in ascending order based on base address */
    sort(vmmio->handlers, vmmio->num_entries, sizeof(struct mmio_handler),
         cmp_mmio_handler, swap_mmio_handler);

    write_unlock(&vmmio->lock);
}

int domain_io_init(struct domain *d, unsigned int max_count)
{
    rwlock_init(&d->arch.vmmio.lock);
    d->arch.vmmio.num_entries = 0;
    d->arch.vmmio.max_num_entries = max_count;
    d->arch.vmmio.handlers = xzalloc_array(struct mmio_handler, max_count);
    if ( !d->arch.vmmio.handlers )
        return -ENOMEM;

    return 0;
}

void domain_io_free(struct domain *d)
{
    xfree(d->arch.vmmio.handlers);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
