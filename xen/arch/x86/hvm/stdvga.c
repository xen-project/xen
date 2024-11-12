/*
 *  Copyright (c) 2003-2007, Virtual Iron Software, Inc.
 *
 *  Portions have been modified by Virtual Iron Software, Inc.
 *  (c) 2007. This file and the modifications can be redistributed and/or
 *  modified under the terms and conditions of the GNU General Public
 *  License, version 2.1 and not any later version of the GPL, as published
 *  by the Free Software Foundation. 
 *
 *  This improves the performance of Standard VGA,
 *  the mode used during Windows boot and by the Linux
 *  splash screen.
 *
 *  It does so by buffering all the stdvga programmed output ops
 *  and memory mapped ops (both reads and writes) that are sent to QEMU.
 *
 *  We maintain locally essential VGA state so we can respond
 *  immediately to input and read ops without waiting for
 *  QEMU.  We snoop output and write ops to keep our state
 *  up-to-date.
 *
 *  PIO input ops are satisfied from cached state without
 *  bothering QEMU.
 *
 *  PIO output and mmio ops are passed through to QEMU, including
 *  mmio read ops.  This is necessary because mmio reads
 *  can have side effects.
 */

#include <xen/ioreq.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/domain_page.h>
#include <xen/numa.h>
#include <xen/paging.h>

#define VGA_MEM_BASE 0xa0000
#define VGA_MEM_SIZE 0x20000

static int cf_check stdvga_mem_read(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
    uint64_t *p_data)
{
    ASSERT_UNREACHABLE();
    *p_data = ~0;
    return X86EMUL_UNHANDLEABLE;
}

static int cf_check stdvga_mem_write(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
    uint64_t data)
{
    ioreq_t p = {
        .type = IOREQ_TYPE_COPY,
        .addr = addr,
        .size = size,
        .count = 1,
        .dir = IOREQ_WRITE,
        .data = data,
    };
    struct ioreq_server *srv = ioreq_server_select(current->domain, &p);

    if ( !srv )
        return X86EMUL_UNHANDLEABLE;

    return ioreq_send(srv, &p, 1);
}

static bool cf_check stdvga_mem_accept(
    const struct hvm_io_handler *handler, const ioreq_t *p)
{
    /*
     * Only accept single direct writes, as that's the only thing we can
     * accelerate using buffered ioreq handling.
     */
    if ( p->dir != IOREQ_WRITE || p->data_is_ptr || p->count != 1 ||
         (ioreq_mmio_first_byte(p) < VGA_MEM_BASE) ||
         (ioreq_mmio_last_byte(p) >= (VGA_MEM_BASE + VGA_MEM_SIZE)) )
        return false;

    return true;
}

static const struct hvm_io_ops stdvga_mem_ops = {
    .accept = stdvga_mem_accept,
    .read = stdvga_mem_read,
    .write = stdvga_mem_write,
};

void stdvga_init(struct domain *d)
{
    struct hvm_io_handler *handler;

    if ( !has_vvga(d) )
        return;

    /* VGA memory */
    handler = hvm_next_io_handler(d);
    if ( handler )
    {
        handler->type = IOREQ_TYPE_COPY;
        handler->ops = &stdvga_mem_ops;
    }
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
