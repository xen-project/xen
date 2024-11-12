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
#include <asm/hvm/support.h>
#include <xen/numa.h>
#include <xen/paging.h>

#define VGA_MEM_BASE 0xa0000
#define VGA_MEM_SIZE 0x20000

/* force some bits to zero */
static const uint8_t sr_mask[8] = {
    (uint8_t)~0xfc,
    (uint8_t)~0xc2,
    (uint8_t)~0xf0,
    (uint8_t)~0xc0,
    (uint8_t)~0xf1,
    (uint8_t)~0xff,
    (uint8_t)~0xff,
    (uint8_t)~0x00,
};

static int stdvga_outb(uint64_t addr, uint8_t val)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;
    int rc = 1;

    switch ( addr )
    {
    case 0x3c4:                 /* sequencer address register */
        s->sr_index = val;
        break;

    case 0x3c5:                 /* sequencer data register */
        rc = (s->sr_index < sizeof(s->sr));
        if ( rc )
            s->sr[s->sr_index] = val & sr_mask[s->sr_index] ;
        break;

    case 0x3ce:                 /* graphics address register */
        s->gr_index = val;
        break;

    default:
        rc = 0;
        break;
    }

    return rc;
}

static void stdvga_out(uint32_t port, uint32_t bytes, uint32_t val)
{
    switch ( bytes )
    {
    case 1:
        stdvga_outb(port, val);
        break;

    case 2:
        stdvga_outb(port + 0, val >> 0);
        stdvga_outb(port + 1, val >> 8);
        break;

    default:
        break;
    }
}

static int cf_check stdvga_intercept_pio(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;

    if ( dir == IOREQ_WRITE )
    {
        spin_lock(&s->lock);
        stdvga_out(port, bytes, *val);
        spin_unlock(&s->lock);
    }

    return X86EMUL_UNHANDLEABLE; /* propagate to external ioemu */
}

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
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;

    /*
     * The range check must be done without taking the lock, to avoid
     * deadlock when hvm_mmio_internal() is called from
     * hvm_copy_to/from_guest_phys() in hvm_process_io_intercept().
     */
    if ( (ioreq_mmio_first_byte(p) < VGA_MEM_BASE) ||
         (ioreq_mmio_last_byte(p) >= (VGA_MEM_BASE + VGA_MEM_SIZE)) )
        return 0;

    spin_lock(&s->lock);

    if ( p->dir != IOREQ_WRITE || p->data_is_ptr || p->count != 1 )
    {
        /*
         * Only accept single direct writes, as that's the only thing we can
         * accelerate using buffered ioreq handling.
         */
        goto reject;
    }

    /* s->lock intentionally held */
    return 1;

 reject:
    spin_unlock(&s->lock);
    return 0;
}

static void cf_check stdvga_mem_complete(const struct hvm_io_handler *handler)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;

    spin_unlock(&s->lock);
}

static const struct hvm_io_ops stdvga_mem_ops = {
    .accept = stdvga_mem_accept,
    .read = stdvga_mem_read,
    .write = stdvga_mem_write,
    .complete = stdvga_mem_complete
};

void stdvga_init(struct domain *d)
{
    struct hvm_hw_stdvga *s = &d->arch.hvm.stdvga;
    struct page_info *pg;
    unsigned int i;

    if ( !has_vvga(d) )
        return;

    memset(s, 0, sizeof(*s));
    spin_lock_init(&s->lock);
    
    for ( i = 0; i != ARRAY_SIZE(s->vram_page); i++ )
    {
        pg = alloc_domheap_page(d, MEMF_no_owner);
        if ( pg == NULL )
            break;
        s->vram_page[i] = pg;
        clear_domain_page(page_to_mfn(pg));
    }

    if ( i == ARRAY_SIZE(s->vram_page) )
    {
        struct hvm_io_handler *handler;

        /* Sequencer registers. */
        register_portio_handler(d, 0x3c4, 2, stdvga_intercept_pio);
        /* Graphics registers. */
        register_portio_handler(d, 0x3ce, 2, stdvga_intercept_pio);

        /* VGA memory */
        handler = hvm_next_io_handler(d);

        if ( handler == NULL )
            return;

        handler->type = IOREQ_TYPE_COPY;
        handler->ops = &stdvga_mem_ops;
    }
}

void stdvga_deinit(struct domain *d)
{
    struct hvm_hw_stdvga *s = &d->arch.hvm.stdvga;
    int i;

    if ( !has_vvga(d) )
        return;

    for ( i = 0; i != ARRAY_SIZE(s->vram_page); i++ )
    {
        if ( s->vram_page[i] == NULL )
            continue;
        free_domheap_page(s->vram_page[i]);
        s->vram_page[i] = NULL;
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
