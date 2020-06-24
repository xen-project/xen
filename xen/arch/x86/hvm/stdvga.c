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

#include <xen/types.h>
#include <xen/sched.h>
#include <xen/domain_page.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/support.h>
#include <xen/numa.h>
#include <xen/paging.h>

#define VGA_MEM_BASE 0xa0000
#define VGA_MEM_SIZE 0x20000

#define PAT(x) (x)
static const uint32_t mask16[16] = {
    PAT(0x00000000),
    PAT(0x000000ff),
    PAT(0x0000ff00),
    PAT(0x0000ffff),
    PAT(0x00ff0000),
    PAT(0x00ff00ff),
    PAT(0x00ffff00),
    PAT(0x00ffffff),
    PAT(0xff000000),
    PAT(0xff0000ff),
    PAT(0xff00ff00),
    PAT(0xff00ffff),
    PAT(0xffff0000),
    PAT(0xffff00ff),
    PAT(0xffffff00),
    PAT(0xffffffff),
};

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

static const uint8_t gr_mask[9] = {
    (uint8_t)~0xf0, /* 0x00 */
    (uint8_t)~0xf0, /* 0x01 */
    (uint8_t)~0xf0, /* 0x02 */
    (uint8_t)~0xe0, /* 0x03 */
    (uint8_t)~0xfc, /* 0x04 */
    (uint8_t)~0x84, /* 0x05 */
    (uint8_t)~0xf0, /* 0x06 */
    (uint8_t)~0xf0, /* 0x07 */
    (uint8_t)~0x00, /* 0x08 */
};

static uint8_t *vram_getb(struct hvm_hw_stdvga *s, unsigned int a)
{
    struct page_info *pg = s->vram_page[(a >> 12) & 0x3f];
    uint8_t *p = __map_domain_page(pg);
    return &p[a & 0xfff];
}

static uint32_t *vram_getl(struct hvm_hw_stdvga *s, unsigned int a)
{
    struct page_info *pg = s->vram_page[(a >> 10) & 0x3f];
    uint32_t *p = __map_domain_page(pg);
    return &p[a & 0x3ff];
}

static void vram_put(struct hvm_hw_stdvga *s, void *p)
{
    unmap_domain_page(p);
}

static void stdvga_try_cache_enable(struct hvm_hw_stdvga *s)
{
    /*
     * Caching mode can only be enabled if the the cache has
     * never been used before. As soon as it is disabled, it will
     * become out-of-sync with the VGA device model and since no
     * mechanism exists to acquire current VRAM state from the
     * device model, re-enabling it would lead to stale data being
     * seen by the guest.
     */
    if ( s->cache != STDVGA_CACHE_UNINITIALIZED )
        return;

    gdprintk(XENLOG_INFO, "entering caching mode\n");
    s->cache = STDVGA_CACHE_ENABLED;
}

static void stdvga_cache_disable(struct hvm_hw_stdvga *s)
{
    if ( s->cache != STDVGA_CACHE_ENABLED )
        return;

    gdprintk(XENLOG_INFO, "leaving caching mode\n");
    s->cache = STDVGA_CACHE_DISABLED;
}

static bool_t stdvga_cache_is_enabled(const struct hvm_hw_stdvga *s)
{
    return s->cache == STDVGA_CACHE_ENABLED;
}

static int stdvga_outb(uint64_t addr, uint8_t val)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;
    int rc = 1, prev_stdvga = s->stdvga;

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

    case 0x3cf:                 /* graphics data register */
        rc = (s->gr_index < sizeof(s->gr));
        if ( rc )
            s->gr[s->gr_index] = val & gr_mask[s->gr_index];
        break;

    default:
        rc = 0;
        break;
    }

    /* When in standard vga mode, emulate here all writes to the vram buffer
     * so we can immediately satisfy reads without waiting for qemu. */
    s->stdvga = (s->sr[7] == 0x00);

    if ( !prev_stdvga && s->stdvga )
    {
        gdprintk(XENLOG_INFO, "entering stdvga mode\n");
        stdvga_try_cache_enable(s);
    }
    else if ( prev_stdvga && !s->stdvga )
    {
        gdprintk(XENLOG_INFO, "leaving stdvga mode\n");
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

static int stdvga_intercept_pio(
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

static unsigned int stdvga_mem_offset(
    struct hvm_hw_stdvga *s, unsigned int mmio_addr)
{
    unsigned int memory_map_mode = (s->gr[6] >> 2) & 3;
    unsigned int offset = mmio_addr & 0x1ffff;

    switch ( memory_map_mode )
    {
    case 0:
        break;
    case 1:
        if ( offset >= 0x10000 )
            goto fail;
        offset += 0; /* assume bank_offset == 0; */
        break;
    case 2:
        offset -= 0x10000;
        if ( offset >= 0x8000 )
            goto fail;
        break;
    default:
    case 3:
        offset -= 0x18000;
        if ( offset >= 0x8000 )
            goto fail;
        break;
    }

    return offset;

 fail:
    return ~0u;
}

#define GET_PLANE(data, p) (((data) >> ((p) * 8)) & 0xff)

static uint8_t stdvga_mem_readb(uint64_t addr)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;
    int plane;
    uint32_t ret, *vram_l;
    uint8_t *vram_b;

    addr = stdvga_mem_offset(s, addr);
    if ( addr == ~0u )
        return 0xff;

    if ( s->sr[4] & 0x08 )
    {
        /* chain 4 mode : simplest access */
        vram_b = vram_getb(s, addr);
        ret = *vram_b;
        vram_put(s, vram_b);
    }
    else if ( s->gr[5] & 0x10 )
    {
        /* odd/even mode (aka text mode mapping) */
        plane = (s->gr[4] & 2) | (addr & 1);
        vram_b = vram_getb(s, ((addr & ~1) << 1) | plane);
        ret = *vram_b;
        vram_put(s, vram_b);
    }
    else
    {
        /* standard VGA latched access */
        vram_l = vram_getl(s, addr);
        s->latch = *vram_l;
        vram_put(s, vram_l);

        if ( !(s->gr[5] & 0x08) )
        {
            /* read mode 0 */
            plane = s->gr[4];
            ret = GET_PLANE(s->latch, plane);
        }
        else
        {
            /* read mode 1 */
            ret = (s->latch ^ mask16[s->gr[2]]) & mask16[s->gr[7]];
            ret |= ret >> 16;
            ret |= ret >> 8;
            ret = (~ret) & 0xff;
        }
    }

    return ret;
}

static int stdvga_mem_read(const struct hvm_io_handler *handler,
                           uint64_t addr, uint32_t size, uint64_t *p_data)
{
    uint64_t data = ~0ul;

    switch ( size )
    {
    case 1:
        data = stdvga_mem_readb(addr);
        break;

    case 2:
        data = stdvga_mem_readb(addr);
        data |= stdvga_mem_readb(addr + 1) << 8;
        break;

    case 4:
        data = stdvga_mem_readb(addr);
        data |= stdvga_mem_readb(addr + 1) << 8;
        data |= stdvga_mem_readb(addr + 2) << 16;
        data |= (uint32_t)stdvga_mem_readb(addr + 3) << 24;
        break;

    case 8:
        data =  (uint64_t)(stdvga_mem_readb(addr));
        data |= (uint64_t)(stdvga_mem_readb(addr + 1)) << 8;
        data |= (uint64_t)(stdvga_mem_readb(addr + 2)) << 16;
        data |= (uint64_t)(stdvga_mem_readb(addr + 3)) << 24;
        data |= (uint64_t)(stdvga_mem_readb(addr + 4)) << 32;
        data |= (uint64_t)(stdvga_mem_readb(addr + 5)) << 40;
        data |= (uint64_t)(stdvga_mem_readb(addr + 6)) << 48;
        data |= (uint64_t)(stdvga_mem_readb(addr + 7)) << 56;
        break;

    default:
        gdprintk(XENLOG_WARNING, "invalid io size: %u\n", size);
        break;
    }

    *p_data = data;
    return X86EMUL_OKAY;
}

static void stdvga_mem_writeb(uint64_t addr, uint32_t val)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;
    int plane, write_mode, b, func_select, mask;
    uint32_t write_mask, bit_mask, set_mask, *vram_l;
    uint8_t *vram_b;

    addr = stdvga_mem_offset(s, addr);
    if ( addr == ~0u )
        return;

    if ( s->sr[4] & 0x08 )
    {
        /* chain 4 mode : simplest access */
        plane = addr & 3;
        mask = (1 << plane);
        if ( s->sr[2] & mask )
        {
            vram_b = vram_getb(s, addr);
            *vram_b = val;
            vram_put(s, vram_b);
        }
    }
    else if ( s->gr[5] & 0x10 )
    {
        /* odd/even mode (aka text mode mapping) */
        plane = (s->gr[4] & 2) | (addr & 1);
        mask = (1 << plane);
        if ( s->sr[2] & mask )
        {
            addr = ((addr & ~1) << 1) | plane;
            vram_b = vram_getb(s, addr);
            *vram_b = val;
            vram_put(s, vram_b);
        }
    }
    else
    {
        write_mode = s->gr[5] & 3;
        switch ( write_mode )
        {
        default:
        case 0:
            /* rotate */
            b = s->gr[3] & 7;
            val = ((val >> b) | (val << (8 - b))) & 0xff;
            val |= val << 8;
            val |= val << 16;

            /* apply set/reset mask */
            set_mask = mask16[s->gr[1]];
            val = (val & ~set_mask) | (mask16[s->gr[0]] & set_mask);
            bit_mask = s->gr[8];
            break;
        case 1:
            val = s->latch;
            goto do_write;
        case 2:
            val = mask16[val & 0x0f];
            bit_mask = s->gr[8];
            break;
        case 3:
            /* rotate */
            b = s->gr[3] & 7;
            val = (val >> b) | (val << (8 - b));

            bit_mask = s->gr[8] & val;
            val = mask16[s->gr[0]];
            break;
        }

        /* apply logical operation */
        func_select = s->gr[3] >> 3;
        switch ( func_select )
        {
        case 0:
        default:
            /* nothing to do */
            break;
        case 1:
            /* and */
            val &= s->latch;
            break;
        case 2:
            /* or */
            val |= s->latch;
            break;
        case 3:
            /* xor */
            val ^= s->latch;
            break;
        }

        /* apply bit mask */
        bit_mask |= bit_mask << 8;
        bit_mask |= bit_mask << 16;
        val = (val & bit_mask) | (s->latch & ~bit_mask);

    do_write:
        /* mask data according to sr[2] */
        mask = s->sr[2];
        write_mask = mask16[mask];
        vram_l = vram_getl(s, addr);
        *vram_l = (*vram_l & ~write_mask) | (val & write_mask);
        vram_put(s, vram_l);
    }
}

static int stdvga_mem_write(const struct hvm_io_handler *handler,
                            uint64_t addr, uint32_t size,
                            uint64_t data)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;
    ioreq_t p = {
        .type = IOREQ_TYPE_COPY,
        .addr = addr,
        .size = size,
        .count = 1,
        .dir = IOREQ_WRITE,
        .data = data,
    };
    struct hvm_ioreq_server *srv;

    if ( !stdvga_cache_is_enabled(s) || !s->stdvga )
        goto done;

    /* Intercept mmio write */
    switch ( size )
    {
    case 1:
        stdvga_mem_writeb(addr, (data >>  0) & 0xff);
        break;

    case 2:
        stdvga_mem_writeb(addr+0, (data >>  0) & 0xff);
        stdvga_mem_writeb(addr+1, (data >>  8) & 0xff);
        break;

    case 4:
        stdvga_mem_writeb(addr+0, (data >>  0) & 0xff);
        stdvga_mem_writeb(addr+1, (data >>  8) & 0xff);
        stdvga_mem_writeb(addr+2, (data >> 16) & 0xff);
        stdvga_mem_writeb(addr+3, (data >> 24) & 0xff);
        break;

    case 8:
        stdvga_mem_writeb(addr+0, (data >>  0) & 0xff);
        stdvga_mem_writeb(addr+1, (data >>  8) & 0xff);
        stdvga_mem_writeb(addr+2, (data >> 16) & 0xff);
        stdvga_mem_writeb(addr+3, (data >> 24) & 0xff);
        stdvga_mem_writeb(addr+4, (data >> 32) & 0xff);
        stdvga_mem_writeb(addr+5, (data >> 40) & 0xff);
        stdvga_mem_writeb(addr+6, (data >> 48) & 0xff);
        stdvga_mem_writeb(addr+7, (data >> 56) & 0xff);
        break;

    default:
        gdprintk(XENLOG_WARNING, "invalid io size: %u\n", size);
        break;
    }

 done:
    srv = hvm_select_ioreq_server(current->domain, &p);
    if ( !srv )
        return X86EMUL_UNHANDLEABLE;

    return hvm_send_ioreq(srv, &p, 1);
}

static bool_t stdvga_mem_accept(const struct hvm_io_handler *handler,
                                const ioreq_t *p)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm.stdvga;

    /*
     * The range check must be done without taking the lock, to avoid
     * deadlock when hvm_mmio_internal() is called from
     * hvm_copy_to/from_guest_phys() in hvm_process_io_intercept().
     */
    if ( (hvm_mmio_first_byte(p) < VGA_MEM_BASE) ||
         (hvm_mmio_last_byte(p) >= (VGA_MEM_BASE + VGA_MEM_SIZE)) )
        return 0;

    spin_lock(&s->lock);

    if ( p->dir == IOREQ_WRITE && p->count > 1 )
    {
        /*
         * We cannot return X86EMUL_UNHANDLEABLE on anything other then the
         * first cycle of an I/O. So, since we cannot guarantee to always be
         * able to send buffered writes, we have to reject any multi-cycle
         * I/O and, since we are rejecting an I/O, we must invalidate the
         * cache.
         * Single-cycle write transactions are accepted even if the cache is
         * not active since we can assert, when in stdvga mode, that writes
         * to VRAM have no side effect and thus we can try to buffer them.
         */
        stdvga_cache_disable(s);

        goto reject;
    }
    else if ( p->dir == IOREQ_READ &&
              (!stdvga_cache_is_enabled(s) || !s->stdvga) )
        goto reject;

    /* s->lock intentionally held */
    return 1;

 reject:
    spin_unlock(&s->lock);
    return 0;
}

static void stdvga_mem_complete(const struct hvm_io_handler *handler)
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
