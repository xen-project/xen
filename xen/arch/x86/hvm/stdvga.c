/*
 *  Copyright (c) 2003-2007, Virtual Iron Software, Inc.
 *
 *  Portions have been modified by Virtual Iron Software, Inc.
 *  (c) 2007. This file and the modifications can be redistributed and/or
 *  modified under the terms and conditions of the GNU General Public
 *  License, version 2.1 and not any later version of the GPL, as published
 *  by the Free Software Foundation. 
 *
 *
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
    PIO output and mmio ops are passed through to QEMU, including
 *  mmio read ops.  This is necessary because mmio reads
 *  can have side effects.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/hvm/support.h>

#define vram_b(_s, _a) (((uint8_t*) (_s)->vram_ptr[((_a)>>12)&0x3f])[(_a)&0xfff])
#define vram_w(_s, _a) (((uint16_t*)(_s)->vram_ptr[((_a)>>11)&0x3f])[(_a)&0x7ff])
#define vram_l(_s, _a) (((uint32_t*)(_s)->vram_ptr[((_a)>>10)&0x3f])[(_a)&0x3ff])

#ifdef STDVGA_STATS
#define UPDATE_STATS(x) x
#else
#define UPDATE_STATS(x)
#endif

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
const uint8_t sr_mask[8] = {
    (uint8_t)~0xfc,
    (uint8_t)~0xc2,
    (uint8_t)~0xf0,
    (uint8_t)~0xc0,
    (uint8_t)~0xf1,
    (uint8_t)~0xff,
    (uint8_t)~0xff,
    (uint8_t)~0x00,
};

const uint8_t gr_mask[16] = {
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

static uint64_t stdvga_inb(uint64_t addr)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm_domain.stdvga;
    uint8_t val = 0;
    switch (addr) {
    case 0x3c4:                 /* sequencer address register */
        val = s->sr_index;
        break;

    case 0x3c5:                 /* sequencer data register */
        if (s->sr_index < sizeof(s->sr))
            val = s->sr[s->sr_index];
        break;

    case 0x3ce:                 /* graphics address register */
        val = s->gr_index;
        break;

    case 0x3cf:                 /* graphics data register */
        val = s->gr[s->gr_index];
        break;

    default:
        gdprintk(XENLOG_WARNING, "unexpected io addr 0x%04x\n", (int)addr);
    }
    return val;
}

static uint64_t stdvga_in(ioreq_t *p)
{
    /* Satisfy reads from sequence and graphics registers using local values */
    uint64_t data = 0;
    switch (p->size) {
    case 1:
        data = stdvga_inb(p->addr);
        break;

    case 2:
        data = stdvga_inb(p->addr);
        data |= stdvga_inb(p->addr + 1) << 8;
        break;

    case 4:
        data = stdvga_inb(p->addr);
        data |= stdvga_inb(p->addr + 1) << 8;
        data |= stdvga_inb(p->addr + 2) << 16;
        data |= stdvga_inb(p->addr + 3) << 24;
        break;

    case 8:
        data = stdvga_inb(p->addr);
        data |= stdvga_inb(p->addr + 1) << 8;
        data |= stdvga_inb(p->addr + 2) << 16;
        data |= stdvga_inb(p->addr + 3) << 24;
        data |= stdvga_inb(p->addr + 4) << 32;
        data |= stdvga_inb(p->addr + 5) << 40;
        data |= stdvga_inb(p->addr + 6) << 48;
        data |= stdvga_inb(p->addr + 7) << 56;
        break;

    default:
        gdprintk(XENLOG_WARNING, "invalid io size:%d\n", (int)p->size);
    }
    return data;
}

static void stdvga_outb(uint64_t addr, uint8_t val)
{
    /* Bookkeep (via snooping) the sequencer and graphics registers */

    struct hvm_hw_stdvga *s = &current->domain->arch.hvm_domain.stdvga;
    int prev_stdvga = s->stdvga;

    switch (addr) {
    case 0x3c4:                 /* sequencer address register */
        s->sr_index = val;
        break;

    case 0x3c5:                 /* sequencer data register */
        switch (s->sr_index) {
        case 0x00 ... 0x05:
        case 0x07:
            s->sr[s->sr_index] = val & sr_mask[s->sr_index];
            break;
        case 0x06:
            s->sr[s->sr_index] = ((val & 0x17) == 0x12) ? 0x12 : 0x0f;
            break;
        default:
            if (s->sr_index < sizeof(s->sr))
                s->sr[s->sr_index] = val;
            break;
        }
        break;

    case 0x3ce:                 /* graphics address register */
        s->gr_index = val;
        break;

    case 0x3cf:                 /* graphics data register */
        if (s->gr_index < sizeof(gr_mask)) {
            s->gr[s->gr_index] = val & gr_mask[s->gr_index];
        }
        else if (s->gr_index == 0xff && s->vram_ptr != NULL) {
            uint32_t addr;
            for (addr = 0xa0000; addr < 0xa4000; addr += 2)
                vram_w(s, addr) = (val << 8) | s->gr[0xfe];
        }
        else
            s->gr[s->gr_index] = val;
        break;
    }

    /* When in standard vga mode, emulate here all writes to the vram buffer
     * so we can immediately satisfy reads without waiting for qemu. */
    s->stdvga =
        s->sr[0x07] == 0 &&          /* standard vga mode */
        s->gr[6] == 0x05;            /* misc graphics register w/ MemoryMapSelect=1  0xa0000-0xaffff (64K region) and AlphaDis=1 */

    if (!prev_stdvga && s->stdvga) {
        s->cache = 1;       /* (re)start caching video buffer */
        gdprintk(XENLOG_INFO, "entering stdvga and caching modes\n");
    }
    else
    if (prev_stdvga && !s->stdvga)
        gdprintk(XENLOG_INFO, "leaving  stdvga\n");
}

static void stdvga_outv(uint64_t addr, uint64_t data, uint32_t size)
{
    switch (size) {
    case 1:
        stdvga_outb(addr, data);
        break;

    case 2:
        stdvga_outb(addr+0, data >>  0);
        stdvga_outb(addr+1, data >>  8);
        break;

    case 4:
        stdvga_outb(addr+0, data >>  0);
        stdvga_outb(addr+1, data >>  8);
        stdvga_outb(addr+2, data >> 16);
        stdvga_outb(addr+3, data >> 24);
        break;

    case 8:
        stdvga_outb(addr+0, data >>  0);
        stdvga_outb(addr+1, data >>  8);
        stdvga_outb(addr+2, data >> 16);
        stdvga_outb(addr+3, data >> 24);
        stdvga_outb(addr+4, data >> 32);
        stdvga_outb(addr+5, data >> 40);
        stdvga_outb(addr+6, data >> 48);
        stdvga_outb(addr+7, data >> 56);
        break;

    default:
        gdprintk(XENLOG_WARNING, "invalid io size:%d\n", size);
    }
}

static void stdvga_out(ioreq_t *p)
{
    if (p->data_is_ptr) {
        int i, sign = p->df ? -1 : 1;
        uint64_t addr = p->addr, data = p->data, tmp;
        for (i = 0; i < p->count; i++) {
            hvm_copy_from_guest_phys(&tmp, data, p->size);
            stdvga_outv(addr, tmp, p->size);
            data += sign * p->size;
            addr += sign * p->size;
        }
    }
    else
        stdvga_outv(p->addr, p->data, p->size);
}

int stdvga_intercept_pio(ioreq_t *p)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm_domain.stdvga;
    int buf = 0;

    if (p->size > 8) {
        gdprintk(XENLOG_WARNING, "stdvga bad access size %d\n", (int)p->size);
        return 0;
    }

    spin_lock(&s->lock);
    if ( p->dir == IOREQ_READ ) {
        if (p->size != 1)
            gdprintk(XENLOG_WARNING, "unexpected io size:%d\n", (int)p->size);
        if (!(p->addr == 0x3c5 && s->sr_index >= sizeof(sr_mask)) &&
            !(p->addr == 0x3cf && s->gr_index >= sizeof(gr_mask)))
        {
            p->data = stdvga_in(p);
            buf = 1;
        }
    }
    else {
        stdvga_out(p);
        buf = 1;
    }

    if (buf && hvm_buffered_io_send(p)) {
        UPDATE_STATS(s->stats.nr_pio_buffered_wr++);
        spin_unlock(&s->lock);
        return 1;
    }
    else {
        UPDATE_STATS(s->stats.nr_pio_unbuffered_wr++);
        spin_unlock(&s->lock);
        return 0;
    }
}

#define GET_PLANE(data, p) (((data) >> ((p) * 8)) & 0xff)

static uint8_t stdvga_mem_readb(uint64_t addr)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm_domain.stdvga;
    int plane;
    uint32_t ret;

    addr &= 0x1ffff;
    if (addr >= 0x10000)
        return 0xff;

    if (s->sr[4] & 0x08) {
        /* chain 4 mode : simplest access */
        ret = vram_b(s, addr);
    } else if (s->gr[5] & 0x10) {
        /* odd/even mode (aka text mode mapping) */
        plane = (s->gr[4] & 2) | (addr & 1);
        ret = vram_b(s, ((addr & ~1) << 1) | plane);
    } else {
        /* standard VGA latched access */
        s->latch = vram_l(s, addr);

        if (!(s->gr[5] & 0x08)) {
            /* read mode 0 */
            plane = s->gr[4];
            ret = GET_PLANE(s->latch, plane);
        } else {
            /* read mode 1 */
            ret = (s->latch ^ mask16[s->gr[2]]) & mask16[s->gr[7]];
            ret |= ret >> 16;
            ret |= ret >> 8;
            ret = (~ret) & 0xff;
        }
    }
    return ret;
}

static uint32_t stdvga_mem_read(uint32_t addr, uint32_t size)
{
    uint32_t data = 0;

    switch (size) {
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
        data |= stdvga_mem_readb(addr + 3) << 24;
        break;

    default:
        gdprintk(XENLOG_WARNING, "invalid io size:%d\n", size);
    }
    return data;
}

static void stdvga_mem_writeb(uint64_t addr, uint32_t val)
{
    struct hvm_hw_stdvga *s = &current->domain->arch.hvm_domain.stdvga;
    int plane, write_mode, b, func_select, mask;
    uint32_t write_mask, bit_mask, set_mask;

    addr &= 0x1ffff;
    if (addr >= 0x10000)
        return;

    if (s->sr[4] & 0x08) {
        /* chain 4 mode : simplest access */
        plane = addr & 3;
        mask = (1 << plane);
        if (s->sr[2] & mask) {
            vram_b(s, addr) = val;
        }
    } else if (s->gr[5] & 0x10) {
        /* odd/even mode (aka text mode mapping) */
        plane = (s->gr[4] & 2) | (addr & 1);
        mask = (1 << plane);
        if (s->sr[2] & mask) {
            addr = ((addr & ~1) << 1) | plane;
            vram_b(s, addr) = val;
        }
    } else {
        write_mode = s->gr[5] & 3;
        switch(write_mode) {
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
        switch(func_select) {
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
        vram_l(s, addr) =
            (vram_l(s, addr) & ~write_mask) |
            (val & write_mask);
    }
}

static void stdvga_mem_write(uint32_t addr, uint32_t data, uint32_t size)
{
    /* Intercept mmio write */
    switch (size) {
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

    default:
        gdprintk(XENLOG_WARNING, "invalid io size:%d\n", size);
    }
}

static uint32_t read_data;

static int mmio_move(struct hvm_hw_stdvga *s, ioreq_t *p)
{
    int i;
    int sign = p->df ? -1 : 1;

    if (p->data_is_ptr) {
        if (p->dir == IOREQ_READ ) {
            uint32_t addr = p->addr, data = p->data, tmp;
            for (i = 0; i < p->count; i++) {
                tmp = stdvga_mem_read(addr, p->size);
                hvm_copy_to_guest_phys(data, &tmp, p->size);
                data += sign * p->size;
                addr += sign * p->size;
            }
        }
        else {
            uint32_t addr = p->addr, data = p->data, tmp;
            for (i = 0; i < p->count; i++) {
                hvm_copy_from_guest_phys(&tmp, data, p->size);
                stdvga_mem_write(addr, tmp, p->size);
                data += sign * p->size;
                addr += sign * p->size;
            }
        }
    }
    else {
        if (p->dir == IOREQ_READ ) {
            uint32_t addr = p->addr;
            for (i = 0; i < p->count; i++) {
                p->data = stdvga_mem_read(addr, p->size);
                addr += sign * p->size;
            }
        }
        else {
            uint32_t addr = p->addr;
            for (i = 0; i < p->count; i++) {
                stdvga_mem_write(addr, p->data, p->size);
                addr += sign * p->size;
            }
        }
    }

    read_data = p->data;
    return 1;
}

static uint32_t op_and(uint32_t a, uint32_t b) { return a & b; }
static uint32_t op_or (uint32_t a, uint32_t b) { return a | b; }
static uint32_t op_xor(uint32_t a, uint32_t b) { return a ^ b; }
static uint32_t op_add(uint32_t a, uint32_t b) { return a + b; }
static uint32_t op_sub(uint32_t a, uint32_t b) { return a - b; }
static uint32_t (*op_array[])(uint32_t, uint32_t) = {
    [IOREQ_TYPE_AND] = op_and,
    [IOREQ_TYPE_OR ] = op_or,
    [IOREQ_TYPE_XOR] = op_xor,
    [IOREQ_TYPE_ADD] = op_add,
    [IOREQ_TYPE_SUB] = op_sub
};

static int mmio_op(struct hvm_hw_stdvga *s, ioreq_t *p)
{
    uint32_t orig, mod = 0;
    orig = stdvga_mem_read(p->addr, p->size);
    if (p->dir == IOREQ_WRITE) {
        mod = (op_array[p->type])(orig, p->data);
        stdvga_mem_write(p->addr, mod, p->size);
    }
    // p->data = orig; // Can't modify p->data yet.  QEMU still needs to use it.  So return zero below.
    return 0; /* Don't try to buffer these operations */
}

int stdvga_intercept_mmio(ioreq_t *p)
{
    struct domain *d = current->domain;
    struct hvm_hw_stdvga *s = &d->arch.hvm_domain.stdvga;
    int buf = 0;

    if (p->size > 8) {
        gdprintk(XENLOG_WARNING, "invalid mmio size %d\n", (int)p->size);
        return 0;
    }

    spin_lock(&s->lock);

    if (s->stdvga && s->cache) {
        switch (p->type) {
        case IOREQ_TYPE_COPY:
            buf = mmio_move(s, p);
            break;
        case IOREQ_TYPE_AND:
        case IOREQ_TYPE_OR:
        case IOREQ_TYPE_XOR:
        case IOREQ_TYPE_ADD:
        case IOREQ_TYPE_SUB:
            buf = mmio_op(s, p);
            break;
        default:
            gdprintk(XENLOG_ERR, "unsupported mmio request type:%d "
                     "addr:0x%04x data:0x%04x size:%d count:%d state:%d isptr:%d dir:%d df:%d\n",
                     p->type,
                     (int)p->addr, (int)p->data, (int)p->size, (int)p->count, p->state,
                     p->data_is_ptr, p->dir, p->df);
            s->cache = 0;
        }
    }
    if (buf && hvm_buffered_io_send(p)) {
        UPDATE_STATS(p->dir == IOREQ_READ ? s->stats.nr_mmio_buffered_rd++ : s->stats.nr_mmio_buffered_wr++);
        spin_unlock(&s->lock);
        return 1;
    }
    else {
        UPDATE_STATS(p->dir == IOREQ_READ ? s->stats.nr_mmio_unbuffered_rd++ : s->stats.nr_mmio_unbuffered_wr++);
        spin_unlock(&s->lock);
        return 0;
    }
}

void stdvga_init(struct domain *d)
{
    int i;
    struct hvm_hw_stdvga *s = &d->arch.hvm_domain.stdvga;
    memset(s, 0, sizeof(*s));
    spin_lock_init(&s->lock);
    
    for (i = 0; i != ARRAY_SIZE(s->vram_ptr); i++) {
        struct page_info *vram_page;
        vram_page = alloc_domheap_page(NULL);
        if (!vram_page)
            break;
        s->vram_ptr[i] = page_to_virt(vram_page);
        memset(s->vram_ptr[i], 0, PAGE_SIZE);
    }
    if (i == ARRAY_SIZE(s->vram_ptr)) {
        register_portio_handler(d, 0x3c4, 2, stdvga_intercept_pio); /* sequencer registers */
        register_portio_handler(d, 0x3ce, 2, stdvga_intercept_pio); /* graphics registers */
        register_buffered_io_handler(d, 0xa0000, 0x10000, stdvga_intercept_mmio); /* mmio */
    }
}

void stdvga_deinit(struct domain *d)
{
    struct hvm_hw_stdvga *s = &d->arch.hvm_domain.stdvga;
    int i;
    for (i = 0; i != ARRAY_SIZE(s->vram_ptr); i++) {
        struct page_info *vram_page;
        if (s->vram_ptr[i] == NULL)
            continue;
        vram_page = virt_to_page(s->vram_ptr[i]);
        free_domheap_page(vram_page);
        s->vram_ptr[i] = NULL;
    }
}

#ifdef STDVGA_STATS
static void stdvga_stats_dump(unsigned char key)
{
    struct domain *d;

    printk("%s: key '%c' pressed\n", __FUNCTION__, key);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        struct hvm_hw_stdvga *s;
        int i;

        if ( !is_hvm_domain(d) )
            continue;

        s = &d->arch.hvm_domain.stdvga;
        spin_lock(&s->lock);
        printk("\n>>> Domain %d <<<\n", d->domain_id);
        printk("    modes: stdvga:%d caching:%d\n", s->stdvga, s->cache);
        printk("                       %8s %8s\n", "read", "write");
        printk("    nr_mmio_buffered:  %8u %8u\n", s->stats.nr_mmio_buffered_rd, s->stats.nr_mmio_buffered_wr);
        printk("    nr_mmio_unbuffered:%8u %8u\n", s->stats.nr_mmio_unbuffered_rd, s->stats.nr_mmio_unbuffered_wr);
        printk("    nr_pio_buffered:   %8u %8u\n", s->stats.nr_pio_buffered_rd, s->stats.nr_pio_buffered_wr);
        printk("    nr_pio_unbuffered: %8u %8u\n", s->stats.nr_pio_unbuffered_rd, s->stats.nr_pio_unbuffered_wr);

        for (i = 0; i != sizeof(s->sr); i++) {
            if (i % 8 == 0)
                printk("    sr[0x%02x] ", i);
            printk("%02x ", s->sr[i]);
            if (i % 8 == 7)
                printk("\n");
        }
        if (i % 8 != 7)
            printk("\n");

        for (i = 0; i != sizeof(s->gr); i++) {
            if (i % 8 == 0)
                printk("    gr[0x%02x] ", i);
            printk("%02x ", s->gr[i]);
            if (i % 8 == 7)
                printk("\n");
        }
        if (i % 8 != 7)
            printk("\n");

        memset(&s->stats, 0, sizeof(s->stats));

        spin_unlock(&s->lock);
    }

    rcu_read_unlock(&domlist_read_lock);
}

#include <xen/keyhandler.h>

static int __init setup_stdvga_stats_dump(void)
{
    register_keyhandler('<', stdvga_stats_dump, "dump stdvga stats");
    return 0;
}

__initcall(setup_stdvga_stats_dump);

#endif

