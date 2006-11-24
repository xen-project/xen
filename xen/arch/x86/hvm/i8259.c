/*
 * i8259 interrupt controller emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2005 Intel Corperation
 * Copyright (c) 2006 Keir Fraser, XenSource Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/current.h>

static inline void pic_set_irq1(PicState *s, int irq, int level)
{
    int mask = 1 << irq;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    if ( s->elcr & mask )
    {
        /* Level triggered. */
        if ( level )
        {
            s->irr |= mask;
            s->last_irr |= mask;
        }
        else
        {
            s->irr &= ~mask;
            s->last_irr &= ~mask;
        }
    }
    else
    {
        /* Edge triggered. */
        if ( level )
        {
            if ( (s->last_irr & mask) == 0 )
                s->irr |= mask;
            s->last_irr |= mask;
        }
        else
        {
            s->last_irr &= ~mask;
        }
    }
}

/* Return the highest priority found in mask. Return 8 if no irq. */
static inline int get_priority(PicState *s, int mask)
{
    int priority;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    if ( mask == 0 )
        return 8;

    priority = 0;
    while ( (mask & (1 << ((priority + s->priority_add) & 7))) == 0 )
        priority++;

    return priority;
}

/* Return the PIC's highest priority pending interrupt. Return -1 if none. */
static int pic_get_irq(PicState *s)
{
    int mask, cur_priority, priority;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    mask = s->irr & ~s->imr;
    priority = get_priority(s, mask);
    if ( priority == 8 )
        return -1;

    /*
     * Compute current priority. If special fully nested mode on the master,
     * the IRQ coming from the slave is not taken into account for the
     * priority computation.
     */
    mask = s->isr;
    if ( s->special_fully_nested_mode && (s == &s->pics_state->pics[0]) )
        mask &= ~(1 << 2);
    cur_priority = get_priority(s, mask);
    if ( priority < cur_priority )
        /* Higher priority found: an irq should be generated. */
        return (priority + s->priority_add) & 7;

    return -1;
}

/* Raise irq to CPU if necessary. */
static void pic_update_irq(struct vpic *vpic)
{
    int irq2, irq;

    ASSERT(spin_is_locked(vpic_lock(vpic)));

    /* First look at slave PIC. */
    irq2 = pic_get_irq(&vpic->pics[1]);
    if ( irq2 >= 0 )
    {
        /* If irq request by slave pic, signal master PIC. */
        pic_set_irq1(&vpic->pics[0], 2, 1);
        pic_set_irq1(&vpic->pics[0], 2, 0);
    }

    /* Look at requested IRQ. */
    irq = pic_get_irq(&vpic->pics[0]);
    if ( irq >= 0 )
        vpic->irq_pending = 1;
}

void pic_set_irq(struct vpic *vpic, int irq, int level)
{
    ASSERT(spin_is_locked(vpic_lock(vpic)));
    pic_set_irq1(&vpic->pics[irq >> 3], irq & 7, level);
    pic_update_irq(vpic);
}

/* Acknowledge interrupt @irq. */
static inline void pic_intack(PicState *s, int irq)
{
    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    if ( s->auto_eoi )
    {
        if ( s->rotate_on_auto_eoi )
            s->priority_add = (irq + 1) & 7;
    }
    else
    {
        s->isr |= (1 << irq);
    }

    /* We don't clear a level sensitive interrupt here */
    if ( !(s->elcr & (1 << irq)) )
        s->irr &= ~(1 << irq);
}

static int pic_read_irq(struct vpic *vpic)
{
    int irq, irq2, intno;

    spin_lock(vpic_lock(vpic));

    irq = pic_get_irq(&vpic->pics[0]);
    if ( irq >= 0 )
    {
        pic_intack(&vpic->pics[0], irq);
        if ( irq == 2 )
        {
            irq2 = pic_get_irq(&vpic->pics[1]);
            if ( irq2 >= 0 )
            {
                pic_intack(&vpic->pics[1], irq2);
            }
            else
            {
		gdprintk(XENLOG_WARNING, "Spurious irq on slave i8259.\n");
                irq2 = 7;
            }
            intno = vpic->pics[1].irq_base + irq2;
            irq = irq2 + 8;
        }
        else
        {
            intno = vpic->pics[0].irq_base + irq;
        }
    }
    else
    {
        irq = 7;
        intno = vpic->pics[0].irq_base + irq;
	gdprintk(XENLOG_WARNING, "Spurious irq on master i8259.\n");
    }

    pic_update_irq(vpic);

    spin_unlock(vpic_lock(vpic));

    return intno;
}

static void pic_reset(void *opaque)
{
    PicState *s = opaque;

    s->last_irr = 0;
    s->irr = 0;
    s->imr = 0;
    s->isr = 0;
    s->priority_add = 0;
    s->irq_base = 0;
    s->read_reg_select = 0;
    s->poll = 0;
    s->special_mask = 0;
    s->init_state = 0;
    s->auto_eoi = 0;
    s->rotate_on_auto_eoi = 0;
    s->special_fully_nested_mode = 0;
    s->init4 = 0;
    /* Note: ELCR is not reset */
}

static void pic_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    PicState *s = opaque;
    int priority, cmd, irq;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    addr &= 1;
    if ( addr == 0 )
    {
        if ( val & 0x10 )
        {
            pic_reset(s);
            s->pics_state->irq_pending = 0;
            s->init_state = 1;
            s->init4 = val & 1;
        }
        else if ( val & 0x08 )
        {
            if ( val & 0x04 )
                s->poll = 1;
            if ( val & 0x02 )
                s->read_reg_select = val & 1;
            if ( val & 0x40 )
                s->special_mask = (val >> 5) & 1;
        }
        else
        {
            cmd = val >> 5;
            switch ( cmd )
            {
            case 0:
            case 4:
                s->rotate_on_auto_eoi = cmd >> 2;
                break;
            case 1:
            case 5:
                priority = get_priority(s, s->isr);
                if (priority != 8) {
                    irq = (priority + s->priority_add) & 7;
                    s->isr &= ~(1 << irq);
                    if (cmd == 5)
                        s->priority_add = (irq + 1) & 7;
                    pic_update_irq(s->pics_state);
                }
                break;
            case 3:
                irq = val & 7;
                s->isr &= ~(1 << irq);
                pic_update_irq(s->pics_state);
                break;
            case 6:
                s->priority_add = (val + 1) & 7;
                pic_update_irq(s->pics_state);
                break;
            case 7:
                irq = val & 7;
                s->isr &= ~(1 << irq);
                s->priority_add = (irq + 1) & 7;
                pic_update_irq(s->pics_state);
                break;
            default:
                break;
            }
        }
    }
    else
    {
        switch ( s->init_state )
        {
        case 0:
            s->imr = val;
            pic_update_irq(s->pics_state);
            break;
        case 1:
            s->irq_base = val & 0xf8;
            s->init_state = 2;
            break;
        case 2:
            s->init_state = s->init4 ? 3 : 0;
            break;
        case 3:
            s->special_fully_nested_mode = (val >> 4) & 1;
            s->auto_eoi = (val >> 1) & 1;
            s->init_state = 0;
            break;
        }
    }
}

static uint32_t pic_poll_read (PicState *s, uint32_t addr1)
{
    int ret;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    ret = pic_get_irq(s);
    if ( ret >= 0 )
    {
        if ( addr1 >> 7 )
        {
            s->pics_state->pics[0].isr &= ~(1 << 2);
            s->pics_state->pics[0].irr &= ~(1 << 2);
        }
        s->irr &= ~(1 << ret);
        s->isr &= ~(1 << ret);
        if ( (addr1 >> 7) || (ret != 2) )
            pic_update_irq(s->pics_state);
    }
    else
    {
        ret = 0x07;
        pic_update_irq(s->pics_state);
    }

    return ret;
}

static uint32_t pic_ioport_read(void *opaque, uint32_t addr1)
{
    PicState *s = opaque;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    if ( s->poll )
    {
        s->poll = 0;
        return pic_poll_read(s, addr1);
    }

    if ( (addr1 & 1) == 0 )
        return (s->read_reg_select ? s->isr : s->irr);

    return s->imr;
}

static void elcr_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    PicState *s = opaque;

    ASSERT(spin_is_locked(vpic_lock(s->pics_state)));

    s->elcr = val & s->elcr_mask;
}

static uint32_t elcr_ioport_read(void *opaque, uint32_t addr1)
{
    PicState *s = opaque;
    return s->elcr;
}

static void pic_init1(int io_addr, int elcr_addr, PicState *s)
{
    pic_reset(s);
}

void pic_init(struct vpic *vpic)
{
    memset(vpic, 0, sizeof(*vpic));
    spin_lock_init(vpic_lock(vpic));
    vpic->pics[0].pics_state = vpic;
    vpic->pics[1].pics_state = vpic;
    vpic->pics[0].elcr_mask = 0xf8;
    vpic->pics[1].elcr_mask = 0xde;
    pic_init1(0x20, 0x4d0, &vpic->pics[0]);
    pic_init1(0xa0, 0x4d1, &vpic->pics[1]);
}

static int intercept_pic_io(ioreq_t *p)
{
    struct vpic *vpic = domain_vpic(current->domain);
    uint32_t data;

    if ( (p->size != 1) || (p->count != 1) )
    {
        gdprintk(XENLOG_WARNING,
                 "PIC_IO wrong access size %d!\n", (int)p->size);
        return 1;
    }

    if ( p->dir == IOREQ_WRITE )
    {
        if ( p->data_is_ptr )
            (void)hvm_copy_from_guest_phys(&data, p->data, p->size);
        else
            data = p->data;
        spin_lock(vpic_lock(vpic));
        pic_ioport_write((void*)&vpic->pics[p->addr>>7],
                (uint32_t) p->addr, (uint32_t) (data & 0xff));
        spin_unlock(vpic_lock(vpic));
    }
    else
    {
        spin_lock(vpic_lock(vpic));
        data = pic_ioport_read(
            (void*)&vpic->pics[p->addr>>7], (uint32_t) p->addr);
        spin_unlock(vpic_lock(vpic));
        if ( p->data_is_ptr )
            (void)hvm_copy_to_guest_phys(p->data, &data, p->size);
        else
            p->data = (u64)data;
    }

    return 1;
}

static int intercept_elcr_io(ioreq_t *p)
{
    struct vpic *vpic = domain_vpic(current->domain);
    uint32_t data;

    if ( (p->size != 1) || (p->count != 1) )
    {
        gdprintk(XENLOG_WARNING,
                 "PIC_IO wrong access size %d!\n", (int)p->size);
        return 1;
    }

    if ( p->dir == IOREQ_WRITE )
    {
        if ( p->data_is_ptr )
            (void)hvm_copy_from_guest_phys(&data, p->data, p->size);
        else
            data = p->data;
        spin_lock(vpic_lock(vpic));
        elcr_ioport_write((void*)&vpic->pics[p->addr&1],
                (uint32_t) p->addr, (uint32_t)( data & 0xff));
        spin_unlock(vpic_lock(vpic));
    }
    else
    {
        data = (u64) elcr_ioport_read(
                (void*)&vpic->pics[p->addr&1], (uint32_t) p->addr);
        if ( p->data_is_ptr )
            (void)hvm_copy_to_guest_phys(p->data, &data, p->size);
        else
            p->data = (u64)data;
    }

    return 1;
}

void register_pic_io_hook(struct domain *d)
{
    register_portio_handler(d, 0x20, 2, intercept_pic_io);
    register_portio_handler(d, 0x4d0, 1, intercept_elcr_io);
    register_portio_handler(d, 0xa0, 2, intercept_pic_io);
    register_portio_handler(d, 0x4d1, 1, intercept_elcr_io);
}

int cpu_get_pic_interrupt(struct vcpu *v, int *type)
{
    int intno;
    struct vpic *vpic = domain_vpic(v->domain);

    if ( !vlapic_accept_pic_intr(v) )
        return -1;

    if ( xchg(&vpic->irq_pending, 0) == 0 )
        return -1;

    /* Read the irq from the PIC. */
    intno = pic_read_irq(vpic);
    *type = APIC_DM_EXTINT;
    return intno;
}

int is_periodic_irq(struct vcpu *v, int irq, int type)
{
    int vec;
    struct periodic_time *pt = &v->domain->arch.hvm_domain.pl_time.periodic_tm;

    if ( pt->irq != 0 )
        return 0;

    if ( type == APIC_DM_EXTINT )
        vec = domain_vpic(v->domain)->pics[0].irq_base;
    else
        vec = domain_vioapic(v->domain)->redirtbl[0].fields.vector;

    return (irq == vec);
}
