/*
 * QEMU 8259 interrupt controller emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2005 Intel Corperation
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <public/io/ioreq.h>
#include <asm/vmx.h>
#include <public/io/vmx_vpic.h>
#include <asm/current.h>
#include <asm/vmx_vioapic.h>
#include <asm/vmx_vlapic.h>

/* set irq level. If an edge is detected, then the IRR is set to 1 */
static inline void pic_set_irq1(PicState *s, int irq, int level)
{
    int mask;
    mask = 1 << irq;
    if (s->elcr & mask) {
        /* level triggered */
        if (level) {
            s->irr |= mask;
            s->last_irr |= mask;
        } else {
            s->irr &= ~mask;
            s->last_irr &= ~mask;
        }
    } else {
        /* edge triggered */
        if (level) {
            if ((s->last_irr & mask) == 0) {
                s->irr |= mask;
	    }
            s->last_irr |= mask;
        } else {
            s->last_irr &= ~mask;
        }
    }
}

/* return the highest priority found in mask (highest = smallest
   number). Return 8 if no irq */
static inline int get_priority(PicState *s, int mask)
{
    int priority;
    if (mask == 0)
        return 8;
    priority = 0;
    while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
        priority++;
    return priority;
}

/* return the pic wanted interrupt. return -1 if none */
static int pic_get_irq(PicState *s)
{
    int mask, cur_priority, priority;

    mask = s->irr & ~s->imr;
    priority = get_priority(s, mask);
    if (priority == 8)
        return -1;
    /* compute current priority. If special fully nested mode on the
       master, the IRQ coming from the slave is not taken into account
       for the priority computation. */
    mask = s->isr;
    if (s->special_fully_nested_mode && s == &s->pics_state->pics[0])
        mask &= ~(1 << 2);
    cur_priority = get_priority(s, mask);
    if (priority < cur_priority) {
        /* higher priority found: an irq should be generated */
        return (priority + s->priority_add) & 7;
    } else {
        return -1;
    }
}

/* raise irq to CPU if necessary. must be called every time the active
   irq may change */
/* XXX: should not export it, but it is needed for an APIC kludge */
void pic_update_irq(struct vmx_virpic *s)
{
    int irq2, irq;

    /* first look at slave pic */
    irq2 = pic_get_irq(&s->pics[1]);
    if (irq2 >= 0) {
        /* if irq request by slave pic, signal master PIC */
        pic_set_irq1(&s->pics[0], 2, 1);
        pic_set_irq1(&s->pics[0], 2, 0);
    }
    /* look at requested irq */
    irq = pic_get_irq(&s->pics[0]);
    if (irq >= 0) {
        s->irq_request(s->irq_request_opaque, 1);
    }
}

void pic_set_irq_new(void *opaque, int irq, int level)
{
    struct vmx_virpic *s = opaque;

    vmx_vioapic_set_irq(current->domain, irq, level);
    pic_set_irq1(&s->pics[irq >> 3], irq & 7, level);
    /* used for IOAPIC irqs */
    if (s->alt_irq_func)
        s->alt_irq_func(s->alt_irq_opaque, irq, level);
    pic_update_irq(s);
}

void do_pic_irqs (struct vmx_virpic *s, uint16_t irqs)
{
    s->pics[1].irr |= (uint8_t)(irqs >> 8);
    s->pics[0].irr |= (uint8_t) irqs;
    vmx_vioapic_do_irqs(current->domain, irqs);
    pic_update_irq(s);
}

void do_pic_irqs_clear (struct vmx_virpic *s, uint16_t irqs)
{
    s->pics[1].irr &= ~(uint8_t)(irqs >> 8);
    s->pics[0].irr &= ~(uint8_t) irqs;
    vmx_vioapic_do_irqs_clear(current->domain, irqs);
    pic_update_irq(s);
}

/* obsolete function */
void pic_set_irq(struct vmx_virpic *isa_pic, int irq, int level)
{
    pic_set_irq_new(isa_pic, irq, level);
}

/* acknowledge interrupt 'irq' */
static inline void pic_intack(PicState *s, int irq)
{
    if (s->auto_eoi) {
        if (s->rotate_on_auto_eoi)
            s->priority_add = (irq + 1) & 7;
    } else {
        s->isr |= (1 << irq);
    }
    /* We don't clear a level sensitive interrupt here */
    if (!(s->elcr & (1 << irq)))
        s->irr &= ~(1 << irq);
}

int pic_read_irq(struct vmx_virpic *s)
{
    int irq, irq2, intno;

    irq = pic_get_irq(&s->pics[0]);
    if (irq >= 0) {
        pic_intack(&s->pics[0], irq);
        if (irq == 2) {
            irq2 = pic_get_irq(&s->pics[1]);
            if (irq2 >= 0) {
                pic_intack(&s->pics[1], irq2);
            } else {
                /* spurious IRQ on slave controller */
                irq2 = 7;
            }
            intno = s->pics[1].irq_base + irq2;
            irq = irq2 + 8;
        } else {
            intno = s->pics[0].irq_base + irq;
        }
    } else {
        /* spurious IRQ on host controller */
        printk("spurious IRQ irq got=%d\n",irq);
        irq = 7;
        intno = s->pics[0].irq_base + irq;
    }
    pic_update_irq(s);
        
    return intno;
}

static void update_shared_irr(struct vmx_virpic *s, PicState *c)
{
    uint8_t *pl, *pe;

    get_sp(current->domain)->sp_global.pic_elcr = 
		s->pics[0].elcr | ((u16)s->pics[1].elcr << 8);
    pl =(uint8_t*)&get_sp(current->domain)->sp_global.pic_last_irr;
    pe =(uint8_t*)&get_sp(current->domain)->sp_global.pic_elcr;
    if ( c == &s->pics[0] ) {
         *pl = c->last_irr;
         *pe = c->elcr;
    }
    else {
         *(pl+1) = c->last_irr;
         *(pe+1) = c->elcr;
    }
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
    s->elcr = 0;
}

static void pic_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    PicState *s = opaque;
    int priority, cmd, irq;

    addr &= 1;
    if (addr == 0) {
        if (val & 0x10) {
            /* init */
            pic_reset(s);
            update_shared_irr(s->pics_state, s);
            /* deassert a pending interrupt */
            s->pics_state->irq_request(s->pics_state->irq_request_opaque, 0);
            s->init_state = 1;
            s->init4 = val & 1;
            if (val & 0x02)
                hw_error("single mode not supported");
            if (val & 0x08)
                hw_error("level sensitive irq not supported");
        } else if (val & 0x08) {
            if (val & 0x04)
                s->poll = 1;
            if (val & 0x02)
                s->read_reg_select = val & 1;
            if (val & 0x40)
                s->special_mask = (val >> 5) & 1;
        } else {
            cmd = val >> 5;
            switch(cmd) {
            case 0:
            case 4:
                s->rotate_on_auto_eoi = cmd >> 2;
                break;
            case 1: /* end of interrupt */
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
                /* no operation */
                break;
            }
        }
    } else {
        switch(s->init_state) {
        case 0:
            /* normal mode */
            s->imr = val;
            pic_update_irq(s->pics_state);
            break;
        case 1:
            s->irq_base = val & 0xf8;
            s->init_state = 2;
            break;
        case 2:
            if (s->init4) {
                s->init_state = 3;
            } else {
                s->init_state = 0;
            }
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

    ret = pic_get_irq(s);
    if (ret >= 0) {
        if (addr1 >> 7) {
            s->pics_state->pics[0].isr &= ~(1 << 2);
            s->pics_state->pics[0].irr &= ~(1 << 2);
        }
        s->irr &= ~(1 << ret);
        s->isr &= ~(1 << ret);
        if (addr1 >> 7 || ret != 2)
            pic_update_irq(s->pics_state);
    } else {
        ret = 0x07;
        pic_update_irq(s->pics_state);
    }

    return ret;
}

static uint32_t pic_ioport_read(void *opaque, uint32_t addr1)
{
    PicState *s = opaque;
    unsigned int addr;
    int ret;

    addr = addr1;
    addr &= 1;
    if (s->poll) {
        ret = pic_poll_read(s, addr1);
        s->poll = 0;
    } else {
        if (addr == 0) {
            if (s->read_reg_select)
                ret = s->isr;
            else
                ret = s->irr;
        } else {
            ret = s->imr;
        }
    }
    return ret;
}

/* memory mapped interrupt status */
/* XXX: may be the same than pic_read_irq() */
uint32_t pic_intack_read(struct vmx_virpic *s)
{
    int ret;

    ret = pic_poll_read(&s->pics[0], 0x00);
    if (ret == 2)
        ret = pic_poll_read(&s->pics[1], 0x80) + 8;
    /* Prepare for ISR read */
    s->pics[0].read_reg_select = 1;
    
    return ret;
}

static void elcr_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    PicState *s = opaque;
    s->elcr = val & s->elcr_mask;
}

static uint32_t elcr_ioport_read(void *opaque, uint32_t addr1)
{
    PicState *s = opaque;
    return s->elcr;
}

/* XXX: add generic master/slave system */
static void pic_init1(int io_addr, int elcr_addr, PicState *s)
{
    pic_reset(s);
}

void pic_init(struct vmx_virpic *s, void (*irq_request)(), 
              void *irq_request_opaque)
{
    memset(s, 0, sizeof(*s));
    pic_init1(0x20, 0x4d0, &s->pics[0]);
    pic_init1(0xa0, 0x4d1, &s->pics[1]);
    s->pics[0].elcr_mask = 0xf8;
    s->pics[1].elcr_mask = 0xde;
    s->irq_request = irq_request;
    s->irq_request_opaque = irq_request_opaque;
    s->pics[0].pics_state = s;
    s->pics[1].pics_state = s;
    return; 
}

void pic_set_alt_irq_func(struct vmx_virpic *s, void (*alt_irq_func)(),
                          void *alt_irq_opaque)
{
    s->alt_irq_func = alt_irq_func;
    s->alt_irq_opaque = alt_irq_opaque;
}

static int intercept_pic_io(ioreq_t *p)
{
    struct vmx_virpic  *pic;
    struct vcpu *v = current;
    uint32_t data;
    
    if ( p->size != 1 || p->count != 1) {
        printk("PIC_IO wrong access size %d!\n", (int)p->size);
        return 1;
    }
    pic = &v->domain->arch.vmx_platform.vmx_pic;
    if ( p->dir == 0 ) {
        if(p->pdata_valid) 
            vmx_copy(&data, (unsigned long)p->u.pdata, p->size, VMX_COPY_IN);
        else
            data = p->u.data;
        pic_ioport_write((void*)&pic->pics[p->addr>>7],
                (uint32_t) p->addr, (uint32_t) (data & 0xff));
    }
    else {
        data = pic_ioport_read(
            (void*)&pic->pics[p->addr>>7], (uint32_t) p->addr);
        if(p->pdata_valid) 
            vmx_copy(&data, (unsigned long)p->u.pdata, p->size, VMX_COPY_OUT);
        else 
            p->u.data = (u64)data;
    }
    return 1;
}

static int intercept_elcr_io(ioreq_t *p)
{
    struct vmx_virpic  *s;
    struct vcpu *v = current;
    uint32_t data;
    
    if ( p->size != 1 || p->count != 1 ) {
        printk("PIC_IO wrong access size %d!\n", (int)p->size);
        return 1;
    }

    s = &v->domain->arch.vmx_platform.vmx_pic;
    if ( p->dir == 0 ) {
        if(p->pdata_valid) 
            vmx_copy(&data, (unsigned long)p->u.pdata, p->size, VMX_COPY_IN);
        else
            data = p->u.data;
        elcr_ioport_write((void*)&s->pics[p->addr&1],
                (uint32_t) p->addr, (uint32_t)( data & 0xff));
    	get_sp(current->domain)->sp_global.pic_elcr = 
            s->pics[0].elcr | ((u16)s->pics[1].elcr << 8);
    }
    else {
        data = (u64) elcr_ioport_read(
                (void*)&s->pics[p->addr&1], (uint32_t) p->addr);
        if(p->pdata_valid) 
            vmx_copy(&data, (unsigned long)p->u.pdata, p->size, VMX_COPY_OUT);
        else 
            p->u.data = (u64)data;

    }
    return 1;
}
void register_pic_io_hook (void)
{
    register_portio_handler(0x20, 2, intercept_pic_io); 
    register_portio_handler(0x4d0, 1, intercept_elcr_io); 
    register_portio_handler(0xa0, 2, intercept_pic_io); 
    register_portio_handler(0x4d1, 1, intercept_elcr_io); 
}


/* IRQ handling */
int cpu_get_pic_interrupt(struct vcpu *v, int *type)
{
    int intno;
    struct vmx_virpic *s = &v->domain->arch.vmx_platform.vmx_pic;
    struct vmx_platform *plat = &v->domain->arch.vmx_platform;

    if ( !vlapic_accept_pic_intr(v) )
        return -1;

    if ( !plat->interrupt_request )
        return -1;

    plat->interrupt_request = 0;
    /* read the irq from the PIC */
    intno = pic_read_irq(s);
    *type = VLAPIC_DELIV_MODE_EXT;
    return intno;
}

int is_pit_irq(struct vcpu *v, int irq, int type)
{
    int pit_vec;

    if (type == VLAPIC_DELIV_MODE_EXT)
        pit_vec = v->domain->arch.vmx_platform.vmx_pic.pics[0].irq_base;
    else
        pit_vec =
          v->domain->arch.vmx_platform.vmx_vioapic.redirtbl[0].RedirForm.vector;

    return (irq == pit_vec);
}

int is_irq_enabled(struct vcpu *v, int irq)
{
    struct vmx_virpic *vpic=&v->domain->arch.vmx_platform.vmx_pic;
        
    if ( irq & 8 ) {
        return !( (1 << (irq&7)) & vpic->pics[1].imr);
    }
    else {
        return !( (1 << irq) & vpic->pics[0].imr);
    }
}

