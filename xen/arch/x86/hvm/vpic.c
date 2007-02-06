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
#include <xen/event.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>

#define vpic_domain(v) (container_of((v), struct domain, \
                        arch.hvm_domain.vpic[!vpic->is_master]))
#define __vpic_lock(v) &container_of((v), struct hvm_domain, \
                                        vpic[!(v)->is_master])->irq_lock
#define vpic_lock(v)   spin_lock(__vpic_lock(v))
#define vpic_unlock(v) spin_unlock(__vpic_lock(v))
#define vpic_is_locked(v) spin_is_locked(__vpic_lock(v))
#define vpic_elcr_mask(v) (vpic->is_master ? (uint8_t)0xf8 : (uint8_t)0xde);

/* Return the highest priority found in mask. Return 8 if none. */
#define VPIC_PRIO_NONE 8
static int vpic_get_priority(struct hvm_hw_vpic *vpic, uint8_t mask)
{
    int prio;

    ASSERT(vpic_is_locked(vpic));

    if ( mask == 0 )
        return VPIC_PRIO_NONE;

    /* prio = ffs(mask ROL vpic->priority_add); */
    asm ( "rol %%cl,%b1 ; bsf %1,%0"
          : "=r" (prio) : "r" ((uint32_t)mask), "c" (vpic->priority_add) );
    return prio;
}

/* Return the PIC's highest priority pending interrupt. Return -1 if none. */
static int vpic_get_highest_priority_irq(struct hvm_hw_vpic *vpic)
{
    int cur_priority, priority, irq;
    uint8_t mask;

    ASSERT(vpic_is_locked(vpic));

    mask = vpic->irr & ~vpic->imr;
    priority = vpic_get_priority(vpic, mask);
    if ( priority == VPIC_PRIO_NONE )
        return -1;

    irq = (priority + vpic->priority_add) & 7;

    /*
     * Compute current priority. If special fully nested mode on the master,
     * the IRQ coming from the slave is not taken into account for the
     * priority computation. In special mask mode, masked interrupts do not
     * block lower-priority interrupts even if their IS bit is set.
     */
    mask = vpic->isr;
    if ( vpic->special_fully_nested_mode && vpic->is_master && (irq == 2) )
        mask &= ~(1 << 2);
    if ( vpic->special_mask_mode )
        mask &= ~vpic->imr;
    cur_priority = vpic_get_priority(vpic, mask);

    /* If a higher priority is found then an irq should be generated. */
    return (priority < cur_priority) ? irq : -1;
}

static void vpic_update_int_output(struct hvm_hw_vpic *vpic)
{
    int irq;

    ASSERT(vpic_is_locked(vpic));

    irq = vpic_get_highest_priority_irq(vpic);
    if ( vpic->int_output == (irq >= 0) )
        return;

    /* INT line transition L->H or H->L. */
    vpic->int_output = !vpic->int_output;

    if ( vpic->int_output )
    {
        if ( vpic->is_master )
        {
            /* Master INT line is connected to VCPU0's VLAPIC LVT0. */
            struct vcpu *v = vpic_domain(vpic)->vcpu[0];
            if ( (v != NULL) && vlapic_accept_pic_intr(v) )
                vcpu_kick(v);
        }
        else
        {
            /* Assert slave line in master PIC. */
            (--vpic)->irr |= 1 << 2;
            vpic_update_int_output(vpic);
        }
    }
    else if ( !vpic->is_master )
    {
        /* Clear slave line in master PIC. */
        (--vpic)->irr &= ~(1 << 2);
        vpic_update_int_output(vpic);
    }
}

static void __vpic_intack(struct hvm_hw_vpic *vpic, int irq)
{
    uint8_t mask = 1 << irq;

    ASSERT(vpic_is_locked(vpic));

    /* Edge-triggered: clear the IRR (forget the edge). */
    if ( !(vpic->elcr & mask) )
        vpic->irr &= ~mask;

    if ( !vpic->auto_eoi )
        vpic->isr |= mask;
    else if ( vpic->rotate_on_auto_eoi )
        vpic->priority_add = (irq + 1) & 7;

    vpic_update_int_output(vpic);
}

static int vpic_intack(struct hvm_hw_vpic *vpic)
{
    int irq = -1;

    vpic_lock(vpic);

    if ( !vpic->int_output )
        goto out;

    irq = vpic_get_highest_priority_irq(vpic);
    BUG_ON(irq < 0);
    __vpic_intack(vpic, irq);

    if ( (irq == 2) && vpic->is_master )
    {
        vpic++; /* Slave PIC */
        irq = vpic_get_highest_priority_irq(vpic);
        BUG_ON(irq < 0);
        __vpic_intack(vpic, irq);
        irq += 8;
    }

 out:
    vpic_unlock(vpic);
    return irq;
}

static void vpic_ioport_write(struct hvm_hw_vpic *vpic, uint32_t addr, uint32_t val)
{
    int priority, cmd, irq;
    uint8_t mask;

    vpic_lock(vpic);

    addr &= 1;
    if ( addr == 0 )
    {
        if ( val & 0x10 )
        {
            /* ICW1 */
            /* Clear edge-sensing logic. */
            vpic->irr &= vpic->elcr;

            /* No interrupts masked or in service. */
            vpic->imr = vpic->isr = 0;

            /* IR7 is lowest priority. */
            vpic->priority_add = 0;
            vpic->rotate_on_auto_eoi = 0;

            vpic->special_mask_mode = 0;
            vpic->readsel_isr = 0;
            vpic->poll = 0;

            if ( !(val & 1) )
            {
                /* NO ICW4: ICW4 features are cleared. */
                vpic->auto_eoi = 0;
                vpic->special_fully_nested_mode = 0;
            }

            vpic->init_state = ((val & 3) << 2) | 1;
        }
        else if ( val & 0x08 )
        {
            /* OCW3 */
            if ( val & 0x04 )
                vpic->poll = 1;
            if ( val & 0x02 )
                vpic->readsel_isr = val & 1;
            if ( val & 0x40 )
                vpic->special_mask_mode = (val >> 5) & 1;
        }
        else
        {
            /* OCW2 */
            cmd = val >> 5;
            switch ( cmd )
            {
            case 0: /* Rotate in AEOI Mode (Clear) */
            case 4: /* Rotate in AEOI Mode (Set)   */
                vpic->rotate_on_auto_eoi = cmd >> 2;
                break;
            case 1: /* Non-Specific EOI            */
            case 5: /* Non-Specific EOI & Rotate   */
                mask = vpic->isr;
                if ( vpic->special_mask_mode )
                    mask &= ~vpic->imr; /* SMM: ignore masked IRs. */
                priority = vpic_get_priority(vpic, mask);
                if ( priority == VPIC_PRIO_NONE )
                    break;
                irq = (priority + vpic->priority_add) & 7;
                vpic->isr &= ~(1 << irq);
                if ( cmd == 5 )
                    vpic->priority_add = (irq + 1) & 7;
                break;
            case 3: /* Specific EOI                */
            case 7: /* Specific EOI & Rotate       */
                irq = val & 7;
                vpic->isr &= ~(1 << irq);
                if ( cmd == 7 )
                    vpic->priority_add = (irq + 1) & 7;
                break;
            case 6: /* Set Priority                */
                vpic->priority_add = (val + 1) & 7;
                break;
            }
        }
    }
    else
    {
        switch ( vpic->init_state & 3 )
        {
        case 0:
            /* OCW1 */
            vpic->imr = val;
            break;
        case 1:
            /* ICW2 */
            vpic->irq_base = val & 0xf8;
            vpic->init_state++;
            if ( !(vpic->init_state & 8) )
                break; /* CASCADE mode: wait for write to ICW3. */
            /* SNGL mode: fall through (no ICW3). */
        case 2:
            /* ICW3 */
            vpic->init_state++;
            if ( !(vpic->init_state & 4) )
                vpic->init_state = 0; /* No ICW4: init done */
            break;
        case 3:
            /* ICW4 */
            vpic->special_fully_nested_mode = (val >> 4) & 1;
            vpic->auto_eoi = (val >> 1) & 1;
            vpic->init_state = 0;
            break;
        }
    }

    vpic_update_int_output(vpic);

    vpic_unlock(vpic);
}

static uint32_t vpic_ioport_read(struct hvm_hw_vpic *vpic, uint32_t addr)
{
    if ( vpic->poll )
    {
        vpic->poll = 0;
        return vpic_intack(vpic);
    }

    if ( (addr & 1) == 0 )
        return (vpic->readsel_isr ? vpic->isr : vpic->irr);

    return vpic->imr;
}

static int vpic_intercept_pic_io(ioreq_t *p)
{
    struct hvm_hw_vpic *vpic;
    uint32_t data;

    if ( (p->size != 1) || (p->count != 1) )
    {
        gdprintk(XENLOG_WARNING, "PIC_IO bad access size %d\n", (int)p->size);
        return 1;
    }

    vpic = &current->domain->arch.hvm_domain.vpic[p->addr >> 7];

    if ( p->dir == IOREQ_WRITE )
    {
        if ( p->data_is_ptr )
            (void)hvm_copy_from_guest_phys(&data, p->data, p->size);
        else
            data = p->data;
        vpic_ioport_write(vpic, (uint32_t)p->addr, (uint8_t)data);
    }
    else
    {
        data = vpic_ioport_read(vpic, (uint32_t)p->addr);
        if ( p->data_is_ptr )
            (void)hvm_copy_to_guest_phys(p->data, &data, p->size);
        else
            p->data = (u64)data;
    }

    return 1;
}

static int vpic_intercept_elcr_io(ioreq_t *p)
{
    struct hvm_hw_vpic *vpic;
    uint32_t data;

    if ( (p->size != 1) || (p->count != 1) )
    {
        gdprintk(XENLOG_WARNING, "PIC_IO bad access size %d\n", (int)p->size);
        return 1;
    }

    vpic = &current->domain->arch.hvm_domain.vpic[p->addr & 1];

    if ( p->dir == IOREQ_WRITE )
    {
        if ( p->data_is_ptr )
            (void)hvm_copy_from_guest_phys(&data, p->data, p->size);
        else
            data = p->data;

        /* Some IRs are always edge trig. Slave IR is always level trig. */
        data &= vpic_elcr_mask(vpic);
        if ( vpic->is_master )
            data |= 1 << 2;
        vpic->elcr = data;
    }
    else
    {
        /* Reader should not see hardcoded level-triggered slave IR. */
        data = vpic->elcr & vpic_elcr_mask(vpic);

        if ( p->data_is_ptr )
            (void)hvm_copy_to_guest_phys(p->data, &data, p->size);
        else
            p->data = data;
    }

    return 1;
}

#ifdef HVM_DEBUG_SUSPEND
static void vpic_info(struct hvm_hw_vpic *s)
{
    printk("*****pic state:*****\n");
    printk("pic 0x%x.\n", s->irr);
    printk("pic 0x%x.\n", s->imr);
    printk("pic 0x%x.\n", s->isr);
    printk("pic 0x%x.\n", s->irq_base);
    printk("pic 0x%x.\n", s->init_state);
    printk("pic 0x%x.\n", s->priority_add);
    printk("pic 0x%x.\n", s->readsel_isr);
    printk("pic 0x%x.\n", s->poll);
    printk("pic 0x%x.\n", s->auto_eoi);
    printk("pic 0x%x.\n", s->rotate_on_auto_eoi);
    printk("pic 0x%x.\n", s->special_fully_nested_mode);
    printk("pic 0x%x.\n", s->special_mask_mode);
    printk("pic 0x%x.\n", s->elcr);
    printk("pic 0x%x.\n", s->int_output);
    printk("pic 0x%x.\n", s->is_master);
}
#else
static void vpic_info(struct hvm_hw_vpic *s)
{
}
#endif

static int vpic_save(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_hw_vpic *s;
    int i;

    /* Save the state of both PICs */
    for ( i = 0; i < 2 ; i++ )
    {
        s = &d->arch.hvm_domain.vpic[i];
        vpic_info(s);
        if ( hvm_save_entry(PIC, i, h, s) )
            return 1;
    }

    return 0;
}

static int vpic_load(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_hw_vpic *s;
    uint16_t inst;
    
    /* Which PIC is this? */
    inst = hvm_load_instance(h);
    if ( inst > 1 )
        return -EINVAL;
    s = &d->arch.hvm_domain.vpic[inst];

    /* Load the state */
    if ( hvm_load_entry(PIC, h, s) != 0 )
        return -EINVAL;

    vpic_info(s);
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PIC, vpic_save, vpic_load);

void vpic_init(struct domain *d)
{
    struct hvm_hw_vpic *vpic;

    /* Master PIC. */
    vpic = &d->arch.hvm_domain.vpic[0];
    memset(vpic, 0, sizeof(*vpic));
    vpic->is_master = 1;
    vpic->elcr      = 1 << 2;
    register_portio_handler(d, 0x20, 2, vpic_intercept_pic_io);
    register_portio_handler(d, 0x4d0, 1, vpic_intercept_elcr_io);

    /* Slave PIC. */
    vpic++;
    memset(vpic, 0, sizeof(*vpic));
    register_portio_handler(d, 0xa0, 2, vpic_intercept_pic_io);
    register_portio_handler(d, 0x4d1, 1, vpic_intercept_elcr_io);
}

void vpic_irq_positive_edge(struct domain *d, int irq)
{
    struct hvm_hw_vpic *vpic = &d->arch.hvm_domain.vpic[irq >> 3];
    uint8_t mask = 1 << (irq & 7);

    ASSERT(irq <= 15);
    ASSERT(vpic_is_locked(vpic));

    if ( irq == 2 )
        return;

    vpic->irr |= mask;
    if ( !(vpic->imr & mask) )
        vpic_update_int_output(vpic);
}

void vpic_irq_negative_edge(struct domain *d, int irq)
{
    struct hvm_hw_vpic *vpic = &d->arch.hvm_domain.vpic[irq >> 3];
    uint8_t mask = 1 << (irq & 7);

    ASSERT(irq <= 15);
    ASSERT(vpic_is_locked(vpic));

    if ( irq == 2 )
        return;

    vpic->irr &= ~mask;
    if ( !(vpic->imr & mask) )
        vpic_update_int_output(vpic);
}

int cpu_get_pic_interrupt(struct vcpu *v, int *type)
{
    int irq, vector;
    struct hvm_hw_vpic *vpic = &v->domain->arch.hvm_domain.vpic[0];

    if ( !vlapic_accept_pic_intr(v) || !vpic->int_output )
        return -1;

    irq = vpic_intack(vpic);
    if ( irq == -1 )
        return -1;

    vector = vpic[irq >> 3].irq_base + (irq & 7);
    *type = APIC_DM_EXTINT;
    return vector;
}
