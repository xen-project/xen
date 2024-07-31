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

#include <xen/types.h>
#include <xen/event.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/trace.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/save.h>

#define vpic_domain(v) (container_of((v), struct domain, \
                                     arch.hvm.vpic[!(v)->is_master]))
#define __vpic_lock(v) &container_of((v), struct hvm_domain, \
                                        vpic[!(v)->is_master])->irq_lock
#define vpic_lock(v)   spin_lock(__vpic_lock(v))
#define vpic_unlock(v) spin_unlock(__vpic_lock(v))
#define vpic_is_locked(v) spin_is_locked(__vpic_lock(v))
#define vpic_elcr_mask(v, mb2) ((v)->is_master ? 0xf8 | ((mb2) << 2) : 0xde)

/* Return the highest priority found in mask. Return 8 if none. */
#define VPIC_PRIO_NONE 8
static int vpic_get_priority(struct hvm_hw_vpic *vpic, uint8_t mask)
{
    int prio;

    ASSERT(vpic_is_locked(vpic));

    if ( mask == 0 )
        return VPIC_PRIO_NONE;

    /* prio = ffs(mask ROR vpic->priority_add); */
    asm ( "ror %%cl,%b1 ; rep; bsf %1,%0"
          : "=r" (prio) : "q" ((uint32_t)mask), "c" (vpic->priority_add) );
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
    TRACE_TIME(TRC_HVM_EMUL_PIC_INT_OUTPUT, vpic->int_output, vpic->is_master, irq);
    if ( vpic->int_output == (!vpic->init_state && irq >= 0) )
        return;

    /*
     * INT line transition L->H or H->L.
     * Force line status to L when in init mode.
     */
    vpic->int_output = !vpic->init_state && !vpic->int_output;

    if ( vpic->int_output )
    {
        if ( vpic->is_master )
        {
            /* Master INT line is connected in Virtual Wire Mode. */
            struct vcpu *v = vpic_domain(vpic)->arch.hvm.i8259_target;

            if ( v != NULL )
            {
                TRACE_TIME(TRC_HVM_EMUL_PIC_KICK, irq);
                vcpu_kick(v);
            }
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

    TRACE_TIME(TRC_HVM_EMUL_PIC_INTACK, vpic->is_master, irq);
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

static void vpic_ioport_write(
    struct hvm_hw_vpic *vpic, uint32_t addr, uint32_t val)
{
    int priority, cmd;
    uint8_t mask;
    bool unmasked = false;

    vpic_lock(vpic);

    if ( (addr & 1) == 0 )
    {
        if ( val & 0x10 )
        {
            unsigned int pending = vpic->isr | (vpic->irr & ~vpic->elcr);

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
            vpic_update_int_output(vpic);
            vpic_unlock(vpic);

            /*
             * Forward the EOI of any pending or in service interrupt that has
             * been cleared from IRR or ISR, or else the dpci logic will get
             * out of sync with the state of the interrupt controller.
             */
            while ( pending )
            {
                unsigned int pin = __scanbit(pending, 8);

                ASSERT(pin < 8);
                hvm_dpci_eoi(current->domain,
                             hvm_isa_irq_to_gsi((addr >> 7) ? (pin | 8) : pin));
                __clear_bit(pin, &pending);
            }
            return;
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
            unsigned int pin;

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
                pin = (priority + vpic->priority_add) & 7;
                goto common_eoi;

            case 3: /* Specific EOI                */
            case 7: /* Specific EOI & Rotate       */
                pin = val & 7;

            common_eoi:
                vpic->isr &= ~(1 << pin);
                if ( cmd == 7 || cmd == 5 )
                    vpic->priority_add = (pin + 1) & 7;
                /* Release lock and EOI the physical interrupt (if any). */
                vpic_update_int_output(vpic);
                vpic_unlock(vpic);
                hvm_dpci_eoi(current->domain,
                             hvm_isa_irq_to_gsi((addr >> 7) ? (pin | 8) : pin));
                return; /* bail immediately */
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
            unmasked = vpic->imr & (~val);
            vpic->imr = val;
            break;
        case 1:
            /* ICW2 */
            vpic->irq_base = val & 0xf8;
            vpic->init_state++;
            if ( !(vpic->init_state & 8) )
                break; /* CASCADE mode: wait for write to ICW3. */
            /* SNGL mode: fall through (no ICW3). */
            fallthrough;
        case 2:
            /* ICW3 */
            vpic->init_state++;
            if ( !(vpic->init_state & 4) )
            {
                vpic->init_state = 0; /* No ICW4: init done */
                unmasked = true;
            }
            break;
        case 3:
            /* ICW4 */
            vpic->special_fully_nested_mode = (val >> 4) & 1;
            vpic->auto_eoi = (val >> 1) & 1;
            vpic->init_state = 0;
            unmasked = true;
            break;
        }
    }

    vpic_update_int_output(vpic);

    vpic_unlock(vpic);

    if ( unmasked )
        pt_may_unmask_irq(vpic_domain(vpic), NULL);
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

static int cf_check vpic_intercept_pic_io(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct hvm_hw_vpic *vpic;

    if ( bytes != 1 )
    {
        gdprintk(XENLOG_WARNING, "PIC_IO bad access size %d\n", bytes);
        *val = ~0;
        return X86EMUL_OKAY;
    }

    vpic = &current->domain->arch.hvm.vpic[!!(port & 0x80)];

    if ( dir == IOREQ_WRITE )
        vpic_ioport_write(vpic, port, (uint8_t)*val);
    else
        *val = (uint8_t)vpic_ioport_read(vpic, port);

    return X86EMUL_OKAY;
}

static int cf_check vpic_intercept_elcr_io(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct hvm_hw_vpic *vpic;
    unsigned int data, shift = 0;

    BUG_ON(bytes > 2 - (port & 1));

    vpic = &current->domain->arch.hvm.vpic[port & 1];

    do {
        if ( dir == IOREQ_WRITE )
        {
            /* Some IRs are always edge trig. Slave IR is always level trig. */
            data = (*val >> shift) & vpic_elcr_mask(vpic, 1);
            if ( vpic->is_master )
                data |= 1 << 2;
            vpic->elcr = data;
        }
        else
        {
            /* Reader should not see hardcoded level-triggered slave IR. */
            data = vpic->elcr & vpic_elcr_mask(vpic, 0);
            if ( !shift )
                *val = data;
            else
                *val |= data << shift;
        }

        ++vpic;
        shift += 8;
    } while ( --bytes );

    return X86EMUL_OKAY;
}

static int cf_check vpic_save(struct vcpu *v, hvm_domain_context_t *h)
{
    struct domain *d = v->domain;
    struct hvm_hw_vpic *s;
    int i;

    if ( !has_vpic(d) )
        return 0;

    /* Save the state of both PICs */
    for ( i = 0; i < 2 ; i++ )
    {
        s = &d->arch.hvm.vpic[i];
        if ( hvm_save_entry(PIC, i, h, s) )
            return 1;
    }

    return 0;
}

static int cf_check vpic_check(const struct domain *d, hvm_domain_context_t *h)
{
    unsigned int inst = hvm_load_instance(h);
    const struct hvm_hw_vpic *s;

    if ( !has_vpic(d) )
        return -ENODEV;

    /* Which PIC is this? */
    if ( inst >= ARRAY_SIZE(d->arch.hvm.vpic) )
        return -ENOENT;

    s = hvm_get_entry(PIC, h);
    if ( !s )
        return -ENODATA;

    /*
     * Check to-be-loaded values are within valid range, for them to represent
     * actually reachable state.  Uses of some of the values elsewhere assume
     * this is the case.
     */
    if ( s->int_output > 1 )
        return -EDOM;

    if ( s->is_master != !inst ||
         (s->int_output && s->init_state) ||
         (s->elcr & ~vpic_elcr_mask(s, 1)) )
        return -EINVAL;

    return 0;
}

static int cf_check vpic_load(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_hw_vpic *s;
    unsigned int inst = hvm_load_instance(h);

    if ( !has_vpic(d) )
        return -ENODEV;

    /* Which PIC is this? */
    ASSERT(inst < ARRAY_SIZE(d->arch.hvm.vpic));
    s = &d->arch.hvm.vpic[inst];

    /* Load the state */
    if ( hvm_load_entry(PIC, h, s) != 0 )
        return -EINVAL;

    if ( s->is_master )
        s->elcr |= 1 << 2;

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PIC, vpic_save, vpic_check, vpic_load, 2,
                          HVMSR_PER_DOM);

void vpic_reset(struct domain *d)
{
    struct hvm_hw_vpic *vpic;

    if ( !has_vpic(d) )
        return;

    /* Master PIC. */
    vpic = &d->arch.hvm.vpic[0];
    memset(vpic, 0, sizeof(*vpic));
    vpic->is_master = 1;
    vpic->elcr      = 1 << 2;

    /* Slave PIC. */
    vpic++;
    memset(vpic, 0, sizeof(*vpic));
}

void vpic_init(struct domain *d)
{
    if ( !has_vpic(d) )
        return;

    vpic_reset(d);

    register_portio_handler(d, 0x20, 2, vpic_intercept_pic_io);
    register_portio_handler(d, 0xa0, 2, vpic_intercept_pic_io);

    register_portio_handler(d, 0x4d0, 2, vpic_intercept_elcr_io);
}

void vpic_irq_positive_edge(struct domain *d, int irq)
{
    struct hvm_hw_vpic *vpic = &d->arch.hvm.vpic[!!(irq & 8)];
    uint8_t mask = 1 << (irq & 7);

    ASSERT(has_vpic(d));
    ASSERT(irq <= 15);
    ASSERT(vpic_is_locked(vpic));

    TRACE_TIME(TRC_HVM_EMUL_PIC_POSEDGE, irq);
    if ( irq == 2 )
        return;

    vpic->irr |= mask;
    if ( !(vpic->imr & mask) )
        vpic_update_int_output(vpic);
}

void vpic_irq_negative_edge(struct domain *d, int irq)
{
    struct hvm_hw_vpic *vpic = &d->arch.hvm.vpic[!!(irq & 8)];
    uint8_t mask = 1 << (irq & 7);

    ASSERT(has_vpic(d));
    ASSERT(irq <= 15);
    ASSERT(vpic_is_locked(vpic));

    TRACE_TIME(TRC_HVM_EMUL_PIC_NEGEDGE, irq);
    if ( irq == 2 )
        return;

    vpic->irr &= ~mask;
    if ( !(vpic->imr & mask) )
        vpic_update_int_output(vpic);
}

int vpic_ack_pending_irq(struct vcpu *v)
{
    int irq, accept;
    struct hvm_hw_vpic *vpic = &v->domain->arch.hvm.vpic[0];

    ASSERT(has_vpic(v->domain));

    accept = vlapic_accept_pic_intr(v);

    TRACE_TIME(TRC_HVM_EMUL_PIC_PEND_IRQ_CALL, accept, vpic->int_output);
    if ( !accept || !vpic->int_output )
        return -1;

    irq = vpic_intack(vpic);
    if ( irq == -1 )
        return -1;

    return vpic[irq >> 3].irq_base + (irq & 7);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
