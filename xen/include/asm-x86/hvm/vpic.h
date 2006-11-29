/*
 * i8259 interrupt controller emulation
 * 
 * Copyright (c) 2003 Fabrice Bellard
 * Copyright (c) 2005 Intel Corp
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

#ifndef __ASM_X86_HVM_VPIC_H__
#define __ASM_X86_HVM_VPIC_H__

struct vpic {
    /* IR line bitmasks. */
    uint8_t irr, imr, isr;

    /* Line IRx maps to IRQ irq_base+x */
    uint8_t irq_base;

    /*
     * Where are we in ICW2-4 initialisation (0 means no init in progress)?
     * Bits 0-1 (=x): Next write at A=1 sets ICW(x+1).
     * Bit 2: ICW1.IC4  (1 == ICW4 included in init sequence)
     * Bit 3: ICW1.SNGL (0 == ICW3 included in init sequence)
     */
    uint8_t init_state:4;

    /* IR line with highest priority. */
    uint8_t priority_add:4;

    /* Reads from A=0 obtain ISR or IRR? */
    uint8_t readsel_isr:1;

    /* Reads perform a polling read? */
    uint8_t poll:1;

    /* Automatically clear IRQs from the ISR during INTA? */
    uint8_t auto_eoi:1;

    /* Automatically rotate IRQ priorities during AEOI? */
    uint8_t rotate_on_auto_eoi:1;

    /* Exclude slave inputs when considering in-service IRQs? */
    uint8_t special_fully_nested_mode:1;

    /* Special mask mode excludes masked IRs from AEOI and priority checks. */
    uint8_t special_mask_mode:1;

    /* Is this a master PIC or slave PIC? (NB. This is not programmable.) */
    uint8_t is_master:1;

    /* Edge/trigger selection. */
    uint8_t elcr;

    /* Virtual INT output. */
    uint8_t int_output;
};

void vpic_irq_positive_edge(struct domain *d, int irq);
void vpic_irq_negative_edge(struct domain *d, int irq);
void vpic_init(struct domain *d);
int cpu_get_pic_interrupt(struct vcpu *v, int *type);
int is_periodic_irq(struct vcpu *v, int irq, int type);

#endif  /* __ASM_X86_HVM_VPIC_H__ */  
