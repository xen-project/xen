/*
 * QEMU System Emulator header
 * 
 * Copyright (c) 2003 Fabrice Bellard
 * Copyright (c) 2005 Intel Corp
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

#ifndef __ASM_X86_HVM_VPIC_H__
#define __ASM_X86_HVM_VPIC_H__

#define hw_error(x)  do {} while (0);


/* i8259.c */
typedef struct IOAPICState IOAPICState;
typedef struct PicState {
    uint8_t last_irr; /* edge detection */
    uint8_t irr; /* interrupt request register */
    uint8_t irr_xen; /* interrupts forced on by the hypervisor e.g.
			the callback irq. */
    uint8_t imr; /* interrupt mask register */
    uint8_t isr; /* interrupt service register */
    uint8_t priority_add; /* highest irq priority */
    uint8_t irq_base;
    uint8_t read_reg_select;
    uint8_t poll;
    uint8_t special_mask;
    uint8_t init_state;
    uint8_t auto_eoi;
    uint8_t rotate_on_auto_eoi;
    uint8_t special_fully_nested_mode;
    uint8_t init4; /* true if 4 byte init */
    uint8_t elcr; /* PIIX edge/trigger selection*/
    uint8_t elcr_mask;
    struct hvm_virpic *pics_state;
} PicState;

struct hvm_virpic {
    /* 0 is master pic, 1 is slave pic */
    /* XXX: better separation between the two pics */
    PicState pics[2];
    void (*irq_request)(void *opaque, int level);
    void *irq_request_opaque;
    /* IOAPIC callback support */
    spinlock_t lock;
};


void pic_set_xen_irq(void *opaque, int irq, int level);
void pic_set_irq(struct hvm_virpic *s, int irq, int level);
void pic_set_irq_new(void *opaque, int irq, int level);
void pic_init(struct hvm_virpic *s, 
              void (*irq_request)(void *, int),
              void *irq_request_opaque);
int pic_read_irq(struct hvm_virpic *s);
void pic_update_irq(struct hvm_virpic *s); /* Caller must hold s->lock */
uint32_t pic_intack_read(struct hvm_virpic *s);
void register_pic_io_hook (void);
int cpu_get_pic_interrupt(struct vcpu *v, int *type);
int is_pit_irq(struct vcpu *v, int irq, int type);
int is_irq_enabled(struct vcpu *v, int irq);
void do_pic_irqs (struct hvm_virpic *s, uint16_t irqs);
void do_pic_irqs_clear (struct hvm_virpic *s, uint16_t irqs);

#endif  /* __ASM_X86_HVM_VPIC_H__ */  
