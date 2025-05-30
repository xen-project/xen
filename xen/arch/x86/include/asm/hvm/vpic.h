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

struct domain;
struct vcpu;

void vpic_irq_positive_edge(struct domain *d, int irq);
void vpic_irq_negative_edge(struct domain *d, int irq);
void vpic_init(struct domain *d);
void vpic_reset(struct domain *d);
int vpic_ack_pending_irq(struct vcpu *v);

#endif  /* __ASM_X86_HVM_VPIC_H__ */  
