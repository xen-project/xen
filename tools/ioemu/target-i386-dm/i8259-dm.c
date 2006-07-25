/* Xen 8259 stub for interrupt controller emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2005      Intel corperation
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
#include "vl.h"

/* debug PIC */
//#define DEBUG_PIC

//#define DEBUG_IRQ_LATENCY
//#define DEBUG_IRQ_COUNT

#include "xenctrl.h"
#include <xen/hvm/ioreq.h>
#include <stdio.h>
#include "cpu.h"
#include "cpu-all.h"

extern shared_iopage_t *shared_page;

struct PicState2 {
};

void pic_set_irq_new(void *opaque, int irq, int level)
{
    /* PicState2 *s = opaque; */
    global_iodata_t  *gio;
    int  mask;

    gio = &shared_page->sp_global;
    mask = 1 << irq;
    if ( gio->pic_elcr & mask ) {
        /* level */
       if ( level ) {
           atomic_clear_bit(irq, &gio->pic_clear_irr);
           atomic_set_bit(irq, &gio->pic_irr);
           cpu_single_env->send_event = 1;
       }
       else {
           atomic_clear_bit(irq, &gio->pic_irr);
           atomic_set_bit(irq, &gio->pic_clear_irr);
           cpu_single_env->send_event = 1;
       }
    }
    else {
       /* edge */
       if ( level ) {
           if ( (mask & gio->pic_last_irr) == 0 ) { 
               atomic_set_bit(irq, &gio->pic_irr);
               atomic_set_bit(irq, &gio->pic_last_irr);
               cpu_single_env->send_event = 1;
           }
       }
       else {
           atomic_clear_bit(irq, &gio->pic_last_irr);
       }
    }
}

/* obsolete function */
void pic_set_irq(int irq, int level)
{
    pic_set_irq_new(isa_pic, irq, level);
}

void irq_info(void)
{
    term_printf("irq statistic code not compiled.\n");
}

void pic_info(void)
{
    term_printf("pic_info code not compiled.\n");
}

PicState2 *pic_init(IRQRequestFunc *irq_request, void *irq_request_opaque)
{
    PicState2 *s;
    s = qemu_mallocz(sizeof(PicState2));
    if (!s)
        return NULL;
    return s;
}

void pic_set_alt_irq_func(PicState2 *s, SetIRQFunc *alt_irq_func,
                          void *alt_irq_opaque)
{
}
