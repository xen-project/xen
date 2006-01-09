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
#include "xenctrl.h"
#include <xen/hvm/ioreq.h>
#include <stdio.h>
#include "cpu.h"
#include "cpu-all.h"

#include <vl.h>
extern shared_iopage_t *shared_page;
extern CPUState *global_env;
void pic_set_irq(int irq, int level)
{
    global_iodata_t  *gio;
    int  mask;

    gio = &shared_page->sp_global;
    mask = 1 << irq;
    if ( gio->pic_elcr & mask ) {
        /* level */
       if ( level ) {
           atomic_clear_bit(irq, &gio->pic_clear_irr);
           atomic_set_bit(irq, &gio->pic_irr);
           global_env->send_event = 1;
       }
       else {
           atomic_clear_bit(irq, &gio->pic_irr);
           atomic_set_bit(irq, &gio->pic_clear_irr);
           global_env->send_event = 1;
       }
    }
    else {
       /* edge */
       if ( level ) {
           if ( (mask & gio->pic_last_irr) == 0 ) { 
               atomic_set_bit(irq, &gio->pic_irr);
               atomic_set_bit(irq, &gio->pic_last_irr);
               global_env->send_event = 1;
           }
       }
       else {
           atomic_clear_bit(irq, &gio->pic_last_irr);
       }
    }
}

void irq_info(void)
{
    term_printf("irq statistic code not compiled.\n");
}

void pic_info(void)
{
    term_printf("pic_infoi code not compiled.\n");
}

void pic_init(void)
{
}

