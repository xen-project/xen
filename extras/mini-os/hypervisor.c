/******************************************************************************
 * hypervisor.c
 * 
 * Communication to/from hypervisor.
 * 
 * Copyright (c) 2002-2003, K A Fraser
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <os.h>
#include <hypervisor.h>

static unsigned long event_mask = 0;
static unsigned long ev_err_count;

void do_hypervisor_callback(struct pt_regs *regs)
{
    unsigned long events, flags;
    shared_info_t *shared = HYPERVISOR_shared_info;

    do {
        /* Specialised local_irq_save(). */
        flags = test_and_clear_bit(EVENTS_MASTER_ENABLE_BIT, 
                                   &shared->events_mask);
        barrier();

        events  = xchg(&shared->events, 0);
        events &= event_mask;

        /* 'events' now contains some pending events to handle. */
        __asm__ __volatile__ (
            "   push %1                            ;"
            "   sub  $4,%%esp                      ;"
            "   jmp  2f                            ;"
            "1: btrl %%eax,%0                      ;" /* clear bit     */
            "   mov  %%eax,(%%esp)                 ;"
            "   call do_event                      ;" /* do_event(event) */
            "2: bsfl %0,%%eax                      ;" /* %eax == bit # */
            "   jnz  1b                            ;"
            "   add  $8,%%esp                      ;"
            /* we use %ebx because it is callee-saved */
            : : "b" (events), "r" (regs)
            /* clobbered by callback function calls */
            : "eax", "ecx", "edx", "memory" ); 

        /* Specialised local_irq_restore(). */
        if ( flags ) set_bit(EVENTS_MASTER_ENABLE_BIT, &shared->events_mask);
        barrier();
    }
    while ( shared->events );
}

void enable_hypervisor_event(unsigned int ev)
{
    set_bit(ev, &event_mask);
    set_bit(ev, &HYPERVISOR_shared_info->events_mask);
    if ( test_bit(EVENTS_MASTER_ENABLE_BIT, 
                  &HYPERVISOR_shared_info->events_mask) )
        do_hypervisor_callback(NULL);
}

void disable_hypervisor_event(unsigned int ev)
{
    clear_bit(ev, &event_mask);
    clear_bit(ev, &HYPERVISOR_shared_info->events_mask);
}

void ack_hypervisor_event(unsigned int ev)
{
    if ( !(event_mask & (1<<ev)) )
        atomic_inc((atomic_t *)&ev_err_count);
    set_bit(ev, &HYPERVISOR_shared_info->events_mask);
}
