/******************************************************************************
 * hypervisor.c
 * 
 * Communication to/from hypervisor.
 *
 * Copied from XenoLinux and adjusted by Rolf.Neugebauer@intel.com
 * 
 * Copyright (c) 2002, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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



/*
 * Define interface to generic handling in irq.c
 */

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
    {
        //printk("Unexpected hypervisor event %d\n", ev);
        atomic_inc((atomic_t *)&ev_err_count);
    }
    set_bit(ev, &HYPERVISOR_shared_info->events_mask);
}
