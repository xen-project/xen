/*
 *	Intel SMP support routines.
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998-99, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 */

//#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/spinlock.h>
#include <asm/smp.h>
//#include <asm/mc146818rtc.h>
#include <asm/pgalloc.h>
//#include <asm/smpboot.h>
#include <asm/hardirq.h>


//Huh? This seems to be used on ia64 even if !CONFIG_SMP
void flush_tlb_mask(unsigned long mask)
{
	dummy();
}
//#if CONFIG_SMP || IA64
#if CONFIG_SMP
//Huh? This seems to be used on ia64 even if !CONFIG_SMP
void smp_send_event_check_mask(unsigned long cpu_mask)
{
	dummy();
	//send_IPI_mask(cpu_mask, EVENT_CHECK_VECTOR);
}


//Huh? This seems to be used on ia64 even if !CONFIG_SMP
int try_flush_tlb_mask(unsigned long mask)
{
	dummy();
	return 1;
}
#endif
