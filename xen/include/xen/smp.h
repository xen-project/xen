#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

/*
 *	Generic SMP support
 *		Alan Cox. <alan@redhat.com>
 */

#include <xen/config.h>

#ifdef CONFIG_SMP

#include <asm/smp.h>

/*
 * main cross-CPU interfaces, handles INIT, TLB flush, STOP, etc.
 * (defined in asm header):
 */ 

/*
 * stops all CPUs but the current one:
 */
extern void smp_send_stop(void);

extern void smp_send_event_check_mask(unsigned long cpu_mask);
#define smp_send_event_check_cpu(_cpu) smp_send_event_check_mask(1<<(_cpu))

/*
 * Boot processor call to load the other CPU's
 */
extern void smp_boot_cpus(void);

/*
 * Processor call in. Must hold processors until ..
 */
extern void smp_callin(void);

/*
 * Multiprocessors may now schedule
 */
extern void smp_commence(void);

/*
 * Call a function on all other processors
 */
extern int smp_call_function (void (*func) (void *info), void *info,
			      int retry, int wait);

/*
 * True once the per process idle is forked
 */
extern int smp_threads_ready;

extern int smp_num_cpus;
extern int ht_per_core;
extern int opt_noht;

extern volatile unsigned long smp_msg_data;
extern volatile int smp_src_cpu;
extern volatile int smp_msg_id;

#define MSG_ALL_BUT_SELF	0x8000	/* Assume <32768 CPU's */
#define MSG_ALL			0x8001

#define MSG_INVALIDATE_TLB	0x0001	/* Remote processor TLB invalidate */
#define MSG_STOP_CPU		0x0002	/* Sent to shut down slave CPU's
					 * when rebooting
					 */
#define MSG_RESCHEDULE		0x0003	/* Reschedule request from master CPU*/
#define MSG_CALL_FUNCTION       0x0004  /* Call function on all other CPUs */

#else

/*
 *	These macros fold the SMP functionality into a single CPU system
 */

#define smp_send_event_check_mask(_m)           ((void)0)
#define smp_send_event_check_cpu(_p)            ((void)0) 
#define smp_num_cpus				1
#define smp_processor_id()			0
#define hard_smp_processor_id()			0
#define smp_threads_ready			1
#define kernel_lock()
#define cpu_logical_map(cpu)			0
#define cpu_number_map(cpu)			0
#define smp_call_function(func,info,retry,wait)	({ 0; })
#define cpu_online_map				1

#endif
#endif
