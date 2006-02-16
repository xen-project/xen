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

extern void smp_send_event_check_mask(cpumask_t mask);
#define smp_send_event_check_cpu(cpu) \
    smp_send_event_check_mask(cpumask_of_cpu(cpu))

/*
 * Prepare machine for booting other CPUs.
 */
extern void smp_prepare_cpus(unsigned int max_cpus);

/*
 * Bring a CPU up
 */
extern int __cpu_up(unsigned int cpunum);

/*
 * Final polishing of CPUs
 */
extern void smp_cpus_done(unsigned int max_cpus);

/*
 * Call a function on all other processors
 */
extern int smp_call_function(
    void (*func) (void *info), void *info, int retry, int wait);

/*
 * Call a function on all processors
 */
static inline int on_each_cpu(void (*func) (void *info), void *info,
                              int retry, int wait)
{
    int ret = smp_call_function(func, info, retry, wait);
    func(info);
    return ret;
}

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

/*
 * Mark the boot cpu "online" so that it can call console drivers in
 * printk() and can access its per-cpu storage.
 */
void smp_prepare_boot_cpu(void);

#else

/*
 *	These macros fold the SMP functionality into a single CPU system
 */

#define smp_send_event_check_mask(m)            ((void)0)
#define smp_send_event_check_cpu(p)             ((void)0) 
#define raw_smp_processor_id()			0
#define hard_smp_processor_id()			0
#define smp_call_function(func,info,retry,wait)	({ do {} while (0); 0; })
#define on_each_cpu(func,info,retry,wait)	({ func(info); 0; })
#define num_booting_cpus()			1
#define smp_prepare_boot_cpu()			do {} while (0)

#endif

#define smp_processor_id() raw_smp_processor_id()

#endif
