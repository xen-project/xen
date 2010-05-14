#ifndef __XEN_CPU_H__
#define __XEN_CPU_H__

#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/notifier.h>

/* Safely access cpu_online_map, cpu_present_map, etc. */
bool_t get_cpu_maps(void);
void put_cpu_maps(void);

/* Safely perform CPU hotplug and update cpu_online_map, etc. */
bool_t cpu_hotplug_begin(void);
void cpu_hotplug_done(void);

/* Receive notification of CPU hotplug events. */
int register_cpu_notifier(struct notifier_block *nb);

/*
 * Possible event sequences for a given CPU:
 *  CPU_UP_PREPARE -> CPU_UP_CANCELLED        -- failed CPU up
 *  CPU_UP_PREPARE -> CPU_ONLINE              -- successful CPU up
 *  CPU_DOWN_PREPARE -> CPU_DOWN_FAILED       -- failed CPU down
 *  CPU_DOWN_PREPARE -> CPU_DYING -> CPU_DEAD -- successful CPU down
 * 
 * Hence note that only CPU_*_PREPARE handlers are allowed to fail. Also note
 * that once CPU_DYING is delivered, an offline action can no longer fail.
 */
#define CPU_UP_PREPARE   0x0002 /* CPU is coming up */
#define CPU_UP_CANCELED  0x0003 /* CPU is no longer coming up */
#define CPU_ONLINE       0x0004 /* CPU is up */
#define CPU_DOWN_PREPARE 0x0005 /* CPU is going down */
#define CPU_DOWN_FAILED  0x0006 /* CPU is no longer going down */
#define CPU_DYING        0x0007 /* CPU is nearly dead (in stop_machine ctxt) */
#define CPU_DEAD         0x0008 /* CPU is dead */

/* Perform CPU hotplug. May return -EAGAIN. */
int cpu_down(unsigned int cpu);
int cpu_up(unsigned int cpu);

/* Power management. */
int disable_nonboot_cpus(void);
void enable_nonboot_cpus(void);

/* Private arch-dependent helpers for CPU hotplug. */
int __cpu_up(unsigned int cpunum);
void __cpu_disable(void);
void __cpu_die(unsigned int cpu);

#endif /* __XEN_CPU_H__ */
