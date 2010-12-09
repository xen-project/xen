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
void register_cpu_notifier(struct notifier_block *nb);

/*
 * Possible event sequences for a given CPU:
 *  CPU_UP_PREPARE -> CPU_UP_CANCELLED           -- failed CPU up
 *  CPU_UP_PREPARE -> CPU_STARTING -> CPU_ONLINE -- successful CPU up
 *  CPU_DOWN_PREPARE -> CPU_DOWN_FAILED          -- failed CPU down
 *  CPU_DOWN_PREPARE -> CPU_DYING -> CPU_DEAD    -- successful CPU down
 * 
 * Hence note that only CPU_*_PREPARE handlers are allowed to fail. Also note
 * that once CPU_DYING is delivered, an offline action can no longer fail.
 * 
 * Notifiers are called highest-priority-first when:
 *  (a) A CPU is coming up; or (b) CPU_DOWN_FAILED
 * Notifiers are called lowest-priority-first when:
 *  (a) A CPU is going down; or (b) CPU_UP_CANCELED
 */
/* CPU_UP_PREPARE: Preparing to bring CPU online. */
#define CPU_UP_PREPARE   (0x0001 | NOTIFY_FORWARD)
/* CPU_UP_CANCELED: CPU is no longer being brought online. */
#define CPU_UP_CANCELED  (0x0002 | NOTIFY_REVERSE)
/* CPU_STARTING: CPU nearly online. Runs on new CPU, irqs still disabled. */
#define CPU_STARTING     (0x0003 | NOTIFY_FORWARD)
/* CPU_ONLINE: CPU is up. */
#define CPU_ONLINE       (0x0004 | NOTIFY_FORWARD)
/* CPU_DOWN_PREPARE: CPU is going down. */
#define CPU_DOWN_PREPARE (0x0005 | NOTIFY_REVERSE)
/* CPU_DOWN_FAILED: CPU is no longer going down. */
#define CPU_DOWN_FAILED  (0x0006 | NOTIFY_FORWARD)
/* CPU_DYING: CPU is nearly dead (in stop_machine context). */
#define CPU_DYING        (0x0007 | NOTIFY_REVERSE)
/* CPU_DEAD: CPU is dead. */
#define CPU_DEAD         (0x0008 | NOTIFY_REVERSE)

/* Perform CPU hotplug. May return -EAGAIN. */
int cpu_down(unsigned int cpu);
int cpu_up(unsigned int cpu);

/* From arch code, send CPU_STARTING notification. */
void notify_cpu_starting(unsigned int cpu);

/* Power management. */
int disable_nonboot_cpus(void);
void enable_nonboot_cpus(void);

/* Private arch-dependent helpers for CPU hotplug. */
int __cpu_up(unsigned int cpunum);
void __cpu_disable(void);
void __cpu_die(unsigned int cpu);

#endif /* __XEN_CPU_H__ */
