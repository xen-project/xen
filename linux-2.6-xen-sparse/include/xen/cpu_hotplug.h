#ifndef __XEN_CPU_HOTPLUG_H__
#define __XEN_CPU_HOTPLUG_H__

#include <linux/kernel.h>
#include <linux/cpumask.h>

#if defined(CONFIG_X86) && defined(CONFIG_SMP)
extern cpumask_t cpu_initialized_map;
#define cpu_set_initialized(cpu) cpu_set(cpu, cpu_initialized_map)
#else
#define cpu_set_initialized(cpu) ((void)0)
#endif

#if defined(CONFIG_HOTPLUG_CPU)

int cpu_up_check(unsigned int cpu);
void init_xenbus_allowed_cpumask(void);
int smp_suspend(void);
void smp_resume(void);

void cpu_bringup(void);

#else /* !defined(CONFIG_HOTPLUG_CPU) */

#define cpu_up_check(cpu)		(0)
#define init_xenbus_allowed_cpumask()	((void)0)

static inline int smp_suspend(void)
{
	if (num_online_cpus() > 1) {
		printk(KERN_WARNING "Can't suspend SMP guests "
		       "without CONFIG_HOTPLUG_CPU\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

static inline void smp_resume(void)
{
}

#endif /* !defined(CONFIG_HOTPLUG_CPU) */

#endif /* __XEN_CPU_HOTPLUG_H__ */
