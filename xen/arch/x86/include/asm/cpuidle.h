#ifndef __ASM_X86_CPUIDLE_H__
#define __ASM_X86_CPUIDLE_H__

#include <xen/cpuidle.h>
#include <xen/notifier.h>
#include <xen/sched.h>

extern struct acpi_processor_power *processor_powers[];

extern void (*pm_idle_save)(void);

bool lapic_timer_init(void);
extern void (*lapic_timer_off)(void);
extern void (*lapic_timer_on)(void);

extern uint64_t (*cpuidle_get_tick)(void);

#ifdef CONFIG_INTEL
int mwait_idle_init(struct notifier_block *nfb);
#else
static inline int mwait_idle_init(struct notifier_block *nfb)
{
    return -ENODEV;
}
#endif
int cpuidle_init_cpu(unsigned int cpu);
void cf_check default_dead_idle(void);
void cf_check acpi_dead_idle(void);
void play_dead(void);
void trace_exit_reason(u32 *irq_traced);
void update_idle_stats(struct acpi_processor_power *power,
                       struct acpi_processor_cx *cx,
                       uint64_t before, uint64_t after);
void update_last_cx_stat(struct acpi_processor_power *power,
                         struct acpi_processor_cx *cx, uint64_t ticks);

bool errata_c6_workaround(void);

#endif /* __X86_ASM_CPUIDLE_H__ */
