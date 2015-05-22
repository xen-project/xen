#ifndef __ASM_X86_CPUIDLE_H__
#define __ASM_X86_CPUIDLE_H__

#include <xen/cpuidle.h>
#include <xen/notifier.h>
#include <xen/sched.h>
#include <xen/sched-if.h>

extern struct acpi_processor_power *processor_powers[];

extern void (*pm_idle_save)(void);

bool_t lapic_timer_init(void);
extern void (*lapic_timer_off)(void);
extern void (*lapic_timer_on)(void);

extern uint64_t (*cpuidle_get_tick)(void);

int mwait_idle_init(struct notifier_block *);
int cpuidle_init_cpu(unsigned int cpu);
void default_dead_idle(void);
void acpi_dead_idle(void);
void trace_exit_reason(u32 *irq_traced);
void update_idle_stats(struct acpi_processor_power *,
                       struct acpi_processor_cx *, uint64_t, uint64_t);
void update_last_cx_stat(struct acpi_processor_power *,
                         struct acpi_processor_cx *, uint64_t);

/*
 * vcpu is urgent if vcpu is polling event channel
 *
 * if urgent vcpu exists, CPU should not enter deep C state
 */
static inline int sched_has_urgent_vcpu(void)
{
    return atomic_read(&this_cpu(schedule_data).urgent_count);
}

#endif /* __X86_ASM_CPUIDLE_H__ */
