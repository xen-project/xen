#ifndef __XEN_SMP_H__
#define __XEN_SMP_H__

#include <asm/smp.h>

/*
 * stops all CPUs but the current one:
 */
extern void smp_send_stop(void);

extern void smp_send_event_check_mask(const cpumask_t *mask);
#define smp_send_event_check_cpu(cpu) \
    smp_send_event_check_mask(cpumask_of(cpu))

extern void smp_send_state_dump(unsigned int cpu);

/*
 * Prepare machine for booting other CPUs.
 */
extern void smp_prepare_cpus(unsigned int max_cpus);

/*
 * Final polishing of CPUs
 */
extern void smp_cpus_done(void);

/*
 * Call a function on all other processors
 */
extern void smp_call_function(
    void (*func) (void *info),
    void *info,
    int wait);

/* 
 * Call a function on a selection of processors
 */
extern void on_selected_cpus(
    const cpumask_t *selected,
    void (*func) (void *info),
    void *info,
    int wait);

/*
 * Mark the boot cpu "online" so that it can call console drivers in
 * printk() and can access its per-cpu storage.
 */
void smp_prepare_boot_cpu(void);

/*
 * Call a function on all processors
 */
static inline void on_each_cpu(
    void (*func) (void *info),
    void *info,
    int wait)
{
    on_selected_cpus(&cpu_online_map, func, info, wait);
}

/*
 * Call a function on the current CPU
 */
void smp_call_function_interrupt(void);

void smp_send_call_function_mask(const cpumask_t *mask);

#define smp_processor_id() raw_smp_processor_id()

int alloc_cpu_id(void);

extern void *stack_base[NR_CPUS];

#endif /* __XEN_SMP_H__ */
