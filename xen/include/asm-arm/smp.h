#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#ifndef __ASSEMBLY__
#include <xen/cpumask.h>
#include <xen/device_tree.h>
#include <asm/current.h>
#endif

DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);

#define cpu_is_offline(cpu) unlikely(!cpu_online(cpu))

#define raw_smp_processor_id() (get_processor_id())

extern void noreturn stop_cpu(void);

extern int arch_smp_init(void);
extern int arch_cpu_init(int cpu, struct dt_device_node *dn);
extern int arch_cpu_up(int cpu);

int cpu_up_send_sgi(int cpu);

/* Secondary CPU entry point */
extern void init_secondary(void);

extern void smp_init_cpus(void);
extern void smp_clear_cpu_maps (void);
extern int smp_get_max_cpus (void);
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
