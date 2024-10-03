#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#ifndef __ASSEMBLY__
#include <xen/percpu.h>
#include <xen/cpumask.h>
#include <asm/current.h>
#endif

extern struct init_info init_data;
extern unsigned long smp_up_cpu;

DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);

extern void noreturn stop_cpu(void);

extern int arch_smp_init(void);

struct dt_device_node;

extern int arch_cpu_init(int cpu, struct dt_device_node *dn);
extern int arch_cpu_up(int cpu);
extern void arch_cpu_up_finish(void);

int cpu_up_send_sgi(int cpu);

/* Secondary CPU entry point */
extern void init_secondary(void);

extern void smp_init_cpus(void);
extern void smp_clear_cpu_maps (void);
extern unsigned int smp_get_max_cpus(void);

#define cpu_physical_id(cpu) cpu_logical_map(cpu)

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
