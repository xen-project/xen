#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <xen/cpumask.h>
#include <asm/current.h>
#endif

DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);

#define cpu_is_offline(cpu) unlikely(!cpu_online(cpu))

#define raw_smp_processor_id() (get_processor_id())

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
