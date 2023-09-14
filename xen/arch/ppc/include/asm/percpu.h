#ifndef __PPC_PERCPU_H__
#define __PPC_PERCPU_H__

#ifndef __ASSEMBLY__

extern char __per_cpu_start[], __per_cpu_data_end[];
extern unsigned long __per_cpu_offset[NR_CPUS];
void percpu_init_areas(void);

#define smp_processor_id() 0 /* TODO: Fix this */

#define per_cpu(var, cpu)  \
    (*RELOC_HIDE(&per_cpu__##var, __per_cpu_offset[cpu]))
#define this_cpu(var) \
    (*RELOC_HIDE(&per_cpu__##var, smp_processor_id()))

#define per_cpu_ptr(var, cpu)  \
    (*RELOC_HIDE(var, __per_cpu_offset[cpu]))
#define this_cpu_ptr(var) \
    (*RELOC_HIDE(var, smp_processor_id()))

#endif

#endif /* __PPC_PERCPU_H__ */
