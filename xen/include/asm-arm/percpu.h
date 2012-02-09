#ifndef __ARM_PERCPU_H__
#define __ARM_PERCPU_H__

#ifndef __ASSEMBLY__
extern char __per_cpu_start[], __per_cpu_data_end[];
extern unsigned long __per_cpu_offset[NR_CPUS];
void percpu_init_areas(void);
#endif

/* Separate out the type, so (int[3], foo) works. */
#define __DEFINE_PER_CPU(type, name, suffix)                    \
    __attribute__((__section__(".bss.percpu" #suffix)))         \
    __typeof__(type) per_cpu_##name

#define per_cpu(var, cpu) ((&per_cpu__##var)[cpu?0:0])
#define __get_cpu_var(var) per_cpu__##var

#define DECLARE_PER_CPU(type, name) extern __typeof__(type) per_cpu__##name

#endif /* __ARM_PERCPU_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
