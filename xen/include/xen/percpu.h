#ifndef __XEN_PERCPU_H__
#define __XEN_PERCPU_H__

#define DECLARE_PER_CPU(type, name) \
    extern __typeof__(type) per_cpu__ ## name

#define __DEFINE_PER_CPU(attr, type, name) \
    attr __typeof__(type) per_cpu_ ## name

/*
 * Separate out the type, so (int[3], foo) works.
 *
 * The _##name concatenation is being used here to prevent 'name' from getting
 * macro expanded.
 */
#define DEFINE_PER_CPU(type, name) \
    __DEFINE_PER_CPU(__section(".bss.percpu"), type, _ ## name)

#define DEFINE_PER_CPU_PAGE_ALIGNED(type, name) \
    typedef char name ## _chk_t \
        [BUILD_BUG_ON_ZERO(__alignof(type) & (PAGE_SIZE - 1))]; \
    __DEFINE_PER_CPU(__section(".bss.percpu.page_aligned"), \
                     type, _ ## name)

#define DEFINE_PER_CPU_READ_MOSTLY(type, name) \
    __DEFINE_PER_CPU(__section(".bss.percpu.read_mostly"), type, _ ## name)

#define get_per_cpu_var(var)  (per_cpu__##var)

#include <asm/percpu.h>

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <asm/current.h>

#ifndef PARK_OFFLINE_CPUS_VAR
/*
 * Do we, for platform reasons, need to actually keep CPUs online when we
 * would otherwise prefer them to be off?
 */
#define park_offline_cpus false
#endif

extern unsigned long __per_cpu_offset[];

#define per_cpu(var, cpu)  \
    (*RELOC_HIDE(&per_cpu__##var, __per_cpu_offset[cpu]))

#define this_cpu(var) \
    (*RELOC_HIDE(&per_cpu__##var, get_per_cpu_offset()))

#define per_cpu_ptr(var, cpu)  \
    (*RELOC_HIDE(var, __per_cpu_offset[cpu]))
#define this_cpu_ptr(var) \
    (*RELOC_HIDE(var, get_per_cpu_offset()))

void percpu_init_areas(void);

#endif /* __ASSEMBLY__ */

/* Linux compatibility. */
#define get_cpu_var(var) this_cpu(var)
#define put_cpu_var(var)

#endif /* __XEN_PERCPU_H__ */
