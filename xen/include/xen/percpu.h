#ifndef __XEN_PERCPU_H__
#define __XEN_PERCPU_H__

#include <asm/percpu.h>

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

/* Linux compatibility. */
#define get_cpu_var(var) this_cpu(var)
#define put_cpu_var(var)

#endif /* __XEN_PERCPU_H__ */
