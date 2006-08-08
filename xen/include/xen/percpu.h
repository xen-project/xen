#ifndef __XEN_PERCPU_H__
#define __XEN_PERCPU_H__

#include <xen/config.h>
#include <asm/percpu.h>

/* Preferred on Xen. Also see arch-defined per_cpu(). */
#define this_cpu(var)    __get_cpu_var(var)

/* Linux compatibility. */
#define get_cpu_var(var) this_cpu(var)
#define put_cpu_var(var)

#endif /* __XEN_PERCPU_H__ */
