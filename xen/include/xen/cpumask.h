/*
 * XXX This to be replaced with the Linux file in the near future.
 */

#ifndef __XEN_CPUMASK_H__
#define __XEN_CPUMASK_H__

#include <xen/bitmap.h>

typedef u32 cpumask_t;

extern cpumask_t cpu_online_map;

static inline int cpus_weight(cpumask_t w)
{
    unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
    res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
    res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
    res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
    return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

#define cpus_addr(_m) (&(_m))

#endif /* __XEN_CPUMASK_H__ */
