#ifndef _XEN_IA64_TIME_H
#define _XEN_IA64_TIME_H

#include <asm/linux/time.h>
#include <asm/timex.h>

extern unsigned long itc_scale;
extern unsigned long ns_scale;

/* We don't expect an absolute cycle value here, since then no way
 * to prevent overflow for large norminator. Normally this conversion
 * is used for relative offset.
 */
static inline u64
cycle_to_ns(u64 cycle)
{
    return (cycle * itc_scale) >> 32;
}

static inline u64
ns_to_cycle(u64 ns)
{
    return (ns * ns_scale) >> 32;
}

#endif /* _XEN_IA64_TIME_H */
