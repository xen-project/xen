#include <xen/bitops.h>
#include <xen/init.h>
#include <asm/processor.h>
#include "cpu.h"

static void init_shanghai(struct cpuinfo_x86 *c)
{
    if ( cpu_has(c, X86_FEATURE_ITSC) )
    {
        __set_bit(X86_FEATURE_CONSTANT_TSC, c->x86_capability);
        __set_bit(X86_FEATURE_NONSTOP_TSC, c->x86_capability);
        __set_bit(X86_FEATURE_TSC_RELIABLE, c->x86_capability);
    }

    init_intel_cacheinfo(c);
}

const struct cpu_dev shanghai_cpu_dev = {
    .c_init     = init_shanghai,
};
