#ifndef __ASM_RANDOM_H__
#define __ASM_RANDOM_H__

#include <asm/processor.h>

static inline unsigned int arch_get_random(void)
{
    unsigned int val = 0;

    if ( cpu_has(&current_cpu_data, X86_FEATURE_RDRAND) )
        asm volatile ( "rdrand %0" : "=r" (val) );

    return val;
}

#endif /* __ASM_RANDOM_H__ */
