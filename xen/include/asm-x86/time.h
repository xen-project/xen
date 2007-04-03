
#ifndef __X86_TIME_H__
#define __X86_TIME_H__

#include <asm/msr.h>

extern void calibrate_tsc_bp(void);
extern void calibrate_tsc_ap(void);

typedef u64 cycles_t;

static inline cycles_t get_cycles(void)
{
    cycles_t c;
    rdtscll(c);
    return c;
}

unsigned long
mktime (unsigned int year, unsigned int mon,
        unsigned int day, unsigned int hour,
        unsigned int min, unsigned int sec);

#endif /* __X86_TIME_H__ */
