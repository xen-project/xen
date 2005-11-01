
#ifndef __X86_TIME_H__
#define __X86_TIME_H__

#include <asm/msr.h>

extern int timer_ack;

extern void calibrate_tsc_bp(void);
extern void calibrate_tsc_ap(void);

struct domain;
extern void init_domain_time(struct domain *d);

typedef u64 cycles_t;

static inline cycles_t get_cycles(void)
{
    cycles_t c;
    rdtscll(c);
    return c;
}

#endif /* __X86_TIME_H__ */
