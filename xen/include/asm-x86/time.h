
#ifndef __X86_TIME_H__
#define __X86_TIME_H__

#include <asm/msr.h>

void calibrate_tsc_bp(void);
void calibrate_tsc_ap(void);

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

int time_suspend(void);
int time_resume(void);

void init_percpu_time(void);

struct ioreq;
int dom0_pit_access(struct ioreq *ioreq);

int cpu_frequency_change(u64 freq);

struct tm;
struct tm wallclock_time(void);

#endif /* __X86_TIME_H__ */
