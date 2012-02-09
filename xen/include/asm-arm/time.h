#ifndef __ARM_TIME_H__
#define __ARM_TIME_H__

typedef unsigned long cycles_t;

static inline cycles_t get_cycles (void)
{
        return 0;
}

struct tm;
struct tm wallclock_time(void);


/* Set up the timer interrupt on this CPU */
extern void __cpuinit init_timer_interrupt(void);

#endif /* __ARM_TIME_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
