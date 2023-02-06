
#ifndef __X86_TIME_H__
#define __X86_TIME_H__

#include <asm/msr.h>

typedef u64 cycles_t;

extern bool disable_tsc_sync;

static inline cycles_t get_cycles(void)
{
    return rdtsc_ordered();
}

unsigned long
mktime (unsigned int year, unsigned int mon,
        unsigned int day, unsigned int hour,
        unsigned int min, unsigned int sec);

int time_suspend(void);
int time_resume(void);

void init_percpu_time(void);
void time_latch_stamps(void);

struct ioreq;
int hwdom_pit_access(struct ioreq *ioreq);

int cpu_frequency_change(u64 freq);

void cf_check pit_broadcast_enter(void);
void cf_check pit_broadcast_exit(void);
int pit_broadcast_is_available(void);

uint64_t cf_check acpi_pm_tick_to_ns(uint64_t ticks);

uint64_t tsc_ticks2ns(uint64_t ticks);

uint64_t pv_soft_rdtsc(const struct vcpu *v, const struct cpu_user_regs *regs);
uint64_t gtime_to_gtsc(const struct domain *d, uint64_t time);
uint64_t gtsc_to_gtime(const struct domain *d, uint64_t tsc);

int tsc_set_info(struct domain *d, uint32_t tsc_mode, uint64_t elapsed_nsec,
                 uint32_t gtsc_khz, uint32_t incarnation);

void tsc_get_info(struct domain *d, uint32_t *tsc_mode, uint64_t *elapsed_nsec,
                  uint32_t *gtsc_khz, uint32_t *incarnation);
   

void force_update_vcpu_system_time(struct vcpu *v);

bool clocksource_is_tsc(void);
int host_tsc_is_safe(void);
u64 stime2tsc(s_time_t stime);

struct time_scale;
void set_time_scale(struct time_scale *ts, u64 ticks_per_sec);
u64 scale_delta(u64 delta, const struct time_scale *scale);

#endif /* __X86_TIME_H__ */
