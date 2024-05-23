
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

/* Programmable Interval Timer (8254) */

/* Timer Control Word */
#define PIT_TCW_CH(n)         ((n) << 6)
/* Lower bits also Timer Status. */
#define PIT_RW_MSB            (1 << 5)
#define PIT_RW_LSB            (1 << 4)
#define PIT_RW_LSB_MSB        (PIT_RW_LSB | PIT_RW_MSB)
#define PIT_MODE_EOC          (0 << 1)
#define PIT_MODE_ONESHOT      (1 << 1)
#define PIT_MODE_RATE_GEN     (2 << 1)
#define PIT_MODE_SQUARE_WAVE  (3 << 1)
#define PIT_MODE_SW_STROBE    (4 << 1)
#define PIT_MODE_HW_STROBE    (5 << 1)
#define PIT_BINARY            (0 << 0)
#define PIT_BCD               (1 << 0)

/* Read Back Command */
#define PIT_RDB               PIT_TCW_CH(3)
#define PIT_RDB_NO_COUNT      (1 << 5)
#define PIT_RDB_NO_STATUS     (1 << 4)
#define PIT_RDB_CH2           (1 << 3)
#define PIT_RDB_CH1           (1 << 2)
#define PIT_RDB_CH0           (1 << 1)
#define PIT_RDB_RSVD          (1 << 0)

/* Counter Latch Command */
#define PIT_LTCH_CH(n)        PIT_TCW_CH(n)

/* Timer Status */
#define PIT_STATUS_OUT_PIN    (1 << 7)
#define PIT_STATUS_NULL_COUNT (1 << 6)
/* Lower bits match Timer Control Word. */

#endif /* __X86_TIME_H__ */
