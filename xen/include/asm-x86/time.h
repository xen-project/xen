
#ifndef __X86_TIME_H__
#define __X86_TIME_H__

#include <asm/msr.h>

/*
 *  PV TSC emulation modes:
 *    0 = guest rdtsc/p executed natively when monotonicity can be guaranteed
 *         and emulated otherwise (with frequency scaled if necessary)
 *    1 = guest rdtsc/p always emulated at 1GHz (kernel and user)
 *    2 = guest rdtsc always executed natively (no monotonicity/frequency
 *         guarantees); guest rdtscp emulated at native frequency if
 *         unsupported by h/w, else executed natively
 *    3 = same as 2, except xen manages TSC_AUX register so guest can
 *         determine when a restore/migration has occurred and assumes
 *         guest obtains/uses pvclock-like mechanism to adjust for
 *         monotonicity and frequency changes
 */
#define TSC_MODE_DEFAULT          0
#define TSC_MODE_ALWAYS_EMULATE   1
#define TSC_MODE_NEVER_EMULATE    2
#define TSC_MODE_PVRDTSCP         3

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

void pit_broadcast_enter(void);
void pit_broadcast_exit(void);
int pit_broadcast_is_available(void);

uint64_t acpi_pm_tick_to_ns(uint64_t ticks);
uint64_t ns_to_acpi_pm_tick(uint64_t ns);

void pv_soft_rdtsc(struct vcpu *v, struct cpu_user_regs *regs, int rdtscp);
u64 gtime_to_gtsc(struct domain *d, u64 tsc);

void tsc_set_info(struct domain *d, uint32_t tsc_mode, uint64_t elapsed_nsec,
                  uint32_t gtsc_khz, uint32_t incarnation);
   
void tsc_get_info(struct domain *d, uint32_t *tsc_mode, uint64_t *elapsed_nsec,
                  uint32_t *gtsc_khz, uint32_t *incarnation);
   

void force_update_vcpu_system_time(struct vcpu *v);

int host_tsc_is_safe(void);
void cpuid_time_leaf(uint32_t sub_idx, unsigned int *eax, unsigned int *ebx,
                      unsigned int *ecx, unsigned int *edx);

#endif /* __X86_TIME_H__ */
