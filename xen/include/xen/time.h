/******************************************************************************
 * time.h
 * 
 * Copyright (c) 2002-2003 Rolf Neugebauer
 * Copyright (c) 2002-2005 K A Fraser
 */

#ifndef __XEN_TIME_H__
#define __XEN_TIME_H__

#include <xen/types.h>
#include <public/xen.h>

extern int init_xen_time(void);
extern void cstate_restore_tsc(void);

extern unsigned long cpu_khz;
extern unsigned long pit0_ticks;

struct domain;
struct vcpu;

/*
 * System Time
 * 64 bit value containing the nanoseconds elapsed since boot time.
 * This value is adjusted by frequency drift.
 * NOW() returns the current time.
 * The other macros are for convenience to approximate short intervals
 * of real time into system time 
 */

typedef int64_t s_time_t;
#define PRI_stime PRId64

s_time_t get_s_time_fixed(u64 at_tick);
s_time_t get_s_time(void);
unsigned long get_localtime(struct domain *d);
uint64_t get_localtime_us(struct domain *d);
unsigned long get_sec(void);

struct tm {
    int     tm_sec;         /* seconds */
    int     tm_min;         /* minutes */
    int     tm_hour;        /* hours */
    int     tm_mday;        /* day of the month */
    int     tm_mon;         /* month */
    int     tm_year;        /* year */
    int     tm_wday;        /* day of the week */
    int     tm_yday;        /* day in the year */
    int     tm_isdst;       /* daylight saving time */
};
struct tm gmtime(unsigned long t);
struct tm wallclock_time(uint64_t *ns);

#define SYSTEM_TIME_HZ  1000000000ULL
#define NOW()           get_s_time()
#define DAYS(_d)        SECONDS((_d) * 86400ULL)
#define SECONDS(_s)     ((s_time_t)((_s)  * 1000000000ULL))
#define MILLISECS(_ms)  ((s_time_t)((_ms) * 1000000ULL))
#define MICROSECS(_us)  ((s_time_t)((_us) * 1000ULL))
#define STIME_MAX ((s_time_t)((uint64_t)~0ULL>>1))
/* Chosen so (NOW() + delta) wont overflow without an uptime of 200 years */
#define STIME_DELTA_MAX ((s_time_t)((uint64_t)~0ULL>>2))

/* Explicitly OR with 1 just in case version number gets out of sync. */
#define version_update_begin(v) (((v) + 1) | 1)
#define version_update_end(v)   ((v) + 1)
extern void update_vcpu_system_time(struct vcpu *v);
extern void update_domain_wallclock_time(struct domain *d);

extern void do_settime(
    u64 secs, unsigned int nsecs, u64 system_time_base);

extern void send_timer_event(struct vcpu *v);

void domain_set_time_offset(struct domain *d, int64_t time_offset_seconds);

#include <asm/time.h>

#endif /* __XEN_TIME_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
