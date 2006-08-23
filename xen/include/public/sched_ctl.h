/******************************************************************************
 * Generic scheduler control interface.
 *
 * Mark Williamson, (C) 2004 Intel Research Cambridge
 */

#ifndef __XEN_PUBLIC_SCHED_CTL_H__
#define __XEN_PUBLIC_SCHED_CTL_H__

/* Scheduler types. */
#define SCHED_SEDF     4
#define SCHED_CREDIT   5

/* Set or get info? */
#define SCHED_INFO_PUT 0
#define SCHED_INFO_GET 1

/*
 * Generic scheduler control command - used to adjust system-wide scheduler
 * parameters
 */
struct sched_ctl_cmd {
    uint32_t sched_id;
    uint32_t direction;
};

struct sched_adjdom_cmd {
    uint32_t sched_id;
    uint32_t direction;
    domid_t  domain;
    union {
        struct sedf_adjdom {
            uint64_t period;
            uint64_t slice;
            uint64_t latency;
            uint32_t extratime;
            uint32_t weight;
        } sedf;
        struct sched_credit_adjdom {
            uint16_t weight;
            uint16_t cap;
        } credit;
    } u;
};

#endif /* __XEN_PUBLIC_SCHED_CTL_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
