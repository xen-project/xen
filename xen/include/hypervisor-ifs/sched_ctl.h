/**
 * Generic scheduler control interface.
 *
 * Mark Williamson, (C) 2004 Intel Research Cambridge
 */

#ifndef __SCHED_CTL_H__
#define __SCHED_CTL_H__

/* Scheduler types. */
#define SCHED_BVT      0
#define SCHED_ATROPOS  1
#define SCHED_RROBIN   2

/*
 * Generic scheduler control command: union of all scheduler control command
 * structures.
 */
struct sched_ctl_cmd
{
    unsigned int sched_id;
    
    union
    {
        struct bvt_ctl
        {
            /* IN variables. */
            unsigned long ctx_allow;  /* context switch allowance */
        } bvt;

        struct rrobin_ctl
        {
            /* IN variables */
            u64 slice;                /* round robin time slice */
        } rrobin;
    } u;
};

struct sched_adjdom_cmd
{
    unsigned int sched_id;
    domid_t domain;
    
    union
    {
        struct bvt_adjdom
        {
            unsigned long mcu_adv;    /* mcu advance: inverse of weight */
            unsigned long warp;       /* time warp */
            unsigned long warpl;      /* warp limit */
            unsigned long warpu;      /* unwarp time requirement */
        } bvt;

        struct atropos_adjdom
        {
            int xtratime;
        } atropos;
    } u;
};

#endif /* __SCHED_CTL_H__ */
