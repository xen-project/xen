/**
 * Generic scheduler control interface.
 *
 * Mark Williamson, (C) 2004 Intel Research Cambridge
 */

#ifndef _SCHED_CTL_H_
#define _SCHED_CTL_H_

/**
 * When this file is changed, increment the version number.  This ensures that
 * tools will refuse to work (rather than causing a crash) when they're
 * out-of-sync with the Xen version number.
 */
#define SCHED_CTL_IF_VER 0x0001

/* scheduler types */
#define SCHED_BVT      0
#define SCHED_ATROPOS  1
#define SCHED_RROBIN   2

/* generic scheduler control command - union of all scheduler control
 * command structures */
struct sched_ctl_cmd
{
    unsigned int if_ver;
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
    unsigned int if_ver;
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

#endif /* _SCHED_CTL_H_ */
