/**
 * @file op_counter.h
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 */
 
#ifndef OP_COUNTER_H
#define OP_COUNTER_H
 
#define OP_MAX_COUNTER 8
 
/* Per-perfctr configuration as set via
 * oprofilefs.
 */
struct op_counter_config {
        unsigned long count;
        unsigned long enabled;
        unsigned long event;
        unsigned long kernel;
        unsigned long user;
        unsigned long unit_mask;
};

extern struct op_counter_config counter_config[];

/* AMD IBS configuration */
struct op_ibs_config {
    unsigned long op_enabled;
    unsigned long fetch_enabled;
    unsigned long max_cnt_fetch;
    unsigned long max_cnt_op;
    unsigned long rand_en;
    unsigned long dispatched_ops;
};

extern struct op_ibs_config ibs_config;

#endif /* OP_COUNTER_H */
