/******************************************************************************
 * multicall.h
 */

#ifndef __XEN_MULTICALL_H__
#define __XEN_MULTICALL_H__

#include <asm/multicall.h>

#define _MCSF_in_multicall   0
#define _MCSF_call_preempted 1
#define MCSF_in_multicall    (1<<_MCSF_in_multicall)
#define MCSF_call_preempted  (1<<_MCSF_call_preempted)
struct mc_state {
    unsigned long flags;
    struct multicall_entry call;
} __cacheline_aligned;

extern struct mc_state mc_state[NR_CPUS];

#endif /* __XEN_MULTICALL_H__ */
