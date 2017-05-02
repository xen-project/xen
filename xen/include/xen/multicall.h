/******************************************************************************
 * multicall.h
 */

#ifndef __XEN_MULTICALL_H__
#define __XEN_MULTICALL_H__

#include <xen/percpu.h>
#ifdef CONFIG_COMPAT
#include <compat/xen.h>
#endif

#define _MCSF_in_multicall   0
#define MCSF_in_multicall    (1<<_MCSF_in_multicall)
struct mc_state {
    unsigned long flags;
    union {
        struct multicall_entry call;
#ifdef CONFIG_COMPAT
        struct compat_multicall_entry compat_call;
#endif
    };
};

enum mc_disposition {
    mc_continue,
    mc_exit,
    mc_preempt,
} arch_do_multicall_call(struct mc_state *mc);

#endif /* __XEN_MULTICALL_H__ */
