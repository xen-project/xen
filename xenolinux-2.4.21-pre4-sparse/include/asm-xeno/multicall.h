/******************************************************************************
 * multicall.h
 */

#ifndef __MULTICALL_H__
#define __MULTICALL_H__

#include <asm/hypervisor.h>

extern multicall_entry_t multicall_list[];
extern int nr_multicall_ents;

static inline void queue_multicall0(unsigned long op)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall1(unsigned long op, unsigned long arg1)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall2(
    unsigned long op, unsigned long arg1, unsigned long arg2)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    nr_multicall_ents = i+1;
}

static inline void execute_multicall_list(void)
{
    if ( unlikely(nr_multicall_ents == 0) ) return;
    (void)HYPERVISOR_multicall(multicall_list, nr_multicall_ents);
    nr_multicall_ents = 0;
}

#endif /* __MULTICALL_H__ */
