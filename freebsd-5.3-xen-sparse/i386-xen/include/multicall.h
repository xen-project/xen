/******************************************************************************
 * multicall.h
 */

#ifndef __MULTICALL_H__
#define __MULTICALL_H__

#include <machine/hypervisor.h>
#define MAX_MULTICALL_ENTS 8
extern multicall_entry_t multicall_list[];
extern int nr_multicall_ents;

static inline void execute_multicall_list(void)
{
    if ( unlikely(nr_multicall_ents == 0) ) return;
    (void)HYPERVISOR_multicall(multicall_list, nr_multicall_ents);
    nr_multicall_ents = 0;
}


static inline void handle_edge(void)
{
    if (unlikely(nr_multicall_ents == MAX_MULTICALL_ENTS)) 
	execute_multicall_list();
}

static inline void queue_multicall0(unsigned long op)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    nr_multicall_ents = i+1;
    handle_edge();
}

static inline void queue_multicall1(unsigned long op, unsigned long arg1)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    nr_multicall_ents = i+1;
    handle_edge();
}

static inline void queue_multicall2(
    unsigned long op, unsigned long arg1, unsigned long arg2)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    nr_multicall_ents = i+1;
    handle_edge();
}

static inline void queue_multicall3(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    multicall_list[i].args[2] = arg3;
    nr_multicall_ents = i+1;
    handle_edge();
}

static inline void queue_multicall4(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    multicall_list[i].args[2] = arg3;
    multicall_list[i].args[3] = arg4;
    nr_multicall_ents = i+1;
    handle_edge();
}

static inline void queue_multicall5(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    multicall_list[i].args[2] = arg3;
    multicall_list[i].args[3] = arg4;
    multicall_list[i].args[4] = arg5;
    nr_multicall_ents = i+1;
    handle_edge();
}


#endif /* __MULTICALL_H__ */
