#ifndef __ASM_IA64_MULTICALL_H__
#define __ASM_IA64_MULTICALL_H__

#include <public/xen.h>

typedef unsigned long (*hypercall_t)(
			unsigned long arg0,
			unsigned long arg1,
			unsigned long arg2,
			unsigned long arg3,
			unsigned long arg4,
			unsigned long arg5);

extern hypercall_t ia64_hypercall_table[];

static inline void do_multicall_call(multicall_entry_t *call)
{
	call->result = (*ia64_hypercall_table[call->op])(
			call->args[0],
			call->args[1],
			call->args[2],
			call->args[3],
			call->args[4],
			call->args[5]);
}

#endif /* __ASM_IA64_MULTICALL_H__ */
