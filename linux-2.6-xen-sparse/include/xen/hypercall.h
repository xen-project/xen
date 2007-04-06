#ifndef __XEN_HYPERCALL_H__
#define __XEN_HYPERCALL_H__

#include <asm/hypercall.h>

static inline int
HYPERVISOR_multicall_check(
	multicall_entry_t *call_list, int nr_calls,
	const unsigned long *rc_list)
{
	int rc = HYPERVISOR_multicall(call_list, nr_calls);

	if (unlikely(rc < 0))
		return rc;
	BUG_ON(rc);

	for ( ; nr_calls > 0; --nr_calls, ++call_list)
		if (unlikely(call_list->result != (rc_list ? *rc_list++ : 0)))
			return nr_calls;

	return 0;
}

#endif /* __XEN_HYPERCALL_H__ */
