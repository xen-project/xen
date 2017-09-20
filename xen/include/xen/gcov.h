#ifndef _XEN_GCOV_H
#define _XEN_GCOV_H

#ifdef CONFIG_GCOV
#include <public/sysctl.h>
int sysctl_gcov_op(struct xen_sysctl_gcov_op *op);
#endif

#endif	/* _XEN_GCOV_H */
