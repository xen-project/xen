#ifndef _XEN_COV_H
#define _XEN_COV_H

#ifdef CONFIG_COVERAGE
#include <public/sysctl.h>
int sysctl_cov_op(struct xen_sysctl_coverage_op *op);
#else
static inline int sysctl_cov_op(void *unused)
{
    return -EOPNOTSUPP;
}
#endif

#endif	/* _XEN_GCOV_H */
