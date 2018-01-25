#ifndef _XEN_COV_PRIV_H
#define _XEN_COV_PRIV_H

#include <xen/types.h>

struct cov_sysctl_ops {
    uint32_t (*get_size)(void);
    void     (*reset_counters)(void);
    int      (*dump)(XEN_GUEST_HANDLE_PARAM(char), uint32_t *);
};
extern const struct cov_sysctl_ops cov_ops;

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
