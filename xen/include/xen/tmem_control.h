/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_TMEM_CONTROL_H__
#define __XEN_TMEM_CONTROL_H__

#ifdef CONFIG_TMEM
#include <public/sysctl.h>
/* Variables and functions that tmem_control.c needs from tmem.c */

extern struct tmem_statistics tmem_stats;
extern struct tmem_global tmem_global;

extern rwlock_t tmem_rwlock;

int tmem_evict(void);
int do_tmem_control(struct xen_sysctl_tmem_op *op);

struct client *client_create(domid_t cli_id);
int do_tmem_new_pool(domid_t this_cli_id, uint32_t d_poolid, uint32_t flags,
                     uint64_t uuid_lo, uint64_t uuid_hi);

int tmemc_shared_pool_auth(domid_t cli_id, uint64_t uuid_lo,
                           uint64_t uuid_hi, bool auth);
#endif /* CONFIG_TMEM */

#endif /* __XEN_TMEM_CONTROL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
