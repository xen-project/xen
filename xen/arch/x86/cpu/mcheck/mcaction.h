#ifndef _MCHECK_ACTION_H
#define _MCHECK_ACTION_H

#include <xen/types.h>
#include "x86_mca.h"

void
mc_memerr_dhandler(struct mca_binfo *binfo,
                   enum mce_result *result,
                   const struct cpu_user_regs *regs);

#define MC_ADDR_PHYSICAL  0
#define MC_ADDR_VIRTUAL   1

typedef int (*mce_check_addr_t)(uint64_t status, uint64_t misc, int addr_type);
extern void mce_register_addrcheck(mce_check_addr_t);

extern mce_check_addr_t mc_check_addr;

#endif
