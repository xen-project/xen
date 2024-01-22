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

#endif
