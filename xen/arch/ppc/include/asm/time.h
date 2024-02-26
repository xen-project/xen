/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_TIME_H__
#define __ASM_PPC_TIME_H__

#include <xen/bug.h>
#include <asm/processor.h>
#include <asm/regs.h>

struct vcpu;

/* TODO: implement */
static inline void force_update_vcpu_system_time(struct vcpu *v) {
    BUG_ON("unimplemented");
}

typedef unsigned long cycles_t;

static inline cycles_t get_cycles(void)
{
    return mfspr(SPRN_TBRL);
}

#endif /* __ASM_PPC_TIME_H__ */
