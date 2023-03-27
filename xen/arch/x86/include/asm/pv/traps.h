/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pv/traps.h
 *
 * PV guest traps interface definitions
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 */

#ifndef __X86_PV_TRAPS_H__
#define __X86_PV_TRAPS_H__

#ifdef CONFIG_PV

#include <public/xen.h>

void pv_trap_init(void);

int pv_raise_nmi(struct vcpu *v);

int pv_emulate_privileged_op(struct cpu_user_regs *regs);
void pv_emulate_gate_op(struct cpu_user_regs *regs);
bool pv_emulate_invalid_op(struct cpu_user_regs *regs);

static inline bool pv_trap_callback_registered(const struct vcpu *v,
                                               uint8_t vector)
{
    return v->arch.pv.trap_ctxt[vector].address;
}

#else  /* !CONFIG_PV */

#include <xen/errno.h>

static inline void pv_trap_init(void) {}

static inline int pv_raise_nmi(struct vcpu *v) { return -EOPNOTSUPP; }

static inline int pv_emulate_privileged_op(struct cpu_user_regs *regs) { return 0; }
static inline void pv_emulate_gate_op(struct cpu_user_regs *regs) {}
static inline bool pv_emulate_invalid_op(struct cpu_user_regs *regs) { return true; }

static inline bool pv_trap_callback_registered(const struct vcpu *v,
                                               uint8_t vector)
{
    return false;
}
#endif /* CONFIG_PV */

#endif /* __X86_PV_TRAPS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
