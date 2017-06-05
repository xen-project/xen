/*
 * pv/traps.h
 *
 * PV guest traps interface definitions
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __X86_PV_TRAPS_H__
#define __X86_PV_TRAPS_H__

#ifdef CONFIG_PV

#include <public/xen.h>

void pv_trap_init(void);

/* Deliver interrupt to PV guest. Return 0 on success. */
int pv_raise_interrupt(struct vcpu *v, uint8_t vector);

int pv_emulate_privileged_op(struct cpu_user_regs *regs);
void pv_emulate_gate_op(struct cpu_user_regs *regs);
bool pv_emulate_invalid_op(struct cpu_user_regs *regs);

static inline bool pv_trap_callback_registered(const struct vcpu *v,
                                               uint8_t vector)
{
    return v->arch.pv_vcpu.trap_ctxt[vector].address;
}

#else  /* !CONFIG_PV */

#include <xen/errno.h>

static inline void pv_trap_init(void) {}

/* Deliver interrupt to PV guest. Return 0 on success. */
static int pv_raise_interrupt(struct vcpu *v, uint8_t vector) { return -EOPNOTSUPP; }

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
