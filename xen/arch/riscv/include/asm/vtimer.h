/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef RISCV_VTIMER_H
#define RISCV_VTIMER_H

#include <xen/timer.h>

struct vtimer {
    struct timer timer;
};

int vcpu_vtimer_init(struct vcpu *v);
void vcpu_timer_destroy(struct vcpu *v);

void vtimer_set_timer(struct vtimer *t, uint64_t ticks);

void vtimer_ctxt_switch_from(struct vcpu *p);
void vtimer_ctxt_switch_to(struct vcpu *n);

#endif /* RISCV_VTIMER_H */
