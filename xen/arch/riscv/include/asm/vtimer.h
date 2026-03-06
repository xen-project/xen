/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__VTIMER_H
#define ASM__RISCV__VTIMER_H

#include <xen/timer.h>

struct vtimer {
    struct timer timer;
};

int vcpu_vtimer_init(struct vcpu *v);
void vcpu_timer_destroy(struct vcpu *v);

void vtimer_set_timer(struct vtimer *t, uint64_t ticks);

#endif /* ASM__RISCV__VTIMER_H */
