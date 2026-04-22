/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__TIME_H
#define ASM__RISCV__TIME_H

#include <xen/bug.h>
#include <xen/muldiv64.h>
#include <xen/sections.h>

#include <asm/csr.h>

/* Clock cycles count at Xen startup */
extern uint64_t boot_clock_cycles;

struct vcpu;

static inline void force_update_vcpu_system_time(struct vcpu *v)
{
    BUG_ON("unimplemented");
}

typedef unsigned long cycles_t;

static inline cycles_t get_cycles(void)
{
    return csr_read(CSR_TIME);
}

void preinit_xen_time(void);

extern int (* __ro_after_init set_xen_timer)(uint64_t deadline);

#endif /* ASM__RISCV__TIME_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
