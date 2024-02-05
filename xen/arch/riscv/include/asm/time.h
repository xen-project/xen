/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_RISCV_TIME_H__
#define __ASM_RISCV_TIME_H__

#include <xen/bug.h>
#include <asm/csr.h>

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

#endif /* __ASM_RISCV_TIME_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
