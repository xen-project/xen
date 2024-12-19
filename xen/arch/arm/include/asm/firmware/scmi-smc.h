/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/include/asm/firmware/scmi-smc.h
 *
 * ARM System Control and Management Interface (SCMI) over SMC
 * Generic handling layer
 *
 * Andrei Cherechesu <andrei.cherechesu@nxp.com>
 * Copyright 2024 NXP
 */

#ifndef __ASM_SCMI_SMC_H__
#define __ASM_SCMI_SMC_H__

#include <xen/types.h>

struct cpu_user_regs;

#ifdef CONFIG_SCMI_SMC

bool scmi_handle_smc(struct cpu_user_regs *regs);

#else

static inline bool scmi_handle_smc(struct cpu_user_regs *regs)
{
    return false;
}

#endif /* CONFIG_SCMI_SMC */

#endif /* __ASM_SCMI_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
