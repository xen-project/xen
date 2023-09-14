/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_DELAY_H__
#define __ASM_PPC_DELAY_H__

#include <xen/lib.h>

static inline void udelay(unsigned long usecs)
{
    BUG_ON("unimplemented");
}

#endif /* __ASM_PPC_DELAY_H__ */
