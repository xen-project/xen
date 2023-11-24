/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_DOM0LESS_BUILD_H_
#define __ASM_DOM0LESS_BUILD_H_

#include <xen/stdbool.h>

#ifdef CONFIG_DOM0LESS_BOOT

void create_domUs(void);
bool is_dom0less_mode(void);

#else /* !CONFIG_DOM0LESS_BOOT */

static inline void create_domUs(void) {}
static inline bool is_dom0less_mode(void)
{
    return false;
}

#endif /* CONFIG_DOM0LESS_BOOT */

#endif /* __ASM_DOM0LESS_BUILD_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
