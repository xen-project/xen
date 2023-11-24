/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_DOM0LESS_BUILD_H_
#define __ASM_DOM0LESS_BUILD_H_

#include <xen/stdbool.h>

void create_domUs(void);
bool is_dom0less_mode(void);

#endif /* __ASM_DOM0LESS_BUILD_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
