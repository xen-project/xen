/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GENERIC_PAGING_H__
#define __ASM_GENERIC_PAGING_H__

#include <xen/stdbool.h>

#define paging_mode_translate(d)    ((void)(d), true)
#define paging_mode_external(d)     ((void)(d), true)

#endif /* __ASM_GENERIC_PAGING_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
