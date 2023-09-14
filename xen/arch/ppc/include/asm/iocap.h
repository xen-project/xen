/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_IOCAP_H__
#define __ASM_PPC_IOCAP_H__

#define cache_flush_permitted(d)                        \
    (!rangeset_is_empty((d)->iomem_caps))

#endif /* __ASM_PPC_IOCAP_H__ */
