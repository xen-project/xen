/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GENERIC_IOCAP_H__
#define __ASM_GENERIC_IOCAP_H__

#define has_arch_io_resources(d)                        \
    (!rangeset_is_empty((d)->iomem_caps))

#define cache_flush_permitted has_arch_io_resources

#endif /* __ASM_GENERIC_IOCAP_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
