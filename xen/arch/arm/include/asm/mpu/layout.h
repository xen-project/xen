/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_LAYOUT_H__
#define __ARM_MPU_LAYOUT_H__

#define XEN_START_ADDRESS CONFIG_XEN_START_ADDRESS

/*
 * All MPU platforms need to provide a XEN_START_ADDRESS for linker. This
 * address indicates where Xen image will be loaded and run from. This
 * address must be aligned to a PAGE_SIZE.
 */
#if (XEN_START_ADDRESS % PAGE_SIZE) != 0
#error "XEN_START_ADDRESS must be aligned to 4KB"
#endif

/*
 * For MPU, XEN's virtual start address is same as the physical address.
 * The reason being MPU treats VA == PA. IOW, it cannot map the physical
 * address to a different fixed virtual address. So, the virtual start
 * address is determined by the physical address at which Xen is loaded.
 */
#define XEN_VIRT_START         _AT(paddr_t, XEN_START_ADDRESS)

#endif /* __ARM_MPU_LAYOUT_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
