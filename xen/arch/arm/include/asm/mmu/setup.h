/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ARM_MMU_SETUP_H__
#define __ARM_MMU_SETUP_H__

#include <asm/lpae.h>
#include <asm/mmu/layout.h>

extern lpae_t boot_pgtable[XEN_PT_LPAE_ENTRIES];

#ifdef CONFIG_ARM_64
extern lpae_t boot_first[XEN_PT_LPAE_ENTRIES];
extern lpae_t boot_first_id[XEN_PT_LPAE_ENTRIES];
#endif
extern lpae_t boot_second[XEN_PT_LPAE_ENTRIES];
extern lpae_t boot_second_id[XEN_PT_LPAE_ENTRIES];
extern lpae_t boot_third[XEN_PT_LPAE_ENTRIES * XEN_NR_ENTRIES(2)];
extern lpae_t boot_third_id[XEN_PT_LPAE_ENTRIES];

/* Find where Xen will be residing at runtime and return a PT entry */
lpae_t pte_of_xenaddr(vaddr_t va);

#endif /* __ARM_MMU_SETUP_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
