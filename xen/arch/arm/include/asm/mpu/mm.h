/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_MM_H__
#define __ARM_MPU_MM_H__

#include <xen/bug.h>
#include <xen/macros.h>
#include <xen/page-size.h>
#include <xen/types.h>
#include <asm/mm.h>
#include <asm/mpu.h>

extern struct page_info *frame_table;

extern uint8_t max_mpu_regions;

extern DECLARE_BITMAP(xen_mpumap_mask, MAX_MPU_REGION_NR);

extern pr_t xen_mpumap[MAX_MPU_REGION_NR];

#define virt_to_maddr(va) ((paddr_t)((vaddr_t)(va) & PADDR_MASK))

#ifdef CONFIG_ARM_32
#define is_xen_heap_page(page) ({ BUG_ON("unimplemented"); false; })
#define is_xen_heap_mfn(mfn) ({ BUG_ON("unimplemented"); false; })
#endif

/* On MPU systems there is no translation, ma == va. */
static inline void *maddr_to_virt(paddr_t ma)
{
    return _p(ma);
}

/* Convert between virtual address to page-info structure. */
static inline struct page_info *virt_to_page(const void *v)
{
    mfn_t mfn = _mfn(virt_to_mfn(v));

    ASSERT(mfn_valid(mfn));

    return mfn_to_page(mfn);
}

#endif /* __ARM_MPU_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
