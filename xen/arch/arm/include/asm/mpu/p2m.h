/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_P2M_H__
#define __ARM_MPU_P2M_H__

#include <xen/bitops.h>
#include <xen/macros.h>
#include <xen/page-size.h>
#include <asm/mpu.h>

struct p2m_domain;

#define P2M_ROOT_PAGES DIV_ROUND_UP(MAX_MPU_REGION_NR * sizeof(pr_t), PAGE_SIZE)
#define P2M_ROOT_ORDER get_count_order(P2M_ROOT_PAGES)

static inline void p2m_clear_root_pages(struct p2m_domain *p2m) {}

static inline void p2m_tlb_flush_sync(struct p2m_domain *p2m) {}

#endif /* __ARM_MPU_P2M_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
