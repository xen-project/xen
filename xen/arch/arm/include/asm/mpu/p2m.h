/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_P2M_H__
#define __ARM_MPU_P2M_H__

struct p2m_domain;

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
