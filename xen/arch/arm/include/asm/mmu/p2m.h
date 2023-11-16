/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ARM_MMU_P2M_H__
#define __ARM_MMU_P2M_H__

extern unsigned int p2m_root_order;
extern unsigned int p2m_root_level;
#define P2M_ROOT_ORDER p2m_root_order
#define P2M_ROOT_LEVEL p2m_root_level
#define P2M_ROOT_PAGES    (1U << P2M_ROOT_ORDER)

struct p2m_domain;
void p2m_force_tlb_flush_sync(struct p2m_domain *p2m);
void p2m_tlb_flush_sync(struct p2m_domain *p2m);

void p2m_clear_root_pages(struct p2m_domain *p2m);

#endif /* __ARM_MMU_P2M_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
