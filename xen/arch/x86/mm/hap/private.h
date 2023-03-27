/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/x86/mm/hap/private.h
 *
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
 *
 */
#ifndef __HAP_PRIVATE_H__
#define __HAP_PRIVATE_H__

#include "../mm-locks.h"

/********************************************/
/*          GUEST TRANSLATION FUNCS         */
/********************************************/
unsigned long cf_check hap_gva_to_gfn_2_levels(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec);
unsigned long cf_check hap_gva_to_gfn_3_levels(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec);
unsigned long cf_check hap_gva_to_gfn_4_levels(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec);

unsigned long cf_check hap_p2m_ga_to_gfn_2_levels(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order);
unsigned long cf_check hap_p2m_ga_to_gfn_3_levels(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order);
unsigned long cf_check hap_p2m_ga_to_gfn_4_levels(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order);

#endif /* __HAP_PRIVATE_H__ */
