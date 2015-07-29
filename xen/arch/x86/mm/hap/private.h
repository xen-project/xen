/*
 * arch/x86/mm/hap/private.h
 *
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef __HAP_PRIVATE_H__
#define __HAP_PRIVATE_H__

#include "../mm-locks.h"

/********************************************/
/*          GUEST TRANSLATION FUNCS         */
/********************************************/
unsigned long hap_gva_to_gfn_2_levels(struct vcpu *v,
                                     struct p2m_domain *p2m,
                                     unsigned long gva, 
                                     uint32_t *pfec);
unsigned long hap_gva_to_gfn_3_levels(struct vcpu *v,
                                     struct p2m_domain *p2m,
                                     unsigned long gva, 
                                     uint32_t *pfec);
unsigned long hap_gva_to_gfn_4_levels(struct vcpu *v,
                                     struct p2m_domain *p2m,
                                     unsigned long gva, 
                                     uint32_t *pfec);

unsigned long hap_p2m_ga_to_gfn_2_levels(struct vcpu *v,
    struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order);
unsigned long hap_p2m_ga_to_gfn_3_levels(struct vcpu *v,
    struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order);
unsigned long hap_p2m_ga_to_gfn_4_levels(struct vcpu *v,
    struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order);

#endif /* __HAP_PRIVATE_H__ */
