/*
 * psr.h: Platform Shared Resource related service for guest.
 *
 * Copyright (c) 2014, Intel Corporation
 * Author: Dongxiao Xu <dongxiao.xu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#ifndef __ASM_PSR_H__
#define __ASM_PSR_H__

#include <xen/types.h>

/* CAT cpuid level */
#define PSR_CPUID_LEVEL_CAT   0x10

/* Resource Type Enumeration */
#define PSR_RESOURCE_TYPE_L3            0x2

/* L3 Monitoring Features */
#define PSR_CMT_L3_OCCUPANCY           0x1

struct psr_cmt_l3 {
    unsigned int features;
    unsigned int upscaling_factor;
    unsigned int rmid_max;
};

struct psr_cmt {
    unsigned int rmid_max;
    unsigned int features;
    domid_t *rmid_to_dom;
    struct psr_cmt_l3 l3;
};

extern struct psr_cmt *psr_cmt;

static inline bool_t psr_cmt_enabled(void)
{
    return !!psr_cmt;
}

int psr_alloc_rmid(struct domain *d);
void psr_free_rmid(struct domain *d);
void psr_ctxt_switch_to(struct domain *d);

int psr_get_cat_l3_info(unsigned int socket, uint32_t *cbm_len,
                        uint32_t *cos_max);
int psr_get_l3_cbm(struct domain *d, unsigned int socket, uint64_t *cbm);
int psr_set_l3_cbm(struct domain *d, unsigned int socket, uint64_t cbm);

int psr_domain_init(struct domain *d);
void psr_domain_free(struct domain *d);

#endif /* __ASM_PSR_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
