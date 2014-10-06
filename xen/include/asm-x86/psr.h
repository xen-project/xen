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
void psr_assoc_rmid(unsigned int rmid);

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
