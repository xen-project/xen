/*
 * domain.h: HVM per domain definitions
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_DOMAIN_H__
#define __ASM_X86_HVM_DOMAIN_H__

#include <asm/iommu.h>
#include <asm/hvm/irq.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vioapic.h>
#include <asm/hvm/io.h>
#include <asm/hvm/iommu.h>
#include <public/hvm/params.h>
#include <public/hvm/save.h>

struct hvm_ioreq_page {
    spinlock_t lock;
    struct page_info *page;
    void *va;
};

struct hvm_domain {
    struct hvm_ioreq_page  ioreq;
    struct hvm_ioreq_page  buf_ioreq;

    s64                    tsc_frequency;
    struct pl_time         pl_time;

    struct hvm_io_handler  io_handler;

    /* Lock protects access to irq, vpic and vioapic. */
    spinlock_t             irq_lock;
    struct hvm_irq         irq;
    struct hvm_hw_vpic     vpic[2]; /* 0=master; 1=slave */
    struct hvm_vioapic    *vioapic;
    struct hvm_hw_stdvga   stdvga;

    /* hvm_print_line() logging. */
    char                   pbuf[80];
    int                    pbuf_idx;
    spinlock_t             pbuf_lock;

    uint64_t               params[HVM_NR_PARAMS];

    unsigned long          vmx_apic_access_mfn;

    /* Memory ranges with pinned cache attributes. */
    struct list_head       pinned_cacheattr_ranges;

    /* If one of vcpus of this domain is in no_fill_mode or
     * mtrr/pat between vcpus is not the same, set is_in_uc_mode
     */
    spinlock_t             uc_lock;
    bool_t                 is_in_uc_mode;

    /* Pass-through */
    struct hvm_iommu       hvm_iommu;
};

#endif /* __ASM_X86_HVM_DOMAIN_H__ */

