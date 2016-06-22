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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_X86_HVM_DOMAIN_H__
#define __ASM_X86_HVM_DOMAIN_H__

#include <xen/iommu.h>
#include <asm/hvm/irq.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vioapic.h>
#include <asm/hvm/io.h>
#include <asm/hvm/viridian.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/svm/vmcb.h>
#include <public/grant_table.h>
#include <public/hvm/params.h>
#include <public/hvm/save.h>
#include <public/hvm/hvm_op.h>

struct hvm_ioreq_page {
    unsigned long gmfn;
    struct page_info *page;
    void *va;
};

struct hvm_ioreq_vcpu {
    struct list_head list_entry;
    struct vcpu      *vcpu;
    evtchn_port_t    ioreq_evtchn;
    bool_t           pending;
};

#define NR_IO_RANGE_TYPES (HVMOP_IO_RANGE_PCI + 1)
#define MAX_NR_IO_RANGES  256

struct hvm_ioreq_server {
    struct list_head       list_entry;
    struct domain          *domain;

    /* Lock to serialize toolstack modifications */
    spinlock_t             lock;

    /* Domain id of emulating domain */
    domid_t                domid;
    ioservid_t             id;
    struct hvm_ioreq_page  ioreq;
    struct list_head       ioreq_vcpu_list;
    struct hvm_ioreq_page  bufioreq;

    /* Lock to serialize access to buffered ioreq ring */
    spinlock_t             bufioreq_lock;
    evtchn_port_t          bufioreq_evtchn;
    struct rangeset        *range[NR_IO_RANGE_TYPES];
    bool_t                 enabled;
    bool_t                 bufioreq_atomic;
};

struct hvm_domain {
    /* Guest page range used for non-default ioreq servers */
    struct {
        unsigned long base;
        unsigned long mask;
    } ioreq_gmfn;

    /* Lock protects all other values in the sub-struct and the default */
    struct {
        spinlock_t       lock;
        ioservid_t       id;
        struct list_head list;
    } ioreq_server;
    struct hvm_ioreq_server *default_ioreq_server;

    /* Cached CF8 for guest PCI config cycles */
    uint32_t                pci_cf8;

    struct pl_time         *pl_time;

    struct hvm_io_handler *io_handler;
    unsigned int          io_handler_count;

    /* Lock protects access to irq, vpic and vioapic. */
    spinlock_t             irq_lock;
    struct hvm_irq         irq;
    struct hvm_hw_vpic     vpic[2]; /* 0=master; 1=slave */
    struct hvm_vioapic    *vioapic;
    struct hvm_hw_stdvga   stdvga;

    /* VCPU which is current target for 8259 interrupts. */
    struct vcpu           *i8259_target;

    /* emulated irq to pirq */
    struct radix_tree_root emuirq_pirq;

    uint64_t              *params;

    /* Memory ranges with pinned cache attributes. */
    struct list_head       pinned_cacheattr_ranges;

    /* VRAM dirty support.  Protect with the domain paging lock. */
    struct sh_dirty_vram *dirty_vram;

    /* If one of vcpus of this domain is in no_fill_mode or
     * mtrr/pat between vcpus is not the same, set is_in_uc_mode
     */
    spinlock_t             uc_lock;
    bool_t                 is_in_uc_mode;

    /* hypervisor intercepted msix table */
    struct list_head       msixtbl_list;

    struct viridian_domain viridian;

    bool_t                 hap_enabled;
    bool_t                 mem_sharing_enabled;
    bool_t                 qemu_mapcache_invalidate;
    bool_t                 is_s3_suspended;

    /*
     * TSC value that VCPUs use to calculate their tsc_offset value.
     * Used during initialization and save/restore.
     */
    uint64_t sync_tsc;

    uint64_t tsc_scaling_ratio;

    unsigned long *io_bitmap;

    /* List of permanently write-mapped pages. */
    struct {
        spinlock_t lock;
        struct list_head list;
    } write_map;

    union {
        struct vmx_domain vmx;
        struct svm_domain svm;
    };
};

#define hap_enabled(d)  ((d)->arch.hvm_domain.hap_enabled)

#endif /* __ASM_X86_HVM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
