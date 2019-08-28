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
#include <public/hvm/dm_op.h>

struct hvm_ioreq_page {
    gfn_t gfn;
    struct page_info *page;
    void *va;
};

struct hvm_ioreq_vcpu {
    struct list_head list_entry;
    struct vcpu      *vcpu;
    evtchn_port_t    ioreq_evtchn;
    bool             pending;
};

#define NR_IO_RANGE_TYPES (XEN_DMOP_IO_RANGE_PCI + 1)
#define MAX_NR_IO_RANGES  256

struct hvm_ioreq_server {
    struct domain          *target, *emulator;

    /* Lock to serialize toolstack modifications */
    spinlock_t             lock;

    struct hvm_ioreq_page  ioreq;
    struct list_head       ioreq_vcpu_list;
    struct hvm_ioreq_page  bufioreq;

    /* Lock to serialize access to buffered ioreq ring */
    spinlock_t             bufioreq_lock;
    evtchn_port_t          bufioreq_evtchn;
    struct rangeset        *range[NR_IO_RANGE_TYPES];
    bool                   enabled;
    uint8_t                bufioreq_handling;
};

/*
 * This structure defines function hooks to support hardware-assisted
 * virtual interrupt delivery to guest. (e.g. VMX PI and SVM AVIC).
 *
 * These hooks are defined by the underlying arch-specific code
 * as needed. For example:
 *   - When the domain is enabled with virtual IPI delivery
 *   - When the domain is enabled with virtual I/O int delivery
 *     and actually has a physical device assigned .
 */
struct hvm_pi_ops {
    unsigned int flags;

    /*
     * Hook into arch_vcpu_block(), which is called
     * from vcpu_block() and vcpu_do_poll().
     */
    void (*vcpu_block)(struct vcpu *);
};

#define MAX_NR_IOREQ_SERVERS 8

struct hvm_domain {
    /* Guest page range used for non-default ioreq servers */
    struct {
        unsigned long base;
        unsigned long mask; /* indexed by GFN minus base */
        unsigned long legacy_mask; /* indexed by HVM param number */
    } ioreq_gfn;

    /* Lock protects all other values in the sub-struct and the default */
    struct {
        spinlock_t              lock;
        struct hvm_ioreq_server *server[MAX_NR_IOREQ_SERVERS];
    } ioreq_server;

    /* Cached CF8 for guest PCI config cycles */
    uint32_t                pci_cf8;

    struct pl_time         *pl_time;

    struct hvm_io_handler *io_handler;
    unsigned int          io_handler_count;

    /* Lock protects access to irq, vpic and vioapic. */
    spinlock_t             irq_lock;
    struct hvm_irq        *irq;
    struct hvm_hw_vpic     vpic[2]; /* 0=master; 1=slave */
    struct hvm_vioapic    **vioapic;
    unsigned int           nr_vioapics;
    struct hvm_hw_stdvga   stdvga;

    /*
     * hvm_hw_pmtimer is a publicly-visible name. We will defer renaming
     * it to the more appropriate hvm_hw_acpi until the expected
     * comprehensive rewrte of migration code, thus avoiding code churn
     * in public header files.
     * Internally, however, we will be using hvm_hw_acpi.
     */
#define hvm_hw_acpi hvm_hw_pmtimer
    struct hvm_hw_acpi     acpi;

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

    struct viridian_domain *viridian;

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

    /* List of guest to machine IO ports mapping. */
    struct list_head g2m_ioport_list;

    /* List of MMCFG regions trapped by Xen. */
    struct list_head mmcfg_regions;
    rwlock_t mmcfg_lock;

    /* List of MSI-X tables. */
    struct list_head msix_tables;

    /* List of permanently write-mapped pages. */
    struct {
        spinlock_t lock;
        struct list_head list;
    } write_map;

    struct hvm_pi_ops pi_ops;

    union {
        struct vmx_domain vmx;
        struct svm_domain svm;
    };
};

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
