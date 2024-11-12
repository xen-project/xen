/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * domain.h: HVM per domain definitions
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation
 */

#ifndef __ASM_X86_HVM_DOMAIN_H__
#define __ASM_X86_HVM_DOMAIN_H__

#include <xen/list.h>
#include <xen/mm.h>
#include <xen/radix-tree.h>

#include <asm/hvm/io.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/svm/vmcb.h>

#ifdef CONFIG_MEM_SHARING
struct mem_sharing_domain
{
    bool enabled, block_interrupts;

    /*
     * When releasing shared gfn's in a preemptible manner, recall where
     * to resume the search.
     */
    unsigned long next_shared_gfn_to_relinquish;
};
#endif

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
    void (*vcpu_block)(struct vcpu *v);
};

struct hvm_domain {
    /* Guest page range used for non-default ioreq servers */
    struct {
        unsigned long base;
        unsigned long mask; /* indexed by GFN minus base */
        unsigned long legacy_mask; /* indexed by HVM param number */
    } ioreq_gfn;

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
    bool                   is_in_uc_mode;

    bool                   is_s3_suspended;

    /* Compatibility setting for a bug in x2APIC LDR */
    bool bug_x2apic_ldr_vcpu_id;

    /* hypervisor intercepted msix table */
    struct list_head       msixtbl_list;

    struct viridian_domain *viridian;

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

#ifdef CONFIG_MEM_SHARING
    struct mem_sharing_domain mem_sharing;
#endif
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
