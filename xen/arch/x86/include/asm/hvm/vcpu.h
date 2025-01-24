/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vcpu.h: HVM per vcpu definitions
 *
 * Copyright (c) 2005, International Business Machines Corporation.
 */

#ifndef __ASM_X86_HVM_VCPU_H__
#define __ASM_X86_HVM_VCPU_H__

#include <xen/tasklet.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vmx/vvmx.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/nestedsvm.h>
#include <asm/mtrr.h>
#include <public/hvm/ioreq.h>

struct hvm_vcpu_asid {
    uint64_t generation;
    uint32_t asid;
};

struct hvm_vcpu_io {
    /*
     * HVM emulation:
     *  Linear address @mmio_gla maps to MMIO physical frame @mmio_gpfn.
     *  The latter is known to be an MMIO frame (not RAM).
     *  This translation is only valid for accesses as per @mmio_access.
     */
    struct npfec        mmio_access;
    unsigned long       mmio_gla;
    unsigned long       mmio_gpfn;

    /*
     * We may need to handle up to 3 distinct memory accesses per
     * instruction.
     */
    struct hvm_mmio_cache *mmio_cache[3];
    unsigned int mmio_cache_count;

    /* For retries we shouldn't re-fetch the instruction. */
    unsigned int mmio_insn_bytes;
    unsigned char mmio_insn[16];
    struct hvmemul_cache *cache;

    /*
     * For string instruction emulation we need to be able to signal a
     * necessary retry through other than function return codes.
     */
    bool mmio_retry;

    unsigned long msix_unmask_address;
    unsigned long msix_snoop_address;
    unsigned long msix_snoop_gpa;

    const struct g2m_ioport *g2m_ioport;
};

struct nestedvcpu {
    bool nv_guestmode; /* vcpu in guestmode? */
    void *nv_vvmcx; /* l1 guest virtual VMCB/VMCS */
    void *nv_n1vmcx; /* VMCB/VMCS used to run l1 guest */
    void *nv_n2vmcx; /* shadow VMCB/VMCS used to run l2 guest */

    uint64_t nv_vvmcxaddr; /* l1 guest physical address of nv_vvmcx */
    paddr_t nv_n1vmcx_pa; /* host physical address of nv_n1vmcx */
    paddr_t nv_n2vmcx_pa; /* host physical address of nv_n2vmcx */

    /* SVM/VMX arch specific */
    union {
        struct nestedsvm nsvm;
        struct nestedvmx nvmx;
    } u;

    bool nv_flushp2m; /* True, when p2m table must be flushed */
    struct p2m_domain *nv_p2m; /* used p2m table for this vcpu */
    bool stale_np2m; /* True when p2m_base in VMCx02 is no longer valid */
    uint64_t np2m_generation;

    struct hvm_vcpu_asid nv_n2asid;

    bool nv_vmentry_pending;
    bool nv_vmexit_pending;
    bool nv_vmswitch_in_progress; /* true during vmentry/vmexit emulation */

    /* Does l1 guest intercept io ports 0x80 and/or 0xED ?
     * Useful to optimize io permission handling.
     */
    bool nv_ioport80;
    bool nv_ioportED;

    /* L2's control-resgister, just as the L2 sees them. */
    unsigned long       guest_cr[5];
};

#define vcpu_nestedhvm(v) ((v)->arch.hvm.nvcpu)

struct altp2mvcpu {
    /*
     * #VE information page.  This pointer being non-NULL indicates that a
     * VMCS's VIRT_EXCEPTION_INFO field is pointing to the page, and an extra
     * page reference is held.
     */
    struct page_info *veinfo_pg;
    uint16_t    p2midx;         /* alternate p2m index */
};

#define vcpu_altp2m(v) ((v)->arch.hvm.avcpu)

struct hvm_vcpu {
    /* Guest control-register and EFER values, just as the guest sees them. */
    unsigned long       guest_cr[5];
    unsigned long       guest_efer;

    /*
     * Processor-visible control-register values, while guest executes.
     *  CR0, CR4: Used as a cache of VMCS contents by VMX only.
     *  CR1, CR2: Never used (guest_cr[2] is always processor-visible CR2).
     *  CR3:      Always used and kept up to date by paging subsystem.
     */
    unsigned long       hw_cr[5];

    struct vlapic       vlapic;
    int64_t             cache_tsc_offset;
    uint64_t            guest_time;

    /* Lock and list for virtual platform timers. */
    spinlock_t          tm_lock;
    struct list_head    tm_list;

    bool                flag_dr_dirty;
    bool                debug_state_latch;
    bool                single_step;
    struct {
        bool     enabled;
        uint16_t p2midx;
    } fast_single_step;

    /* (MFN) hypervisor page table */
    pagetable_t         monitor_table;

    struct hvm_vcpu_asid n1asid;

    u64                 msr_tsc_adjust;

    union {
        struct vmx_vcpu vmx;
        struct svm_vcpu svm;
    };

    struct tasklet      assert_evtchn_irq_tasklet;

    struct nestedvcpu   nvcpu;

    struct altp2mvcpu   avcpu;

    struct mtrr_state   mtrr;
    u64                 pat_cr;

    /* In mode delay_for_missed_ticks, VCPUs have differing guest times. */
    int64_t             stime_offset;

    u8                  evtchn_upcall_vector;

    /* Which cache mode is this VCPU in (CR0:CD/NW)? */
    u8                  cache_mode;

    struct hvm_vcpu_io  hvm_io;

    /* Pending hw/sw interrupt (.vector = -1 means nothing pending). */
    struct x86_event     inject_event;

    struct viridian_vcpu *viridian;
};

#endif /* __ASM_X86_HVM_VCPU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
