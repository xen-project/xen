/*
 * vcpu.h: HVM per vcpu definitions
 *
 * Copyright (c) 2005, International Business Machines Corporation.
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

#ifndef __ASM_X86_HVM_VCPU_H__
#define __ASM_X86_HVM_VCPU_H__

#include <xen/tasklet.h>
#include <asm/hvm/io.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/viridian.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vmx/vvmx.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/nestedsvm.h>
#include <asm/mtrr.h>

enum hvm_io_state {
    HVMIO_none = 0,
    HVMIO_dispatched,
    HVMIO_awaiting_completion,
    HVMIO_handle_mmio_awaiting_completion,
    HVMIO_handle_pio_awaiting_completion,
    HVMIO_completed
};

struct hvm_vcpu_asid {
    uint64_t generation;
    uint32_t asid;
};

struct hvm_vcpu_io {
    /* I/O request in flight to device model. */
    enum hvm_io_state   io_state;
    unsigned long       io_data;
    int                 io_size;

    /*
     * HVM emulation:
     *  Virtual address @mmio_gva maps to MMIO physical frame @mmio_gpfn.
     *  The latter is known to be an MMIO frame (not RAM).
     *  This translation is only valid for accesses as per @mmio_access.
     */
    struct npfec        mmio_access;
    unsigned long       mmio_gva;
    unsigned long       mmio_gpfn;

    /* We may read up to m256 as a number of device-model transactions. */
    paddr_t mmio_large_read_pa;
    uint8_t mmio_large_read[32];
    unsigned int mmio_large_read_bytes;
    /* We may write up to m256 as a number of device-model transactions. */
    unsigned int mmio_large_write_bytes;
    paddr_t mmio_large_write_pa;
    /* For retries we shouldn't re-fetch the instruction. */
    unsigned int mmio_insn_bytes;
    unsigned char mmio_insn[16];
    /*
     * For string instruction emulation we need to be able to signal a
     * necessary retry through other than function return codes.
     */
    bool_t mmio_retry, mmio_retrying;

    unsigned long msix_unmask_address;
};

#define VMCX_EADDR    (~0ULL)

struct nestedvcpu {
    bool_t nv_guestmode; /* vcpu in guestmode? */
    void *nv_vvmcx; /* l1 guest virtual VMCB/VMCS */
    void *nv_n1vmcx; /* VMCB/VMCS used to run l1 guest */
    void *nv_n2vmcx; /* shadow VMCB/VMCS used to run l2 guest */

    uint64_t nv_vvmcxaddr; /* l1 guest physical address of nv_vvmcx */
    uint64_t nv_n1vmcx_pa; /* host physical address of nv_n1vmcx */
    uint64_t nv_n2vmcx_pa; /* host physical address of nv_n2vmcx */

    /* SVM/VMX arch specific */
    union {
        struct nestedsvm nsvm;
        struct nestedvmx nvmx;
    } u;

    bool_t nv_flushp2m; /* True, when p2m table must be flushed */
    struct p2m_domain *nv_p2m; /* used p2m table for this vcpu */

    struct hvm_vcpu_asid nv_n2asid;

    bool_t nv_vmentry_pending;
    bool_t nv_vmexit_pending;
    bool_t nv_vmswitch_in_progress; /* true during vmentry/vmexit emulation */

    /* Does l1 guest intercept io ports 0x80 and/or 0xED ?
     * Useful to optimize io permission handling.
     */
    bool_t nv_ioport80;
    bool_t nv_ioportED;

    /* L2's control-resgister, just as the L2 sees them. */
    unsigned long       guest_cr[5];
};

#define vcpu_nestedhvm(v) ((v)->arch.hvm_vcpu.nvcpu)

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
    s64                 cache_tsc_offset;
    u64                 guest_time;

    /* Lock and list for virtual platform timers. */
    spinlock_t          tm_lock;
    struct list_head    tm_list;

    u8                  flag_dr_dirty;
    bool_t              debug_state_latch;
    bool_t              single_step;

    bool_t              hcall_preempted;
    bool_t              hcall_64bit;

    struct hvm_vcpu_asid n1asid;

    u32                 msr_tsc_aux;
    u64                 msr_tsc_adjust;

    /* VPMU */
    struct vpmu_struct  vpmu;

    union {
        struct arch_vmx_struct vmx;
        struct arch_svm_struct svm;
    } u;

    struct tasklet      assert_evtchn_irq_tasklet;

    struct nestedvcpu   nvcpu;

    struct mtrr_state   mtrr;
    u64                 pat_cr;

    /* In mode delay_for_missed_ticks, VCPUs have differing guest times. */
    int64_t             stime_offset;

    /* Which cache mode is this VCPU in (CR0:CD/NW)? */
    u8                  cache_mode;

    struct hvm_vcpu_io  hvm_io;

    /* Callback into x86_emulate when emulating FPU/MMX/XMM instructions. */
    void (*fpu_exception_callback)(void *, struct cpu_user_regs *);
    void *fpu_exception_callback_arg;

    /* Pending hw/sw interrupt (.vector = -1 means nothing pending). */
    struct hvm_trap     inject_trap;

    struct viridian_vcpu viridian;
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
