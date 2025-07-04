/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmcb.c: VMCB management
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
 *
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/keyhandler.h>
#include <xen/mm.h>
#include <xen/rcupdate.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/hvm/svm/vmcb.h>
#include <asm/msr-index.h>
#include <asm/p2m.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/svmdebug.h>
#include <asm/spec_ctrl.h>

struct vmcb_struct *alloc_vmcb(void)
{
    struct vmcb_struct *vmcb;

    vmcb = alloc_xenheap_page();
    if ( vmcb == NULL )
    {
        printk(XENLOG_WARNING "Warning: failed to allocate vmcb.\n");
        return NULL;
    }

    clear_page(vmcb);
    return vmcb;
}

void free_vmcb(struct vmcb_struct *vmcb)
{
    free_xenheap_page(vmcb);
}

/* This function can directly access fields which are covered by clean bits. */
static int construct_vmcb(struct vcpu *v)
{
    struct svm_vcpu *svm = &v->arch.hvm.svm;
    struct vmcb_struct *vmcb = svm->vmcb;

    vmcb->_general1_intercepts =
        GENERAL1_INTERCEPT_INTR        | GENERAL1_INTERCEPT_NMI         |
        GENERAL1_INTERCEPT_SMI         | GENERAL1_INTERCEPT_INIT        |
        GENERAL1_INTERCEPT_CPUID       | GENERAL1_INTERCEPT_INVD        |
        GENERAL1_INTERCEPT_HLT         | GENERAL1_INTERCEPT_INVLPG      |
        GENERAL1_INTERCEPT_INVLPGA     | GENERAL1_INTERCEPT_IOIO_PROT   |
        GENERAL1_INTERCEPT_MSR_PROT    | GENERAL1_INTERCEPT_SHUTDOWN_EVT|
        GENERAL1_INTERCEPT_TASK_SWITCH;
    vmcb->_general2_intercepts =
        GENERAL2_INTERCEPT_VMRUN       | GENERAL2_INTERCEPT_VMMCALL     |
        GENERAL2_INTERCEPT_VMLOAD      | GENERAL2_INTERCEPT_VMSAVE      |
        GENERAL2_INTERCEPT_STGI        | GENERAL2_INTERCEPT_CLGI        |
        GENERAL2_INTERCEPT_SKINIT      | GENERAL2_INTERCEPT_MWAIT       |
        GENERAL2_INTERCEPT_WBINVD      | GENERAL2_INTERCEPT_MONITOR     |
        GENERAL2_INTERCEPT_XSETBV      | GENERAL2_INTERCEPT_ICEBP       |
        GENERAL2_INTERCEPT_RDPRU;

    /* Intercept all debug-register writes. */
    vmcb->_dr_intercepts = ~0u;

    /* Intercept all control-register accesses except for CR2 and CR8. */
    vmcb->_cr_intercepts = ~(CR_INTERCEPT_CR2_READ |
                             CR_INTERCEPT_CR2_WRITE |
                             CR_INTERCEPT_CR8_READ |
                             CR_INTERCEPT_CR8_WRITE);

    svm->vmcb_sync_state = vmcb_needs_vmload;

    /* I/O and MSR permission bitmaps. */
    svm->msrpm = alloc_xenheap_pages(get_order_from_bytes(MSRPM_SIZE), 0);
    if ( svm->msrpm == NULL )
        return -ENOMEM;
    memset(svm->msrpm, 0xff, MSRPM_SIZE);

    svm_disable_intercept_for_msr(v, MSR_FS_BASE);
    svm_disable_intercept_for_msr(v, MSR_GS_BASE);
    svm_disable_intercept_for_msr(v, MSR_SHADOW_GS_BASE);
    svm_disable_intercept_for_msr(v, MSR_CSTAR);
    svm_disable_intercept_for_msr(v, MSR_LSTAR);
    svm_disable_intercept_for_msr(v, MSR_STAR);
    svm_disable_intercept_for_msr(v, MSR_SYSCALL_MASK);

    vmcb->_msrpm_base_pa = virt_to_maddr(svm->msrpm);
    vmcb->_iopm_base_pa = __pa(v->domain->arch.hvm.io_bitmap);

    /* Virtualise EFLAGS.IF and LAPIC TPR (CR8). */
    vmcb->_vintr.fields.intr_masking = 1;

    /* Don't need to intercept RDTSC if CPU supports TSC rate scaling */
    if ( v->domain->arch.vtsc && !cpu_has_tsc_ratio )
    {
        vmcb->_general1_intercepts |= GENERAL1_INTERCEPT_RDTSC;
        vmcb->_general2_intercepts |= GENERAL2_INTERCEPT_RDTSCP;
    }

    /* Guest segment limits. */
    vmcb->cs.limit = ~0u;
    vmcb->es.limit = ~0u;
    vmcb->ss.limit = ~0u;
    vmcb->ds.limit = ~0u;
    vmcb->fs.limit = ~0u;
    vmcb->gs.limit = ~0u;

    /* Guest segment AR bytes. */
    vmcb->es.attr = 0xc93; /* read/write, accessed */
    vmcb->ss.attr = 0xc93;
    vmcb->ds.attr = 0xc93;
    vmcb->fs.attr = 0xc93;
    vmcb->gs.attr = 0xc93;
    vmcb->cs.attr = 0xc9b; /* exec/read, accessed */

    /* Guest TSS. */
    vmcb->tr.attr = 0x08b; /* 32-bit TSS (busy) */
    vmcb->tr.limit = 0xff;

    v->arch.hvm.guest_cr[0] = X86_CR0_PE | X86_CR0_ET;
    hvm_update_guest_efer(v);
    hvm_update_guest_cr(v, 0);
    hvm_update_guest_cr(v, 4);

    paging_update_paging_modes(v);

    vmcb->_exception_intercepts =
        HVM_TRAP_MASK |
        (v->arch.fully_eager_fpu ? 0 : (1U << X86_EXC_NM));

    if ( paging_mode_hap(v->domain) )
    {
        vmcb_set_np(vmcb, true); /* enable nested paging */
        vmcb->_g_pat = MSR_IA32_CR_PAT_RESET; /* guest PAT */
        vmcb->_h_cr3 = pagetable_get_paddr(
            p2m_get_pagetable(p2m_get_hostp2m(v->domain)));

        /* No point in intercepting CR3 reads/writes. */
        vmcb->_cr_intercepts &=
            ~(CR_INTERCEPT_CR3_READ|CR_INTERCEPT_CR3_WRITE);

        /*
         * No point in intercepting INVLPG if we don't have shadow pagetables
         * that need to be fixed up.
         */
        vmcb->_general1_intercepts &= ~GENERAL1_INTERCEPT_INVLPG;

        /* PAT is under complete control of SVM when using nested paging. */
        svm_disable_intercept_for_msr(v, MSR_IA32_CR_PAT);
    }
    else
    {
        vmcb->_exception_intercepts |= (1U << X86_EXC_PF);
    }

    if ( cpu_has_pause_filter )
    {
        vmcb->_pause_filter_count = 4000;
        vmcb->_general1_intercepts |= GENERAL1_INTERCEPT_PAUSE;

        if ( cpu_has_pause_thresh )
            vmcb->_pause_filter_thresh = 1000;
    }

    /*
     * When default_xen_spec_ctrl simply SPEC_CTRL_STIBP, default this behind
     * the back of the VM too.  Our SMT topology isn't accurate, the overhead
     * is neglegable, and doing this saves a WRMSR on the vmentry path.
     */
    if ( default_xen_spec_ctrl == SPEC_CTRL_STIBP )
        v->arch.msrs->spec_ctrl.raw = SPEC_CTRL_STIBP;

    return 0;
}

int svm_create_vmcb(struct vcpu *v)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct svm_vcpu *svm = &v->arch.hvm.svm;
    int rc;

    if ( (nv->nv_n1vmcx == NULL) &&
         (nv->nv_n1vmcx = alloc_vmcb()) == NULL )
    {
        printk("Failed to create a new VMCB\n");
        return -ENOMEM;
    }

    svm->vmcb = nv->nv_n1vmcx;
    rc = construct_vmcb(v);
    if ( rc != 0 )
    {
        free_vmcb(nv->nv_n1vmcx);
        nv->nv_n1vmcx = NULL;
        svm->vmcb = NULL;
        return rc;
    }

    svm->vmcb_pa = nv->nv_n1vmcx_pa = virt_to_maddr(svm->vmcb);
    return 0;
}

void svm_destroy_vmcb(struct vcpu *v)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct svm_vcpu *svm = &v->arch.hvm.svm;

    if ( nv->nv_n1vmcx != NULL )
        free_vmcb(nv->nv_n1vmcx);

    if ( svm->msrpm != NULL )
    {
        free_xenheap_pages(
            svm->msrpm, get_order_from_bytes(MSRPM_SIZE));
        svm->msrpm = NULL;
    }

    nv->nv_n1vmcx = NULL;
    nv->nv_n1vmcx_pa = INVALID_PADDR;
    svm->vmcb = NULL;
}

static void cf_check vmcb_dump(unsigned char ch)
{
    struct domain *d;
    struct vcpu *v;

    printk("*********** VMCB Areas **************\n");

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( !is_hvm_domain(d) )
            continue;
        printk("\n>>> Domain %d <<<\n", d->domain_id);
        for_each_vcpu ( d, v )
        {
            if ( !v->is_initialised )
            {
                printk("\tVCPU %u: not initialized\n", v->vcpu_id);
                continue;
            }
            printk("\tVCPU %d\n", v->vcpu_id);
            svm_vmcb_dump("key_handler", v->arch.hvm.svm.vmcb);

            process_pending_softirqs();
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    printk("**************************************\n");
}

void __init setup_vmcb_dump(void)
{
    register_keyhandler('v', vmcb_dump, "dump AMD-V VMCBs", 1);
}

static void __init __maybe_unused build_assertions(void)
{
    struct vmcb_struct vmcb;

    /* Build-time check of the VMCB layout. */
    BUILD_BUG_ON(sizeof(vmcb) != PAGE_SIZE);
    BUILD_BUG_ON(offsetof(typeof(vmcb), _pause_filter_thresh) != 0x03c);
    BUILD_BUG_ON(offsetof(typeof(vmcb), _vintr)               != 0x060);
    BUILD_BUG_ON(offsetof(typeof(vmcb), event_inj)            != 0x0a8);
    BUILD_BUG_ON(offsetof(typeof(vmcb), es)                   != 0x400);
    BUILD_BUG_ON(offsetof(typeof(vmcb), _cpl)                 != 0x4cb);
    BUILD_BUG_ON(offsetof(typeof(vmcb), _cr4)                 != 0x548);
    BUILD_BUG_ON(offsetof(typeof(vmcb), rsp)                  != 0x5d8);
    BUILD_BUG_ON(offsetof(typeof(vmcb), rax)                  != 0x5f8);
    BUILD_BUG_ON(offsetof(typeof(vmcb), _g_pat)               != 0x668);
    BUILD_BUG_ON(offsetof(typeof(vmcb), spec_ctrl)            != 0x6e0);

    /* Check struct segment_register against the VMCB segment layout. */
    BUILD_BUG_ON(sizeof(vmcb.es)       != 16);
    BUILD_BUG_ON(sizeof(vmcb.es.sel)   != 2);
    BUILD_BUG_ON(sizeof(vmcb.es.attr)  != 2);
    BUILD_BUG_ON(sizeof(vmcb.es.limit) != 4);
    BUILD_BUG_ON(sizeof(vmcb.es.base)  != 8);
    BUILD_BUG_ON(offsetof(typeof(vmcb.es), sel)   != 0);
    BUILD_BUG_ON(offsetof(typeof(vmcb.es), attr)  != 2);
    BUILD_BUG_ON(offsetof(typeof(vmcb.es), limit) != 4);
    BUILD_BUG_ON(offsetof(typeof(vmcb.es), base)  != 8);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
