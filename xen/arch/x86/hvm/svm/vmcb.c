/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmcb.c: VMCB management
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
 *
 */

#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/rcupdate.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/guest-msr.h>
#include <asm/hvm/svm.h>
#include <asm/msr-index.h>
#include <asm/p2m.h>
#include <asm/spec_ctrl.h>

#include "svm.h"
#include "vmcb.h"

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

    /*
     * Well behaved logic shouldn't ever Bus Lock, but we care about rate
     * limiting buggy/malicious cases.
     */
    if ( cpu_has_svm_bus_lock )
        vmcb->_general3_intercepts |= GENERAL3_INTERCEPT_BUS_LOCK;

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

static void svm_dump_sel(const char *name, const struct segment_register *s)
{
    printk("%s: %04x %04x %08x %016"PRIx64"\n",
           name, s->sel, s->attr, s->limit, s->base);
}

void svm_vmcb_dump(const char *from, const struct vmcb_struct *vmcb)
{
    struct vcpu *curr = current;

    /*
     * If we are dumping the VMCB currently in context, some guest state may
     * still be cached in hardware.  Retrieve it.
     */
    if ( vmcb == curr->arch.hvm.svm.vmcb )
        svm_sync_vmcb(curr, vmcb_in_sync);

    printk("Dumping guest's current state at %s...\n", from);
    printk("Size of VMCB = %zu, paddr = %"PRIpaddr", vaddr = %p\n",
           sizeof(struct vmcb_struct), virt_to_maddr(vmcb), vmcb);

    printk("cr_intercepts = %#x dr_intercepts = %#x "
           "exception_intercepts = %#x\n",
           vmcb_get_cr_intercepts(vmcb), vmcb_get_dr_intercepts(vmcb),
           vmcb_get_exception_intercepts(vmcb));
    printk("general1_intercepts = %#x general2_intercepts = %#x\n",
           vmcb_get_general1_intercepts(vmcb), vmcb_get_general2_intercepts(vmcb));
    printk("iopm_base_pa = %#"PRIx64" msrpm_base_pa = %#"PRIx64" tsc_offset = %#"PRIx64"\n",
           vmcb_get_iopm_base_pa(vmcb), vmcb_get_msrpm_base_pa(vmcb),
           vmcb_get_tsc_offset(vmcb));
    printk("tlb_control = %#x vintr = %#"PRIx64" int_stat = %#"PRIx64"\n",
           vmcb->tlb_control, vmcb_get_vintr(vmcb).bytes,
           vmcb->int_stat.raw);
    printk("event_inj %016"PRIx64", valid? %d, ec? %d, type %u, vector %#x\n",
           vmcb->event_inj.raw, vmcb->event_inj.v,
           vmcb->event_inj.ev, vmcb->event_inj.type,
           vmcb->event_inj.vector);
    printk("exitcode = %#"PRIx64" exit_int_info = %#"PRIx64"\n",
           vmcb->exitcode, vmcb->exit_int_info.raw);
    printk("exitinfo1 = %#"PRIx64" exitinfo2 = %#"PRIx64"\n",
           vmcb->exitinfo1, vmcb->exitinfo2);
    printk("asid = %#x np_ctrl = %#"PRIx64":%s%s%s\n",
           vmcb_get_asid(vmcb), vmcb_get_np_ctrl(vmcb),
           vmcb_get_np(vmcb)     ? " NP"     : "",
           vmcb_get_sev(vmcb)    ? " SEV"    : "",
           vmcb_get_sev_es(vmcb) ? " SEV_ES" : "");
    printk("virtual vmload/vmsave = %d, virt_ext = %#"PRIx64"\n",
           vmcb->virt_ext.fields.vloadsave_enable, vmcb->virt_ext.bytes);
    printk("cpl = %d efer = %#"PRIx64" star = %#"PRIx64" lstar = %#"PRIx64"\n",
           vmcb_get_cpl(vmcb), vmcb_get_efer(vmcb), vmcb->star, vmcb->lstar);
    printk("CR0 = 0x%016"PRIx64" CR2 = 0x%016"PRIx64"\n",
           vmcb_get_cr0(vmcb), vmcb_get_cr2(vmcb));
    printk("CR3 = 0x%016"PRIx64" CR4 = 0x%016"PRIx64"\n",
           vmcb_get_cr3(vmcb), vmcb_get_cr4(vmcb));
    printk("RSP = 0x%016"PRIx64"  RIP = 0x%016"PRIx64"\n",
           vmcb->rsp, vmcb->rip);
    printk("RAX = 0x%016"PRIx64"  RFLAGS=0x%016"PRIx64"\n",
           vmcb->rax, vmcb->rflags);
    printk("DR6 = 0x%016"PRIx64", DR7 = 0x%016"PRIx64"\n",
           vmcb_get_dr6(vmcb), vmcb_get_dr7(vmcb));
    printk("CSTAR = 0x%016"PRIx64" SFMask = 0x%016"PRIx64"\n",
           vmcb->cstar, vmcb->sfmask);
    printk("KernGSBase = 0x%016"PRIx64" PAT = 0x%016"PRIx64"\n",
           vmcb->kerngsbase, vmcb_get_g_pat(vmcb));
    printk("SSP = 0x%016"PRIx64" S_CET = 0x%016"PRIx64" ISST = 0x%016"PRIx64"\n",
           vmcb->_ssp, vmcb->_msr_s_cet, vmcb->_msr_isst);
    printk("H_CR3 = 0x%016"PRIx64" CleanBits = %#x\n",
           vmcb_get_h_cr3(vmcb), vmcb->cleanbits.raw);

    /* print out all the selectors */
    printk("       sel attr  limit   base\n");
    svm_dump_sel("  CS", &vmcb->cs);
    svm_dump_sel("  DS", &vmcb->ds);
    svm_dump_sel("  SS", &vmcb->ss);
    svm_dump_sel("  ES", &vmcb->es);
    svm_dump_sel("  FS", &vmcb->fs);
    svm_dump_sel("  GS", &vmcb->gs);
    svm_dump_sel("GDTR", &vmcb->gdtr);
    svm_dump_sel("LDTR", &vmcb->ldtr);
    svm_dump_sel("IDTR", &vmcb->idtr);
    svm_dump_sel("  TR", &vmcb->tr);
}

bool svm_vmcb_isvalid(
    const char *from, const struct vmcb_struct *vmcb, const struct vcpu *v,
    bool verbose)
{
    bool ret = false; /* ok */
    unsigned long cr0 = vmcb_get_cr0(vmcb);
    unsigned long cr3 = vmcb_get_cr3(vmcb);
    unsigned long cr4 = vmcb_get_cr4(vmcb);
    unsigned long valid;
    uint64_t efer = vmcb_get_efer(vmcb);

#define PRINTF(fmt, args...) do { \
    if ( !verbose ) return true; \
    ret = true; \
    printk(XENLOG_GUEST "%pv[%s]: " fmt, v, from, ## args); \
} while (0)

    if ( !(efer & EFER_SVME) )
        PRINTF("EFER: SVME bit not set (%#"PRIx64")\n", efer);

    if ( !(cr0 & X86_CR0_CD) && (cr0 & X86_CR0_NW) )
        PRINTF("CR0: CD bit is zero and NW bit set (%#"PRIx64")\n", cr0);

    if ( cr0 >> 32 )
        PRINTF("CR0: bits [63:32] are not zero (%#"PRIx64")\n", cr0);

    if ( (cr0 & X86_CR0_PG) &&
         ((cr3 & 7) ||
          ((!(cr4 & X86_CR4_PAE) || (efer & EFER_LMA)) && (cr3 & 0xfe0)) ||
          ((efer & EFER_LMA) &&
           (cr3 >> v->domain->arch.cpuid->extd.maxphysaddr))) )
        PRINTF("CR3: MBZ bits are set (%#"PRIx64")\n", cr3);

    valid = hvm_cr4_guest_valid_bits(v->domain);
    if ( cr4 & ~valid )
        PRINTF("CR4: invalid value %#lx (valid %#lx, rejected %#lx)\n",
               cr4, valid, cr4 & ~valid);

    if ( vmcb_get_dr6(vmcb) >> 32 )
        PRINTF("DR6: bits [63:32] are not zero (%#"PRIx64")\n",
               vmcb_get_dr6(vmcb));

    if ( vmcb_get_dr7(vmcb) >> 32 )
        PRINTF("DR7: bits [63:32] are not zero (%#"PRIx64")\n",
               vmcb_get_dr7(vmcb));

    if ( efer & ~EFER_KNOWN_MASK )
        PRINTF("EFER: unknown bits are not zero (%#"PRIx64")\n", efer);

    if ( hvm_efer_valid(v, efer, -1) )
        PRINTF("EFER: %s (%"PRIx64")\n", hvm_efer_valid(v, efer, -1), efer);

    if ( (efer & EFER_LME) && (cr0 & X86_CR0_PG) )
    {
        if ( !(cr4 & X86_CR4_PAE) )
            PRINTF("EFER_LME and CR0.PG are both set and CR4.PAE is zero\n");
        if ( !(cr0 & X86_CR0_PE) )
            PRINTF("EFER_LME and CR0.PG are both set and CR0.PE is zero\n");
    }

    if ( (efer & EFER_LME) && (cr0 & X86_CR0_PG) && (cr4 & X86_CR4_PAE) &&
         vmcb->cs.l && vmcb->cs.db )
        PRINTF("EFER_LME, CR0.PG, CR4.PAE, CS.L and CS.D are all non-zero\n");

    if ( !(vmcb_get_general2_intercepts(vmcb) & GENERAL2_INTERCEPT_VMRUN) )
        PRINTF("GENERAL2_INTERCEPT: VMRUN intercept bit is clear (%#"PRIx32")\n",
               vmcb_get_general2_intercepts(vmcb));

    if ( vmcb->event_inj.resvd1 )
        PRINTF("eventinj: MBZ bits are set (%#"PRIx64")\n",
               vmcb->event_inj.raw);

#undef PRINTF
    return ret;
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

    /* Control area */
    BUILD_BUG_ON(offsetof(typeof(vmcb), _pause_filter_thresh) != 0x03c);
    BUILD_BUG_ON(offsetof(typeof(vmcb), _vintr)               != 0x060);
    BUILD_BUG_ON(offsetof(typeof(vmcb), event_inj)            != 0x0a8);
    BUILD_BUG_ON(offsetof(typeof(vmcb), bus_lock_count)       != 0x120);

    /* State Save area */
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
