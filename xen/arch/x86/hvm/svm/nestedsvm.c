/*
 * nestedsvm.c: Nested Virtualization
 * Copyright (c) 2011, Advanced Micro Devices, Inc
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
 *
 */

#include <asm/hvm/support.h>
#include <asm/hvm/svm/emulate.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/nestedsvm.h>
#include <asm/hvm/svm/svmdebug.h>
#include <asm/paging.h> /* paging_mode_hap */
#include <asm/event.h> /* for local_event_delivery_(en|dis)able */
#include <asm/p2m.h> /* p2m_get_pagetable, p2m_get_nestedp2m */


#define NSVM_ERROR_VVMCB        1
#define NSVM_ERROR_VMENTRY      2
 
static void
nestedsvm_vcpu_clgi(struct vcpu *v)
{
    /* clear gif flag */
    vcpu_nestedsvm(v).ns_gif = 0;
    local_event_delivery_disable(); /* mask events for PV drivers */
}

static void
nestedsvm_vcpu_stgi(struct vcpu *v)
{
    /* enable gif flag */
    vcpu_nestedsvm(v).ns_gif = 1;
    local_event_delivery_enable(); /* unmask events for PV drivers */
}

static int
nestedsvm_vmcb_isvalid(struct vcpu *v, uint64_t vmcxaddr)
{
    /* Address must be 4k aligned */
    if ( (vmcxaddr & ~PAGE_MASK) != 0 )
        return 0;

    /* Maximum valid physical address.
     * See AMD BKDG for HSAVE_PA MSR.
     */
    if ( vmcxaddr > 0xfd00000000ULL )
        return 0;

    return 1;
}

int nestedsvm_vmcb_map(struct vcpu *v, uint64_t vmcbaddr)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);

    if (nv->nv_vvmcx != NULL && nv->nv_vvmcxaddr != vmcbaddr) {
        ASSERT(nv->nv_vvmcxaddr != VMCX_EADDR);
        hvm_unmap_guest_frame(nv->nv_vvmcx, 1);
        nv->nv_vvmcx = NULL;
        nv->nv_vvmcxaddr = VMCX_EADDR;
    }

    if (nv->nv_vvmcx == NULL) {
        nv->nv_vvmcx = hvm_map_guest_frame_rw(vmcbaddr >> PAGE_SHIFT, 1);
        if (nv->nv_vvmcx == NULL)
            return 0;
        nv->nv_vvmcxaddr = vmcbaddr;
    }

    return 1;
}

/* Interface methods */
int nsvm_vcpu_initialise(struct vcpu *v)
{
    void *msrpm;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    msrpm = alloc_xenheap_pages(get_order_from_bytes(MSRPM_SIZE), 0);
    svm->ns_cached_msrpm = msrpm;
    if (msrpm == NULL)
        goto err;
    memset(msrpm, 0x0, MSRPM_SIZE);

    msrpm = alloc_xenheap_pages(get_order_from_bytes(MSRPM_SIZE), 0);
    svm->ns_merged_msrpm = msrpm;
    if (msrpm == NULL)
        goto err;
    memset(msrpm, 0x0, MSRPM_SIZE);

    nv->nv_n2vmcx = alloc_vmcb();
    if (nv->nv_n2vmcx == NULL)
        goto err;
    nv->nv_n2vmcx_pa = virt_to_maddr(nv->nv_n2vmcx);

    return 0;

err:
    nsvm_vcpu_destroy(v);
    return -ENOMEM;
}

void nsvm_vcpu_destroy(struct vcpu *v)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    /*
     * When destroying the vcpu, it may be running on behalf of l2 guest.
     * Therefore we need to switch the VMCB pointer back to the l1 vmcb,
     * in order to avoid double free of l2 vmcb and the possible memory leak
     * of l1 vmcb page.
     */
    if (nv->nv_n1vmcx)
        v->arch.hvm_svm.vmcb = nv->nv_n1vmcx;

    if (svm->ns_cached_msrpm) {
        free_xenheap_pages(svm->ns_cached_msrpm,
                           get_order_from_bytes(MSRPM_SIZE));
        svm->ns_cached_msrpm = NULL;
    }
    if (svm->ns_merged_msrpm) {
        free_xenheap_pages(svm->ns_merged_msrpm,
                           get_order_from_bytes(MSRPM_SIZE));
        svm->ns_merged_msrpm = NULL;
    }
    hvm_unmap_guest_frame(nv->nv_vvmcx, 1);
    nv->nv_vvmcx = NULL;
    if (nv->nv_n2vmcx) {
        free_vmcb(nv->nv_n2vmcx);
        nv->nv_n2vmcx = NULL;
        nv->nv_n2vmcx_pa = VMCX_EADDR;
    }
    if (svm->ns_iomap)
        svm->ns_iomap = NULL;
}

int nsvm_vcpu_reset(struct vcpu *v)
{
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    svm->ns_msr_hsavepa = VMCX_EADDR;
    svm->ns_ovvmcb_pa = VMCX_EADDR;

    svm->ns_tscratio = DEFAULT_TSC_RATIO;

    svm->ns_cr_intercepts = 0;
    svm->ns_dr_intercepts = 0;
    svm->ns_exception_intercepts = 0;
    svm->ns_general1_intercepts = 0;
    svm->ns_general2_intercepts = 0;
    svm->ns_lbr_control.bytes = 0;

    svm->ns_hap_enabled = 0;
    svm->ns_vmcb_guestcr3 = 0;
    svm->ns_vmcb_hostcr3 = 0;
    svm->ns_guest_asid = 0;
    svm->ns_hostflags.bytes = 0;
    svm->ns_vmexit.exitinfo1 = 0;
    svm->ns_vmexit.exitinfo2 = 0;

    if (svm->ns_iomap)
        svm->ns_iomap = NULL;

    nestedsvm_vcpu_stgi(v);
    return 0;
}

static uint64_t nestedsvm_fpu_vmentry(uint64_t n1cr0,
    struct vmcb_struct *vvmcb,
    struct vmcb_struct *n1vmcb, struct vmcb_struct *n2vmcb)
{
    uint64_t vcr0;

    vcr0 = vvmcb->_cr0;
    if ( !(n1cr0 & X86_CR0_TS) && (n1vmcb->_cr0 & X86_CR0_TS) ) {
        /* svm_fpu_leave() run while l1 guest was running.
         * Sync FPU state with l2 guest.
         */
        vcr0 |= X86_CR0_TS;
        n2vmcb->_exception_intercepts |= (1U << TRAP_no_device);
    } else if ( !(vcr0 & X86_CR0_TS) && (n2vmcb->_cr0 & X86_CR0_TS) ) {
        /* svm_fpu_enter() run while l1 guest was running.
         * Sync FPU state with l2 guest. */
        vcr0 &= ~X86_CR0_TS;
        n2vmcb->_exception_intercepts &= ~(1U << TRAP_no_device);
    }

    return vcr0;
}

static void nestedsvm_fpu_vmexit(struct vmcb_struct *n1vmcb,
    struct vmcb_struct *n2vmcb, uint64_t n1cr0, uint64_t guest_cr0)
{
    if ( !(guest_cr0 & X86_CR0_TS) && (n2vmcb->_cr0 & X86_CR0_TS) ) {
        /* svm_fpu_leave() run while l2 guest was running.
         * Sync FPU state with l1 guest. */
        n1vmcb->_cr0 |= X86_CR0_TS;
        n1vmcb->_exception_intercepts |= (1U << TRAP_no_device);
    } else if ( !(n1cr0 & X86_CR0_TS) && (n1vmcb->_cr0 & X86_CR0_TS) ) {
        /* svm_fpu_enter() run while l2 guest was running.
         * Sync FPU state with l1 guest. */
        n1vmcb->_cr0 &= ~X86_CR0_TS;
        n1vmcb->_exception_intercepts &= ~(1U << TRAP_no_device);
    }
}

static int nsvm_vcpu_hostsave(struct vcpu *v, unsigned int inst_len)
{
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct vmcb_struct *n1vmcb;

    n1vmcb = nv->nv_n1vmcx;
    ASSERT(n1vmcb != NULL);

    n1vmcb->rip += inst_len;

    /* Save shadowed values. This ensures that the l1 guest
     * cannot override them to break out. */
    n1vmcb->_efer = v->arch.hvm_vcpu.guest_efer;
    n1vmcb->_cr0 = v->arch.hvm_vcpu.guest_cr[0];
    n1vmcb->_cr2 = v->arch.hvm_vcpu.guest_cr[2];
    n1vmcb->_cr4 = v->arch.hvm_vcpu.guest_cr[4];

    /* Remember the host interrupt flag */
    svm->ns_hostflags.fields.rflagsif =
        (n1vmcb->rflags & X86_EFLAGS_IF) ? 1 : 0;

    return 0;
}

int nsvm_vcpu_hostrestore(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct vmcb_struct *n1vmcb, *n2vmcb;
    int rc;

    n1vmcb = nv->nv_n1vmcx;
    n2vmcb = nv->nv_n2vmcx;
    ASSERT(n1vmcb != NULL);
    ASSERT(n2vmcb != NULL);

    /* nsvm_vmcb_prepare4vmexit() already saved register values
     * handled by VMSAVE/VMLOAD into n1vmcb directly.
     */

    /* switch vmcb to l1 guest's vmcb */
    v->arch.hvm_svm.vmcb = n1vmcb;
    v->arch.hvm_svm.vmcb_pa = nv->nv_n1vmcx_pa;

    /* EFER */
    v->arch.hvm_vcpu.guest_efer = n1vmcb->_efer;
    rc = hvm_set_efer(n1vmcb->_efer);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_efer failed, rc: %u\n", rc);

    /* CR4 */
    v->arch.hvm_vcpu.guest_cr[4] = n1vmcb->_cr4;
    rc = hvm_set_cr4(n1vmcb->_cr4);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_cr4 failed, rc: %u\n", rc);

    /* CR0 */
    nestedsvm_fpu_vmexit(n1vmcb, n2vmcb,
        svm->ns_cr0, v->arch.hvm_vcpu.guest_cr[0]);
    v->arch.hvm_vcpu.guest_cr[0] = n1vmcb->_cr0 | X86_CR0_PE;
    n1vmcb->rflags &= ~X86_EFLAGS_VM;
    rc = hvm_set_cr0(n1vmcb->_cr0 | X86_CR0_PE);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_cr0 failed, rc: %u\n", rc);
    svm->ns_cr0 = v->arch.hvm_vcpu.guest_cr[0];

    /* CR2 */
    v->arch.hvm_vcpu.guest_cr[2] = n1vmcb->_cr2;
    hvm_update_guest_cr(v, 2);

    /* CR3 */
    /* Nested paging mode */
    if (nestedhvm_paging_mode_hap(v)) {
        /* host nested paging + guest nested paging. */
        /* hvm_set_cr3() below sets v->arch.hvm_vcpu.guest_cr[3] for us. */
    } else if (paging_mode_hap(v->domain)) {
        /* host nested paging + guest shadow paging. */
        /* hvm_set_cr3() below sets v->arch.hvm_vcpu.guest_cr[3] for us. */
    } else {
        /* host shadow paging + guest shadow paging. */

        /* Reset MMU context  -- XXX (hostrestore) not yet working*/
        if (!pagetable_is_null(v->arch.guest_table))
            put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_null();
        /* hvm_set_cr3() below sets v->arch.hvm_vcpu.guest_cr[3] for us. */
    }
    rc = hvm_set_cr3(n1vmcb->_cr3);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_cr3 failed, rc: %u\n", rc);

    regs->eax = n1vmcb->rax;
    regs->esp = n1vmcb->rsp;
    regs->eip = n1vmcb->rip;
    regs->eflags = n1vmcb->rflags;
    n1vmcb->_dr7 = 0; /* disable all breakpoints */
    n1vmcb->_cpl = 0;

    /* Clear exitintinfo to prevent a fault loop of re-injecting
     * exceptions forever.
     */
    n1vmcb->exitintinfo.bytes = 0;

    /* Cleanbits */
    n1vmcb->cleanbits.bytes = 0;

    return 0;
}

static int nsvm_vmrun_permissionmap(struct vcpu *v, bool_t viopm)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct vmcb_struct *ns_vmcb = nv->nv_vvmcx;
    struct vmcb_struct *host_vmcb = arch_svm->vmcb;
    unsigned long *ns_msrpm_ptr;
    unsigned int i;
    enum hvm_copy_result ret;
    unsigned long *ns_viomap;
    bool_t ioport_80 = 1, ioport_ed = 1;

    ns_msrpm_ptr = (unsigned long *)svm->ns_cached_msrpm;

    ret = hvm_copy_from_guest_phys(svm->ns_cached_msrpm,
                                   ns_vmcb->_msrpm_base_pa, MSRPM_SIZE);
    if (ret != HVMCOPY_okay) {
        gdprintk(XENLOG_ERR, "hvm_copy_from_guest_phys msrpm %u\n", ret);
        return 1;
    }

    /* Check l1 guest io permission map and get a shadow one based on
     * if l1 guest intercepts io ports 0x80 and/or 0xED.
     */
    svm->ns_oiomap_pa = svm->ns_iomap_pa;
    svm->ns_iomap_pa = ns_vmcb->_iopm_base_pa;

    ns_viomap = hvm_map_guest_frame_ro(svm->ns_iomap_pa >> PAGE_SHIFT, 0);
    if ( ns_viomap )
    {
        ioport_80 = test_bit(0x80, ns_viomap);
        ioport_ed = test_bit(0xed, ns_viomap);
        hvm_unmap_guest_frame(ns_viomap, 0);
    }

    svm->ns_iomap = nestedhvm_vcpu_iomap_get(ioport_80, ioport_ed);

    nv->nv_ioport80 = ioport_80;
    nv->nv_ioportED = ioport_ed;

    /* v->arch.hvm_svm.msrpm has type unsigned long, thus
     * BYTES_PER_LONG.
     */
    for (i = 0; i < MSRPM_SIZE / BYTES_PER_LONG; i++)
        svm->ns_merged_msrpm[i] = arch_svm->msrpm[i] | ns_msrpm_ptr[i];

    host_vmcb->_iopm_base_pa =
        (uint64_t)virt_to_maddr(svm->ns_iomap);
    host_vmcb->_msrpm_base_pa =
        (uint64_t)virt_to_maddr(svm->ns_merged_msrpm);

    return 0;
}

static void nestedsvm_vmcb_set_nestedp2m(struct vcpu *v,
    struct vmcb_struct *vvmcb, struct vmcb_struct *n2vmcb)
{
    struct p2m_domain *p2m;

    ASSERT(v != NULL);
    ASSERT(vvmcb != NULL);
    ASSERT(n2vmcb != NULL);
    p2m = p2m_get_nestedp2m(v, vvmcb->_h_cr3);
    n2vmcb->_h_cr3 = pagetable_get_paddr(p2m_get_pagetable(p2m));
}

static int nsvm_vmcb_prepare4vmrun(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct vmcb_struct *ns_vmcb, *n1vmcb, *n2vmcb;
    bool_t vcleanbits_valid;
    int rc;
    uint64_t cr0;

    ns_vmcb = nv->nv_vvmcx;
    n1vmcb = nv->nv_n1vmcx;
    n2vmcb = nv->nv_n2vmcx;
    ASSERT(ns_vmcb != NULL);
    ASSERT(n1vmcb != NULL);
    ASSERT(n2vmcb != NULL);

    /* Check if virtual VMCB cleanbits are valid */
    vcleanbits_valid = 1;
    if (svm->ns_ovvmcb_pa == VMCX_EADDR)
        vcleanbits_valid = 0;
    if (svm->ns_ovvmcb_pa != nv->nv_vvmcxaddr)
        vcleanbits_valid = 0;

#define vcleanbit_set(_name)	\
    (vcleanbits_valid && ns_vmcb->cleanbits.fields._name)

    /* Enable l2 guest intercepts */
    if (!vcleanbit_set(intercepts)) {
        svm->ns_cr_intercepts = ns_vmcb->_cr_intercepts;
        svm->ns_dr_intercepts = ns_vmcb->_dr_intercepts;
        svm->ns_exception_intercepts = ns_vmcb->_exception_intercepts;
        svm->ns_general1_intercepts = ns_vmcb->_general1_intercepts;
        svm->ns_general2_intercepts = ns_vmcb->_general2_intercepts;
    }

    /* We could track the cleanbits of the n1vmcb from
     * last emulated #VMEXIT to this emulated VMRUN to safe the merges
     * below. Those cleanbits would be tracked in an integer field
     * in struct nestedsvm.
     * But this effort is not worth doing because:
     * - Only the intercepts bit of the n1vmcb can effectively be used here 
     * - The CPU runs more instructions for the tracking than can be
     *   safed here.
     * The overhead comes from (ordered from highest to lowest):
     * - svm_ctxt_switch_to (CPU context switching)
     * - svm_fpu_enter, svm_fpu_leave (lazy FPU switching)
     * - emulated CLGI (clears VINTR intercept)
     * - host clears VINTR intercept
     * Test results show that the overhead is high enough that the
     * tracked intercepts bit of the n1vmcb is practically *always* cleared.
     */

    n2vmcb->_cr_intercepts =
        n1vmcb->_cr_intercepts | ns_vmcb->_cr_intercepts;
    n2vmcb->_dr_intercepts =
        n1vmcb->_dr_intercepts | ns_vmcb->_dr_intercepts;
    n2vmcb->_exception_intercepts =
        n1vmcb->_exception_intercepts | ns_vmcb->_exception_intercepts;
    n2vmcb->_general1_intercepts =
        n1vmcb->_general1_intercepts | ns_vmcb->_general1_intercepts;
    n2vmcb->_general2_intercepts =
        n1vmcb->_general2_intercepts | ns_vmcb->_general2_intercepts;

    /* Nested Pause Filter */
    if (ns_vmcb->_general1_intercepts & GENERAL1_INTERCEPT_PAUSE)
        n2vmcb->_pause_filter_count =
            min(n1vmcb->_pause_filter_count, ns_vmcb->_pause_filter_count);
    else
        n2vmcb->_pause_filter_count = n1vmcb->_pause_filter_count;

    /* TSC offset */
    n2vmcb->_tsc_offset = n1vmcb->_tsc_offset + ns_vmcb->_tsc_offset;

    /* Nested IO permission bitmaps */
    rc = nsvm_vmrun_permissionmap(v, vcleanbit_set(iopm));
    if (rc)
        return rc;

    /* ASID - Emulation handled in hvm_asid_handle_vmenter() */

    /* TLB control */
    n2vmcb->tlb_control = ns_vmcb->tlb_control;

    /* Virtual Interrupts */
    if (!vcleanbit_set(tpr)) {
        n2vmcb->_vintr = ns_vmcb->_vintr;
        n2vmcb->_vintr.fields.intr_masking = 1;
    }

    /* Shadow Mode */
    n2vmcb->interrupt_shadow = ns_vmcb->interrupt_shadow;

    /* Exit codes */
    n2vmcb->exitcode = ns_vmcb->exitcode;
    n2vmcb->exitinfo1 = ns_vmcb->exitinfo1;
    n2vmcb->exitinfo2 = ns_vmcb->exitinfo2;
    n2vmcb->exitintinfo = ns_vmcb->exitintinfo;

    /* Pending Interrupts */
    n2vmcb->eventinj = ns_vmcb->eventinj;

    /* LBR virtualization */
    if (!vcleanbit_set(lbr)) {
        svm->ns_lbr_control = ns_vmcb->lbr_control;
    }
    n2vmcb->lbr_control.bytes =
        n1vmcb->lbr_control.bytes | ns_vmcb->lbr_control.bytes;

    /* NextRIP - only evaluated on #VMEXIT. */

    /*
     * VMCB Save State Area
     */

    /* Segments */
    if (!vcleanbit_set(seg)) {
        n2vmcb->es = ns_vmcb->es;
        n2vmcb->cs = ns_vmcb->cs;
        n2vmcb->ss = ns_vmcb->ss;
        n2vmcb->ds = ns_vmcb->ds;
        /* CPL */
        n2vmcb->_cpl = ns_vmcb->_cpl;
    }
    if (!vcleanbit_set(dt)) {
        n2vmcb->gdtr = ns_vmcb->gdtr;
        n2vmcb->idtr = ns_vmcb->idtr;
    }

    /* EFER */
    v->arch.hvm_vcpu.guest_efer = ns_vmcb->_efer;
    rc = hvm_set_efer(ns_vmcb->_efer);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_efer failed, rc: %u\n", rc);

    /* CR4 */
    v->arch.hvm_vcpu.guest_cr[4] = ns_vmcb->_cr4;
    rc = hvm_set_cr4(ns_vmcb->_cr4);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_cr4 failed, rc: %u\n", rc);

    /* CR0 */
    svm->ns_cr0 = v->arch.hvm_vcpu.guest_cr[0];
    cr0 = nestedsvm_fpu_vmentry(svm->ns_cr0, ns_vmcb, n1vmcb, n2vmcb);
    v->arch.hvm_vcpu.guest_cr[0] = ns_vmcb->_cr0;
    rc = hvm_set_cr0(cr0);
    if (rc != X86EMUL_OKAY)
        gdprintk(XENLOG_ERR, "hvm_set_cr0 failed, rc: %u\n", rc);

    /* CR2 */
    v->arch.hvm_vcpu.guest_cr[2] = ns_vmcb->_cr2;
    hvm_update_guest_cr(v, 2);

    /* Nested paging mode */
    if (nestedhvm_paging_mode_hap(v)) {
        /* host nested paging + guest nested paging. */
        n2vmcb->_np_enable = 1;

        nestedsvm_vmcb_set_nestedp2m(v, ns_vmcb, n2vmcb);

        /* hvm_set_cr3() below sets v->arch.hvm_vcpu.guest_cr[3] for us. */
        rc = hvm_set_cr3(ns_vmcb->_cr3);
        if (rc != X86EMUL_OKAY)
            gdprintk(XENLOG_ERR, "hvm_set_cr3 failed, rc: %u\n", rc);
    } else if (paging_mode_hap(v->domain)) {
        /* host nested paging + guest shadow paging. */
        n2vmcb->_np_enable = 1;
        /* Keep h_cr3 as it is. */
        n2vmcb->_h_cr3 = n1vmcb->_h_cr3;
        /* When l1 guest does shadow paging
         * we assume it intercepts page faults.
         */
        /* hvm_set_cr3() below sets v->arch.hvm_vcpu.guest_cr[3] for us. */
        rc = hvm_set_cr3(ns_vmcb->_cr3);
        if (rc != X86EMUL_OKAY)
            gdprintk(XENLOG_ERR, "hvm_set_cr3 failed, rc: %u\n", rc);
    } else {
        /* host shadow paging + guest shadow paging. */
        n2vmcb->_np_enable = 0;
        n2vmcb->_h_cr3 = 0x0;

        /* TODO: Once shadow-shadow paging is in place come back to here
         * and set host_vmcb->_cr3 to the shadowed shadow table.
         */
    }

    /* DRn */
    if (!vcleanbit_set(dr)) {
        n2vmcb->_dr7 = ns_vmcb->_dr7;
        n2vmcb->_dr6 = ns_vmcb->_dr6;
    }

    /* RFLAGS */
    n2vmcb->rflags = ns_vmcb->rflags;

    /* RIP */
    n2vmcb->rip = ns_vmcb->rip;

    /* RSP */
    n2vmcb->rsp = ns_vmcb->rsp;

    /* RAX */
    n2vmcb->rax = ns_vmcb->rax;

    /* Keep the host values of the fs, gs, ldtr, tr, kerngsbase,
     * star, lstar, cstar, sfmask, sysenter_cs, sysenter_esp,
     * sysenter_eip. These are handled via VMSAVE/VMLOAD emulation.
     */

    /* Page tables */
    n2vmcb->pdpe0 = ns_vmcb->pdpe0;
    n2vmcb->pdpe1 = ns_vmcb->pdpe1;
    n2vmcb->pdpe2 = ns_vmcb->pdpe2;
    n2vmcb->pdpe3 = ns_vmcb->pdpe3;

    /* PAT */
    if (!vcleanbit_set(np)) {
        n2vmcb->_g_pat = ns_vmcb->_g_pat;
    }

    if (!vcleanbit_set(lbr)) {
        /* Debug Control MSR */
        n2vmcb->_debugctlmsr = ns_vmcb->_debugctlmsr;

        /* LBR MSRs */
        n2vmcb->_lastbranchfromip = ns_vmcb->_lastbranchfromip;
        n2vmcb->_lastbranchtoip = ns_vmcb->_lastbranchtoip;
        n2vmcb->_lastintfromip = ns_vmcb->_lastintfromip;
        n2vmcb->_lastinttoip = ns_vmcb->_lastinttoip;
    }

    /* Cleanbits */
    n2vmcb->cleanbits.bytes = 0;

    rc = svm_vmcb_isvalid(__func__, ns_vmcb, 1);
    if (rc) {
        gdprintk(XENLOG_ERR, "virtual vmcb invalid\n");
        return NSVM_ERROR_VVMCB;
    }

    rc = svm_vmcb_isvalid(__func__, n2vmcb, 1);
    if (rc) {
        gdprintk(XENLOG_ERR, "n2vmcb invalid\n");
        return NSVM_ERROR_VMENTRY;
    }

    /* Switch guest registers to l2 guest */
    regs->eax = ns_vmcb->rax;
    regs->eip = ns_vmcb->rip;
    regs->esp = ns_vmcb->rsp;
    regs->eflags = ns_vmcb->rflags;

#undef vcleanbit_set
    return 0;
}

static int
nsvm_vcpu_vmentry(struct vcpu *v, struct cpu_user_regs *regs,
    unsigned int inst_len)
{
    int ret;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct vmcb_struct *ns_vmcb;

    ns_vmcb = nv->nv_vvmcx;
    ASSERT(ns_vmcb != NULL);
    ASSERT(nv->nv_n2vmcx != NULL);
    ASSERT(nv->nv_n2vmcx_pa != VMCX_EADDR);

    /* Save values for later use. Needed for Nested-on-Nested and
     * Shadow-on-Shadow paging.
     */
    svm->ns_vmcb_guestcr3 = ns_vmcb->_cr3;
    svm->ns_vmcb_hostcr3 = ns_vmcb->_h_cr3;

    /* Convert explicitely to boolean. Deals with l1 guests
     * that use flush-by-asid w/o checking the cpuid bits */
    nv->nv_flushp2m = !!ns_vmcb->tlb_control;
    if ( svm->ns_guest_asid != ns_vmcb->_guest_asid )
    {
        nv->nv_flushp2m = 1;
        hvm_asid_flush_vcpu_asid(&vcpu_nestedhvm(v).nv_n2asid);
        svm->ns_guest_asid = ns_vmcb->_guest_asid;
    }

    /* nested paging for the guest */
    svm->ns_hap_enabled = (ns_vmcb->_np_enable) ? 1 : 0;

    /* Remember the V_INTR_MASK in hostflags */
    svm->ns_hostflags.fields.vintrmask =
        (ns_vmcb->_vintr.fields.intr_masking) ? 1 : 0;

    /* Save l1 guest state (= host state) */
    ret = nsvm_vcpu_hostsave(v, inst_len);
    if (ret) {
        gdprintk(XENLOG_ERR, "hostsave failed, ret = %i\n", ret);
        return ret;
    }

    /* switch vmcb to shadow vmcb */
    v->arch.hvm_svm.vmcb = nv->nv_n2vmcx;
    v->arch.hvm_svm.vmcb_pa = nv->nv_n2vmcx_pa;

    ret = nsvm_vmcb_prepare4vmrun(v, regs);
    if (ret) {
        gdprintk(XENLOG_ERR, "prepare4vmrun failed, ret = %i\n", ret);
        return ret;
    }

    nestedsvm_vcpu_stgi(v);
    return 0;
}

int
nsvm_vcpu_vmrun(struct vcpu *v, struct cpu_user_regs *regs)
{
    int ret;
    unsigned int inst_len;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    inst_len = __get_instruction_length(v, INSTR_VMRUN);
    if (inst_len == 0) {
        svm->ns_vmexit.exitcode = VMEXIT_SHUTDOWN;
        return -1;
    }

    nv->nv_vmswitch_in_progress = 1;
    ASSERT(nv->nv_vvmcx != NULL);

    /* save host state */
    ret = nsvm_vcpu_vmentry(v, regs, inst_len);

    /* Switch vcpu to guest mode. In the error case
     * this ensures the host mode is restored correctly
     * and l1 guest keeps alive. */
    nestedhvm_vcpu_enter_guestmode(v);

    switch (ret) {
    case 0:
        break;
    case NSVM_ERROR_VVMCB:
        gdprintk(XENLOG_ERR, "inject VMEXIT(INVALID)\n");
        svm->ns_vmexit.exitcode = VMEXIT_INVALID;
        return -1;
    case NSVM_ERROR_VMENTRY:
    default:
        gdprintk(XENLOG_ERR,
            "nsvm_vcpu_vmentry failed, injecting #UD\n");
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        /* Must happen after hvm_inject_hw_exception or it doesn't work right. */
        nv->nv_vmswitch_in_progress = 0;
        return 1;
    }

    /* If l1 guest uses shadow paging, update the paging mode. */
    if (!nestedhvm_paging_mode_hap(v))
        paging_update_paging_modes(v);

    nv->nv_vmswitch_in_progress = 0;
    return 0;
}

int
nsvm_vcpu_vmexit_inject(struct vcpu *v, struct cpu_user_regs *regs,
    uint64_t exitcode)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct vmcb_struct *ns_vmcb;

    ASSERT(svm->ns_gif == 0);
    ns_vmcb = nv->nv_vvmcx;

    if (nv->nv_vmexit_pending) {

        switch (exitcode) {
        case VMEXIT_INTR:
            if ( unlikely(ns_vmcb->eventinj.fields.v)
                && nv->nv_vmentry_pending
                && hvm_event_needs_reinjection(ns_vmcb->eventinj.fields.type,
                    ns_vmcb->eventinj.fields.vector) )
            {
                ns_vmcb->exitintinfo.bytes = ns_vmcb->eventinj.bytes;
            }
            break;
        case VMEXIT_EXCEPTION_PF:
            ns_vmcb->_cr2 = ns_vmcb->exitinfo2;
            /* fall through */
        case VMEXIT_NPF:
            /* PF error code */
            ns_vmcb->exitinfo1 = svm->ns_vmexit.exitinfo1;
            /* fault address */
            ns_vmcb->exitinfo2 = svm->ns_vmexit.exitinfo2;
            break;
        case VMEXIT_EXCEPTION_NP:
        case VMEXIT_EXCEPTION_SS:
        case VMEXIT_EXCEPTION_GP:
        case VMEXIT_EXCEPTION_15:
        case VMEXIT_EXCEPTION_MF:
        case VMEXIT_EXCEPTION_AC:
            ns_vmcb->exitinfo1 = svm->ns_vmexit.exitinfo1;
            break;
        default:
            break;
        }
    }

    ns_vmcb->exitcode = exitcode;
    ns_vmcb->eventinj.bytes = 0;
    return 0;
}

int
nsvm_vcpu_vmexit_trap(struct vcpu *v, struct hvm_trap *trap)
{
    ASSERT(vcpu_nestedhvm(v).nv_vvmcx != NULL);

    nestedsvm_vmexit_defer(v, VMEXIT_EXCEPTION_DE + trap->vector,
                           trap->error_code, trap->cr2);
    return NESTEDHVM_VMEXIT_DONE;
}

uint64_t nsvm_vcpu_guestcr3(struct vcpu *v)
{
    return vcpu_nestedsvm(v).ns_vmcb_guestcr3;
}

uint64_t nsvm_vcpu_hostcr3(struct vcpu *v)
{
    return vcpu_nestedsvm(v).ns_vmcb_hostcr3;
}

uint32_t nsvm_vcpu_asid(struct vcpu *v)
{
    return vcpu_nestedsvm(v).ns_guest_asid;
}

static int
nsvm_vmcb_guest_intercepts_msr(unsigned long *msr_bitmap,
    uint32_t msr, bool_t write)
{
    bool_t enabled;
    unsigned long *msr_bit;

    msr_bit = svm_msrbit(msr_bitmap, msr);

    if (msr_bit == NULL)
        /* MSR not in the permission map: Let the guest handle it. */
        return NESTEDHVM_VMEXIT_INJECT;

    msr &= 0x1fff;

    if (write)
        /* write access */
        enabled = test_bit(msr * 2 + 1, msr_bit);
    else
        /* read access */
        enabled = test_bit(msr * 2, msr_bit);

    if (!enabled)
        return NESTEDHVM_VMEXIT_HOST;

    return NESTEDHVM_VMEXIT_INJECT;
}

static int
nsvm_vmcb_guest_intercepts_ioio(paddr_t iopm_pa, uint64_t exitinfo1)
{
    unsigned long gfn = iopm_pa >> PAGE_SHIFT;
    unsigned long *io_bitmap;
    ioio_info_t ioinfo;
    uint16_t port;
    unsigned int size;
    bool_t enabled;

    ioinfo.bytes = exitinfo1;
    port = ioinfo.fields.port;
    size = ioinfo.fields.sz32 ? 4 : ioinfo.fields.sz16 ? 2 : 1;

    switch ( port )
    {
    case 0 ... 8 * PAGE_SIZE - 1: /* first 4KB page */
        break;
    case 8 * PAGE_SIZE ... 2 * 8 * PAGE_SIZE - 1: /* second 4KB page */
        port -= 8 * PAGE_SIZE;
        ++gfn;
        break;
    default:
        BUG();
        break;
    }

    for ( io_bitmap = hvm_map_guest_frame_ro(gfn, 0); ; )
    {
        enabled = io_bitmap && test_bit(port, io_bitmap);
        if ( !enabled || !--size )
            break;
        if ( unlikely(++port == 8 * PAGE_SIZE) )
        {
            hvm_unmap_guest_frame(io_bitmap, 0);
            io_bitmap = hvm_map_guest_frame_ro(++gfn, 0);
            port -= 8 * PAGE_SIZE;
        }
    }
    hvm_unmap_guest_frame(io_bitmap, 0);

    if ( !enabled )
        return NESTEDHVM_VMEXIT_HOST;

    return NESTEDHVM_VMEXIT_INJECT;
}

int
nsvm_vmcb_guest_intercepts_exitcode(struct vcpu *v,
    struct cpu_user_regs *regs, uint64_t exitcode)
{
    uint64_t exit_bits;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct vmcb_struct *ns_vmcb = nv->nv_vvmcx;
    enum nestedhvm_vmexits vmexits;

    switch (exitcode) {
    case VMEXIT_CR0_READ ... VMEXIT_CR15_READ:
    case VMEXIT_CR0_WRITE ... VMEXIT_CR15_WRITE:
        exit_bits = 1ULL << (exitcode - VMEXIT_CR0_READ);
        if (svm->ns_cr_intercepts & exit_bits)
            break;
        return 0;

    case VMEXIT_DR0_READ ... VMEXIT_DR7_READ:
    case VMEXIT_DR0_WRITE ... VMEXIT_DR7_WRITE:
        exit_bits = 1ULL << (exitcode - VMEXIT_DR0_READ);
        if (svm->ns_dr_intercepts & exit_bits)
            break;
        return 0;

    case VMEXIT_EXCEPTION_DE ... VMEXIT_EXCEPTION_XF:
        exit_bits = 1ULL << (exitcode - VMEXIT_EXCEPTION_DE);
        if (svm->ns_exception_intercepts & exit_bits)
            break;
        return 0;

    case VMEXIT_INTR ... VMEXIT_SHUTDOWN:
        exit_bits = 1ULL << (exitcode - VMEXIT_INTR);
        if (svm->ns_general1_intercepts & exit_bits)
            break;
        return 0;

    case VMEXIT_VMRUN ... VMEXIT_XSETBV:
        exit_bits = 1ULL << (exitcode - VMEXIT_VMRUN);
        if (svm->ns_general2_intercepts & exit_bits)
            break;
        return 0;

    case VMEXIT_NPF:
        if (nestedhvm_paging_mode_hap(v))
            break;
        return 0;
    case VMEXIT_INVALID:
        /* Always intercepted */
        break;

    default:
        gdprintk(XENLOG_ERR, "Illegal exitcode %#"PRIx64"\n", exitcode);
        BUG();
        break;
    }

    /* Special cases: Do more detailed checks */
    switch (exitcode) {
    case VMEXIT_MSR:
        ASSERT(regs != NULL);
        if ( !nestedsvm_vmcb_map(v, nv->nv_vvmcxaddr) )
            break;
        ns_vmcb = nv->nv_vvmcx;
        vmexits = nsvm_vmcb_guest_intercepts_msr(svm->ns_cached_msrpm,
            regs->ecx, ns_vmcb->exitinfo1 != 0);
        if (vmexits == NESTEDHVM_VMEXIT_HOST)
            return 0;
        break;
    case VMEXIT_IOIO:
        if ( !nestedsvm_vmcb_map(v, nv->nv_vvmcxaddr) )
            break;
        ns_vmcb = nv->nv_vvmcx;
        vmexits = nsvm_vmcb_guest_intercepts_ioio(ns_vmcb->_iopm_base_pa,
            ns_vmcb->exitinfo1);
        if (vmexits == NESTEDHVM_VMEXIT_HOST)
            return 0;
        break;
    }

    return 1;
}

int
nsvm_vmcb_guest_intercepts_trap(struct vcpu *v, unsigned int trapnr, int errcode)
{
    return nsvm_vmcb_guest_intercepts_exitcode(v,
        guest_cpu_user_regs(), VMEXIT_EXCEPTION_DE + trapnr);
}

static int
nsvm_vmcb_prepare4vmexit(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct vmcb_struct *ns_vmcb = nv->nv_vvmcx;
    struct vmcb_struct *n2vmcb = nv->nv_n2vmcx;

    svm_vmsave(nv->nv_n1vmcx);

    /* Cache guest physical address of virtual vmcb
     * for VMCB Cleanbit emulation.
     */
    svm->ns_ovvmcb_pa = nv->nv_vvmcxaddr;

    /* Intercepts - keep them as they are */

    /* Pausefilter - keep it as is */

    /* Nested IO permission bitmap */
    /* Just keep the iopm_base_pa and msrpm_base_pa values.
     * The guest must not see the virtualized values.
     */

    /* TSC offset */
    /* Keep it. It's maintainted by the l1 guest. */ 

    /* ASID */
    /* ns_vmcb->_guest_asid = n2vmcb->_guest_asid; */

    /* TLB control */
    ns_vmcb->tlb_control = 0;

    /* Virtual Interrupts */
    ns_vmcb->_vintr = n2vmcb->_vintr;
    if (!(svm->ns_hostflags.fields.vintrmask))
        ns_vmcb->_vintr.fields.intr_masking = 0;

    /* Shadow mode */
    ns_vmcb->interrupt_shadow = n2vmcb->interrupt_shadow;

    /* Exit codes */
    ns_vmcb->exitcode = n2vmcb->exitcode;
    ns_vmcb->exitinfo1 = n2vmcb->exitinfo1;
    ns_vmcb->exitinfo2 = n2vmcb->exitinfo2;
    ns_vmcb->exitintinfo = n2vmcb->exitintinfo;

    /* Interrupts */
    /* If we emulate a VMRUN/#VMEXIT in the same host #VMEXIT cycle we have
     * to make sure that we do not lose injected events. So check eventinj
     * here and copy it to exitintinfo if it is valid.
     * exitintinfo and eventinj can't be both valid because the case below
     * only happens on a VMRUN instruction intercept which has no valid
     * exitintinfo set.
     */
    if ( unlikely(n2vmcb->eventinj.fields.v) &&
         hvm_event_needs_reinjection(n2vmcb->eventinj.fields.type,
                                     n2vmcb->eventinj.fields.vector) )
    {
        ns_vmcb->exitintinfo = n2vmcb->eventinj;
    }

    ns_vmcb->eventinj.bytes = 0;

    /* Nested paging mode */
    if (nestedhvm_paging_mode_hap(v)) {
        /* host nested paging + guest nested paging. */
        ns_vmcb->_np_enable = n2vmcb->_np_enable;
        ns_vmcb->_cr3 = n2vmcb->_cr3;
        /* The vmcb->h_cr3 is the shadowed h_cr3. The original
         * unshadowed guest h_cr3 is kept in ns_vmcb->h_cr3,
         * hence we keep the ns_vmcb->h_cr3 value. */
    } else if (paging_mode_hap(v->domain)) {
        /* host nested paging + guest shadow paging. */
        ns_vmcb->_np_enable = 0;
        /* Throw h_cr3 away. Guest is not allowed to set it or
         * it can break out, otherwise (security hole!) */
        ns_vmcb->_h_cr3 = 0x0;
        /* Stop intercepting #PF (already done above
         * by restoring cached intercepts). */
        ns_vmcb->_cr3 = n2vmcb->_cr3;
    } else {
        /* host shadow paging + guest shadow paging. */
        ns_vmcb->_np_enable = 0;
        ns_vmcb->_h_cr3 = 0x0;
        /* The vmcb->_cr3 is the shadowed cr3. The original
         * unshadowed guest cr3 is kept in ns_vmcb->_cr3,
         * hence we keep the ns_vmcb->_cr3 value. */
    }

    /* LBR virtualization - keep lbr control as is */

    /* NextRIP */
    ns_vmcb->nextrip = n2vmcb->nextrip;

    /* Decode Assist */
    ns_vmcb->guest_ins_len = n2vmcb->guest_ins_len;
    memcpy(ns_vmcb->guest_ins, n2vmcb->guest_ins, sizeof(ns_vmcb->guest_ins));

    /*
     * VMCB Save State Area
     */

    /* Segments */
    ns_vmcb->es = n2vmcb->es;
    ns_vmcb->cs = n2vmcb->cs;
    ns_vmcb->ss = n2vmcb->ss;
    ns_vmcb->ds = n2vmcb->ds;
    ns_vmcb->gdtr = n2vmcb->gdtr;
    ns_vmcb->idtr = n2vmcb->idtr;

    /* CPL */
    ns_vmcb->_cpl = n2vmcb->_cpl;

    /* EFER */
    ns_vmcb->_efer = n2vmcb->_efer;

    /* CRn */
    ns_vmcb->_cr4 = n2vmcb->_cr4;
    ns_vmcb->_cr0 = n2vmcb->_cr0;

    /* DRn */
    ns_vmcb->_dr7 = n2vmcb->_dr7;
    ns_vmcb->_dr6 = n2vmcb->_dr6;

    /* Restore registers from regs as those values
     * can be newer than in n2vmcb (e.g. due to an
     * instruction emulation right before).
     */

    /* RFLAGS */
    ns_vmcb->rflags = n2vmcb->rflags = regs->rflags;

    /* RIP */
    ns_vmcb->rip = n2vmcb->rip = regs->rip;

    /* RSP */
    ns_vmcb->rsp = n2vmcb->rsp = regs->rsp;

    /* RAX */
    ns_vmcb->rax = n2vmcb->rax = regs->rax;

    /* Keep the l2 guest values of the fs, gs, ldtr, tr, kerngsbase,
     * star, lstar, cstar, sfmask, sysenter_cs, sysenter_esp,
     * sysenter_eip. These are handled via VMSAVE/VMLOAD emulation.
     */

    /* CR2 */
    ns_vmcb->_cr2 = n2vmcb->_cr2;

    /* Page tables */
    ns_vmcb->pdpe0 = n2vmcb->pdpe0;
    ns_vmcb->pdpe1 = n2vmcb->pdpe1;
    ns_vmcb->pdpe2 = n2vmcb->pdpe2;
    ns_vmcb->pdpe3 = n2vmcb->pdpe3;

    /* PAT */
    ns_vmcb->_g_pat = n2vmcb->_g_pat;

    /* Debug Control MSR */
    ns_vmcb->_debugctlmsr = n2vmcb->_debugctlmsr;

    /* LBR MSRs */
    ns_vmcb->_lastbranchfromip = n2vmcb->_lastbranchfromip;
    ns_vmcb->_lastbranchtoip = n2vmcb->_lastbranchtoip;
    ns_vmcb->_lastintfromip = n2vmcb->_lastintfromip;
    ns_vmcb->_lastinttoip = n2vmcb->_lastinttoip;

    return 0;
}

bool_t
nsvm_vmcb_hap_enabled(struct vcpu *v)
{
    return vcpu_nestedsvm(v).ns_hap_enabled;
}

/* This function uses L2_gpa to walk the P2M page table in L1. If the
 * walk is successful, the translated value is returned in
 * L1_gpa. The result value tells what to do next.
 */
int
nsvm_hap_walk_L1_p2m(struct vcpu *v, paddr_t L2_gpa, paddr_t *L1_gpa,
                     unsigned int *page_order, uint8_t *p2m_acc,
                     bool_t access_r, bool_t access_w, bool_t access_x)
{
    uint32_t pfec;
    unsigned long nested_cr3, gfn;

    nested_cr3 = nhvm_vcpu_p2m_base(v);

    pfec = PFEC_user_mode | PFEC_page_present;
    if ( access_w )
        pfec |= PFEC_write_access;
    if ( access_x )
        pfec |= PFEC_insn_fetch;

    /* Walk the guest-supplied NPT table, just as if it were a pagetable */
    gfn = paging_ga_to_gfn_cr3(v, nested_cr3, L2_gpa, &pfec, page_order);

    if ( gfn == INVALID_GFN )
        return NESTEDHVM_PAGEFAULT_INJECT;

    *L1_gpa = (gfn << PAGE_SHIFT) + (L2_gpa & ~PAGE_MASK);
    return NESTEDHVM_PAGEFAULT_DONE;
}

enum hvm_intblk nsvm_intr_blocked(struct vcpu *v)
{
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);

    ASSERT(nestedhvm_enabled(v->domain));

    if ( !nestedsvm_gif_isset(v) )
        return hvm_intblk_svm_gif;

    if ( nestedhvm_vcpu_in_guestmode(v) ) {
        struct vmcb_struct *n2vmcb = nv->nv_n2vmcx;

        if ( svm->ns_hostflags.fields.vintrmask )
            if ( !svm->ns_hostflags.fields.rflagsif )
                return hvm_intblk_rflags_ie;

        /* when l1 guest passes its devices through to the l2 guest
         * and l2 guest does an MMIO access then we may want to
         * inject an VMEXIT(#INTR) exitcode into the l1 guest.
         * Delay the injection because this would result in delivering
         * an interrupt *within* the execution of an instruction.
         */
        if ( v->arch.hvm_vcpu.hvm_io.io_state != HVMIO_none )
            return hvm_intblk_shadow;

        if ( !nv->nv_vmexit_pending && n2vmcb->exitintinfo.bytes != 0 ) {
            /* Give the l2 guest a chance to finish the delivery of
             * the last injected interrupt or exception before we
             * emulate a VMEXIT (e.g. VMEXIT(INTR) ).
             */
            return hvm_intblk_shadow;
        }
    }

    if ( nv->nv_vmexit_pending ) {
        /* hvm_inject_hw_exception() must have run before.
         * exceptions have higher priority than interrupts.
         */
        return hvm_intblk_rflags_ie;
    }

    return hvm_intblk_none;
}

/* MSR handling */
int nsvm_rdmsr(struct vcpu *v, unsigned int msr, uint64_t *msr_content)
{
    struct nestedsvm *svm = &vcpu_nestedsvm(v);
    int ret = 1;

    *msr_content = 0;

    switch (msr) {
    case MSR_K8_VM_CR:
        break;
    case MSR_K8_VM_HSAVE_PA:
        *msr_content = svm->ns_msr_hsavepa;
        break;
    case MSR_AMD64_TSC_RATIO:
        *msr_content = svm->ns_tscratio;
        break;
    default:
        ret = 0;
        break;
    }

    return ret;
}

int nsvm_wrmsr(struct vcpu *v, unsigned int msr, uint64_t msr_content)
{
    int ret = 1;
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    switch (msr) {
    case MSR_K8_VM_CR:
        /* ignore write. handle all bits as read-only. */
        break;
    case MSR_K8_VM_HSAVE_PA:
        if (!nestedsvm_vmcb_isvalid(v, msr_content)) {
            gdprintk(XENLOG_ERR,
                "MSR_K8_VM_HSAVE_PA value invalid %#"PRIx64"\n", msr_content);
            ret = -1; /* inject #GP */
            break;
        }
        svm->ns_msr_hsavepa = msr_content;
        break;
    case MSR_AMD64_TSC_RATIO:
        if ((msr_content & ~TSC_RATIO_RSVD_BITS) != msr_content) {
            gdprintk(XENLOG_ERR,
                "reserved bits set in MSR_AMD64_TSC_RATIO %#"PRIx64"\n",
                msr_content);
            ret = -1; /* inject #GP */
            break;
        }
        svm->ns_tscratio = msr_content;
        break;
    default:
        ret = 0;
        break;
    }

    return ret;
}

/* VMEXIT emulation */
void
nestedsvm_vmexit_defer(struct vcpu *v,
    uint64_t exitcode, uint64_t exitinfo1, uint64_t exitinfo2)
{
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    nestedsvm_vcpu_clgi(v);
    svm->ns_vmexit.exitcode = exitcode;
    svm->ns_vmexit.exitinfo1 = exitinfo1;
    svm->ns_vmexit.exitinfo2 = exitinfo2;
    vcpu_nestedhvm(v).nv_vmexit_pending = 1;
}

enum nestedhvm_vmexits
nestedsvm_check_intercepts(struct vcpu *v, struct cpu_user_regs *regs,
    uint64_t exitcode)
{
    bool_t is_intercepted;

    ASSERT(vcpu_nestedhvm(v).nv_vmexit_pending == 0);
    is_intercepted = nsvm_vmcb_guest_intercepts_exitcode(v, regs, exitcode);

    switch (exitcode) {
    case VMEXIT_INVALID:
        if (is_intercepted)
            return NESTEDHVM_VMEXIT_INJECT;
        return NESTEDHVM_VMEXIT_HOST;

    case VMEXIT_INTR:
    case VMEXIT_NMI:
        return NESTEDHVM_VMEXIT_HOST;
    case VMEXIT_EXCEPTION_NM:
        /* Host must handle lazy fpu context switching first.
         * Then inject the VMEXIT if L1 guest intercepts this.
         */
        return NESTEDHVM_VMEXIT_HOST;

    case VMEXIT_NPF:
        if (nestedhvm_paging_mode_hap(v)) {
            if (!is_intercepted)
                return NESTEDHVM_VMEXIT_FATALERROR;
            /* host nested paging + guest nested paging */
            return NESTEDHVM_VMEXIT_HOST;
        }
        if (paging_mode_hap(v->domain)) {
            if (is_intercepted)
                return NESTEDHVM_VMEXIT_FATALERROR;
            /* host nested paging + guest shadow paging */
            return NESTEDHVM_VMEXIT_HOST;
        }
        /* host shadow paging + guest shadow paging */
        /* Can this happen? */
        BUG();
        return NESTEDHVM_VMEXIT_FATALERROR;
    case VMEXIT_EXCEPTION_PF:
        if (nestedhvm_paging_mode_hap(v)) {
            /* host nested paging + guest nested paging */
            if (!is_intercepted)
                /* l1 guest intercepts #PF unnecessarily */
                return NESTEDHVM_VMEXIT_HOST;
            /* l2 guest intercepts #PF unnecessarily */
            return NESTEDHVM_VMEXIT_INJECT;
        }
        if (!paging_mode_hap(v->domain)) {
            /* host shadow paging + guest shadow paging */
            return NESTEDHVM_VMEXIT_HOST;
        }
        /* host nested paging + guest shadow paging */
        return NESTEDHVM_VMEXIT_INJECT;
    case VMEXIT_VMMCALL:
        /* Always let the guest handle VMMCALL/VMCALL */
        return NESTEDHVM_VMEXIT_INJECT;
    default:
        break;
    }

    if (is_intercepted)
        return NESTEDHVM_VMEXIT_INJECT;
    return NESTEDHVM_VMEXIT_HOST;
}

enum nestedhvm_vmexits
nestedsvm_vmexit_n2n1(struct vcpu *v, struct cpu_user_regs *regs)
{
    int rc;
    enum nestedhvm_vmexits ret = NESTEDHVM_VMEXIT_DONE;

    ASSERT(vcpu_nestedhvm(v).nv_vmswitch_in_progress);
    ASSERT(nestedhvm_vcpu_in_guestmode(v));

    rc = nsvm_vmcb_prepare4vmexit(v, regs);
    if (rc)
        ret = NESTEDHVM_VMEXIT_ERROR;

    rc = nhvm_vcpu_hostrestore(v, regs);
    if (rc)
        ret = NESTEDHVM_VMEXIT_FATALERROR;

    nestedhvm_vcpu_exit_guestmode(v);
    return ret;
}

/* The exitcode is in native SVM/VMX format. The forced exitcode
 * is in generic format.
 */
static enum nestedhvm_vmexits
nestedsvm_vcpu_vmexit(struct vcpu *v, struct cpu_user_regs *regs,
    uint64_t exitcode)
{
    int rc;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);

    nv->nv_vmswitch_in_progress = 1;

    ASSERT(nv->nv_vvmcx != NULL);

    /* On special intercepts the host has to handle
     * the vcpu is still in guest mode here.
     */
    if (nestedhvm_vcpu_in_guestmode(v)) {
        enum nestedhvm_vmexits ret;

        ret = nestedsvm_vmexit_n2n1(v, regs);
        switch (ret) {
        case NESTEDHVM_VMEXIT_FATALERROR:
            gdprintk(XENLOG_ERR, "VMEXIT: fatal error\n");
            return ret;
        case NESTEDHVM_VMEXIT_HOST:
            BUG();
            return ret;
        case NESTEDHVM_VMEXIT_ERROR:
            exitcode = VMEXIT_INVALID;
            break;
        default:
            ASSERT(!nestedhvm_vcpu_in_guestmode(v));
            break;
        }

        /* host state has been restored */
    }

    ASSERT(!nestedhvm_vcpu_in_guestmode(v));

    /* Prepare for running the l1 guest. Make the actual
     * modifications to the virtual VMCB/VMCS.
     */
    rc = nhvm_vcpu_vmexit(v, regs, exitcode);

    /* If l1 guest uses shadow paging, update the paging mode. */
    if (!nestedhvm_paging_mode_hap(v))
        paging_update_paging_modes(v);

    nv->nv_vmswitch_in_progress = 0;

    if (rc)
        return NESTEDHVM_VMEXIT_FATALERROR;

    return NESTEDHVM_VMEXIT_DONE;
}

/* VCPU switch */
void nsvm_vcpu_switch(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct nestedvcpu *nv;
    struct nestedsvm *svm;

    if (!nestedhvm_enabled(v->domain))
        return;

    nv = &vcpu_nestedhvm(v);
    svm = &vcpu_nestedsvm(v);
    ASSERT(v->arch.hvm_svm.vmcb != NULL);
    ASSERT(nv->nv_n1vmcx != NULL);
    ASSERT(nv->nv_n2vmcx != NULL);
    ASSERT(nv->nv_n1vmcx_pa != VMCX_EADDR);
    ASSERT(nv->nv_n2vmcx_pa != VMCX_EADDR);

    if (nv->nv_vmexit_pending) {
 vmexit:
        nestedsvm_vcpu_vmexit(v, regs, svm->ns_vmexit.exitcode);
        nv->nv_vmexit_pending = 0;
        nv->nv_vmentry_pending = 0;
        return;
    }
    if (nv->nv_vmentry_pending) {
        int ret;
        ASSERT(!nv->nv_vmexit_pending);
        ret = nsvm_vcpu_vmrun(v, regs);
        if (ret)
            goto vmexit;

        ASSERT(nestedhvm_vcpu_in_guestmode(v));
        nv->nv_vmentry_pending = 0;
    }

    if (nestedhvm_vcpu_in_guestmode(v)
       && nestedhvm_paging_mode_hap(v))
    {
        /* In case left the l2 guest due to a physical interrupt (e.g. IPI)
         * that is not for the l1 guest then we continue running the l2 guest
         * but check if the nestedp2m is still valid.
         */
        if (nv->nv_p2m == NULL)
            nestedsvm_vmcb_set_nestedp2m(v, nv->nv_vvmcx, nv->nv_n2vmcx);
    }
}

/* Interrupts, Virtual GIF */
int
nestedsvm_vcpu_interrupt(struct vcpu *v, const struct hvm_intack intack)
{
    int ret;
    enum hvm_intblk intr;
    uint64_t exitcode = VMEXIT_INTR;
    uint64_t exitinfo2 = 0;
    ASSERT(nestedhvm_vcpu_in_guestmode(v));

    intr = nhvm_interrupt_blocked(v);
    if ( intr != hvm_intblk_none )
        return NSVM_INTR_MASKED;

    switch (intack.source) {
    case hvm_intsrc_pic:
    case hvm_intsrc_lapic:
    case hvm_intsrc_vector:
        exitcode = VMEXIT_INTR;
        exitinfo2 = intack.vector;
        break;
    case hvm_intsrc_nmi:
        exitcode = VMEXIT_NMI;
        exitinfo2 = intack.vector;
        break;
    case hvm_intsrc_mce:
        exitcode = VMEXIT_EXCEPTION_MC;
        exitinfo2 = intack.vector;
        break;
    case hvm_intsrc_none:
        return NSVM_INTR_NOTHANDLED;
    default:
        BUG();
    }

    ret = nsvm_vmcb_guest_intercepts_exitcode(v,
                                     guest_cpu_user_regs(), exitcode);
    if (ret) {
        nestedsvm_vmexit_defer(v, exitcode, intack.source, exitinfo2);
        return NSVM_INTR_FORCEVMEXIT;
    }

    return NSVM_INTR_NOTINTERCEPTED;
}

bool_t
nestedsvm_gif_isset(struct vcpu *v)
{
    struct nestedsvm *svm = &vcpu_nestedsvm(v);

    return (!!svm->ns_gif);
}

void svm_vmexit_do_stgi(struct cpu_user_regs *regs, struct vcpu *v)
{
    unsigned int inst_len;

    if ( !nestedhvm_enabled(v->domain) ) {
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        return;
    }

    if ( (inst_len = __get_instruction_length(v, INSTR_STGI)) == 0 )
        return;

    nestedsvm_vcpu_stgi(v);

    __update_guest_eip(regs, inst_len);
}

void svm_vmexit_do_clgi(struct cpu_user_regs *regs, struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int inst_len;
    uint32_t general1_intercepts = vmcb_get_general1_intercepts(vmcb);
    vintr_t intr;

    if ( !nestedhvm_enabled(v->domain) ) {
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        return;
    }

    if ( (inst_len = __get_instruction_length(v, INSTR_CLGI)) == 0 )
        return;

    nestedsvm_vcpu_clgi(v);

    /* After a CLGI no interrupts should come */
    intr = vmcb_get_vintr(vmcb);
    intr.fields.irq = 0;
    general1_intercepts &= ~GENERAL1_INTERCEPT_VINTR;
    vmcb_set_vintr(vmcb, intr);
    vmcb_set_general1_intercepts(vmcb, general1_intercepts);

    __update_guest_eip(regs, inst_len);
}
