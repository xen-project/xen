/*
 * vmcb.c: VMCB management
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/paging.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/intr.h>
#include <asm/hvm/svm/asid.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/domain_page.h>
#include <xen/keyhandler.h>

extern int svm_dbg_on;

#define IOPM_SIZE   (12 * 1024)
#define MSRPM_SIZE  (8  * 1024)

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

struct host_save_area *alloc_host_save_area(void)
{
    struct host_save_area *hsa;

    hsa = alloc_xenheap_page();
    if ( hsa == NULL )
    {
        printk(XENLOG_WARNING "Warning: failed to allocate hsa.\n");
        return NULL;
    }

    clear_page(hsa);
    return hsa;
}

void svm_intercept_msr(struct vcpu *v, uint32_t msr, int enable)
{
    unsigned long *msr_bitmap = v->arch.hvm_svm.msrpm;
    unsigned long *msr_bit = NULL;

    /*
     * See AMD64 Programmers Manual, Vol 2, Section 15.10 (MSR-Bitmap Address).
     */
    if ( msr <= 0x1fff )
        msr_bit = msr_bitmap + 0x0000 / BYTES_PER_LONG;
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
        msr_bit = msr_bitmap + 0x0800 / BYTES_PER_LONG;
    else if ( (msr >= 0xc0010000) && (msr <= 0xc0011fff) )
        msr_bit = msr_bitmap + 0x1000 / BYTES_PER_LONG;

    BUG_ON(msr_bit == NULL);

    msr &= 0x1fff;

    if ( enable )
    {
        __set_bit(msr * 2, msr_bit);
        __set_bit(msr * 2 + 1, msr_bit);
    }
    else
    {
        __clear_bit(msr * 2, msr_bit);
        __clear_bit(msr * 2 + 1, msr_bit);
    }
}

static int construct_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = arch_svm->vmcb;

    vmcb->general1_intercepts = 
        GENERAL1_INTERCEPT_INTR        | GENERAL1_INTERCEPT_NMI         |
        GENERAL1_INTERCEPT_SMI         | GENERAL1_INTERCEPT_INIT        |
        GENERAL1_INTERCEPT_CPUID       | GENERAL1_INTERCEPT_INVD        |
        GENERAL1_INTERCEPT_HLT         | GENERAL1_INTERCEPT_INVLPG      | 
        GENERAL1_INTERCEPT_INVLPGA     | GENERAL1_INTERCEPT_IOIO_PROT   |
        GENERAL1_INTERCEPT_MSR_PROT    | GENERAL1_INTERCEPT_SHUTDOWN_EVT|
        GENERAL1_INTERCEPT_TASK_SWITCH;
    vmcb->general2_intercepts = 
        GENERAL2_INTERCEPT_VMRUN       | GENERAL2_INTERCEPT_VMMCALL     |
        GENERAL2_INTERCEPT_VMLOAD      | GENERAL2_INTERCEPT_VMSAVE      |
        GENERAL2_INTERCEPT_STGI        | GENERAL2_INTERCEPT_CLGI        |
        GENERAL2_INTERCEPT_SKINIT      | GENERAL2_INTERCEPT_RDTSCP      |
        GENERAL2_INTERCEPT_WBINVD      | GENERAL2_INTERCEPT_MONITOR     |
        GENERAL2_INTERCEPT_MWAIT;

    /* Intercept all debug-register writes. */
    vmcb->dr_intercepts = ~0u;

    /* Intercept all control-register accesses except for CR2 and CR8. */
    vmcb->cr_intercepts = ~(CR_INTERCEPT_CR2_READ |
                            CR_INTERCEPT_CR2_WRITE |
                            CR_INTERCEPT_CR8_READ |
                            CR_INTERCEPT_CR8_WRITE);

    /* I/O and MSR permission bitmaps. */
    arch_svm->msrpm = alloc_xenheap_pages(get_order_from_bytes(MSRPM_SIZE), 0);
    if ( arch_svm->msrpm == NULL )
        return -ENOMEM;
    memset(arch_svm->msrpm, 0xff, MSRPM_SIZE);

    svm_disable_intercept_for_msr(v, MSR_FS_BASE);
    svm_disable_intercept_for_msr(v, MSR_GS_BASE);
    svm_disable_intercept_for_msr(v, MSR_SHADOW_GS_BASE);
    svm_disable_intercept_for_msr(v, MSR_CSTAR);
    svm_disable_intercept_for_msr(v, MSR_LSTAR);
    svm_disable_intercept_for_msr(v, MSR_STAR);
    svm_disable_intercept_for_msr(v, MSR_SYSCALL_MASK);

    vmcb->msrpm_base_pa = (u64)virt_to_maddr(arch_svm->msrpm);
    vmcb->iopm_base_pa  = (u64)virt_to_maddr(hvm_io_bitmap);

    /* Virtualise EFLAGS.IF and LAPIC TPR (CR8). */
    vmcb->vintr.fields.intr_masking = 1;
  
    /* Initialise event injection to no-op. */
    vmcb->eventinj.bytes = 0;

    /* TSC. */
    vmcb->tsc_offset = 0;
    if ( v->domain->arch.vtsc )
        vmcb->general1_intercepts |= GENERAL1_INTERCEPT_RDTSC;

    /* Guest EFER. */
    v->arch.hvm_vcpu.guest_efer = 0;
    hvm_update_guest_efer(v);

    /* Guest segment limits. */
    vmcb->cs.limit = ~0u;
    vmcb->es.limit = ~0u;
    vmcb->ss.limit = ~0u;
    vmcb->ds.limit = ~0u;
    vmcb->fs.limit = ~0u;
    vmcb->gs.limit = ~0u;

    /* Guest segment bases. */
    vmcb->cs.base = 0;
    vmcb->es.base = 0;
    vmcb->ss.base = 0;
    vmcb->ds.base = 0;
    vmcb->fs.base = 0;
    vmcb->gs.base = 0;

    /* Guest segment AR bytes. */
    vmcb->es.attr.bytes = 0xc93; /* read/write, accessed */
    vmcb->ss.attr.bytes = 0xc93;
    vmcb->ds.attr.bytes = 0xc93;
    vmcb->fs.attr.bytes = 0xc93;
    vmcb->gs.attr.bytes = 0xc93;
    vmcb->cs.attr.bytes = 0xc9b; /* exec/read, accessed */

    /* Guest IDT. */
    vmcb->idtr.base = 0;
    vmcb->idtr.limit = 0;

    /* Guest GDT. */
    vmcb->gdtr.base = 0;
    vmcb->gdtr.limit = 0;

    /* Guest LDT. */
    vmcb->ldtr.sel = 0;
    vmcb->ldtr.base = 0;
    vmcb->ldtr.limit = 0;
    vmcb->ldtr.attr.bytes = 0;

    /* Guest TSS. */
    vmcb->tr.attr.bytes = 0x08b; /* 32-bit TSS (busy) */
    vmcb->tr.base = 0;
    vmcb->tr.limit = 0xff;

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_PE | X86_CR0_ET;
    hvm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[4] = 0;
    hvm_update_guest_cr(v, 4);

    paging_update_paging_modes(v);

    vmcb->exception_intercepts =
        HVM_TRAP_MASK
        | (1U << TRAP_no_device);

    if ( paging_mode_hap(v->domain) )
    {
        vmcb->np_enable = 1; /* enable nested paging */
        vmcb->g_pat = MSR_IA32_CR_PAT_RESET; /* guest PAT */
        vmcb->h_cr3 = pagetable_get_paddr(v->domain->arch.phys_table);

        /* No point in intercepting CR3 reads/writes. */
        vmcb->cr_intercepts &= ~(CR_INTERCEPT_CR3_READ|CR_INTERCEPT_CR3_WRITE);

        /*
         * No point in intercepting INVLPG if we don't have shadow pagetables
         * that need to be fixed up.
         */
        vmcb->general1_intercepts &= ~GENERAL1_INTERCEPT_INVLPG;

        /* PAT is under complete control of SVM when using nested paging. */
        svm_disable_intercept_for_msr(v, MSR_IA32_CR_PAT);
    }
    else
    {
        vmcb->exception_intercepts |= (1U << TRAP_page_fault);
    }

    if ( cpu_has_pause_filter )
    {
        vmcb->pause_filter_count = 3000;
        vmcb->general1_intercepts |= GENERAL1_INTERCEPT_PAUSE;
    }

    return 0;
}

int svm_create_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;
    int rc;

    if ( (arch_svm->vmcb == NULL) &&
         (arch_svm->vmcb = alloc_vmcb()) == NULL )
    {
        printk("Failed to create a new VMCB\n");
        return -ENOMEM;
    }

    if ( (rc = construct_vmcb(v)) != 0 )
    {
        free_vmcb(arch_svm->vmcb);
        arch_svm->vmcb = NULL;
        return rc;
    }

    arch_svm->vmcb_pa = virt_to_maddr(arch_svm->vmcb);

    return 0;
}

void svm_destroy_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;

    if ( arch_svm->vmcb != NULL )
        free_vmcb(arch_svm->vmcb);

    if ( arch_svm->msrpm != NULL )
    {
        free_xenheap_pages(
            arch_svm->msrpm, get_order_from_bytes(MSRPM_SIZE));
        arch_svm->msrpm = NULL;
    }

    arch_svm->vmcb = NULL;
}

static void svm_dump_sel(char *name, svm_segment_register_t *s)
{
    printk("%s: sel=0x%04x, attr=0x%04x, limit=0x%08x, base=0x%016llx\n", 
           name, s->sel, s->attr.bytes, s->limit,
           (unsigned long long)s->base);
}

void svm_dump_vmcb(const char *from, struct vmcb_struct *vmcb)
{
    printk("Dumping guest's current state at %s...\n", from);
    printk("Size of VMCB = %d, address = %p\n", 
            (int) sizeof(struct vmcb_struct), vmcb);

    printk("cr_intercepts = 0x%08x dr_intercepts = 0x%08x "
           "exception_intercepts = 0x%08x\n", 
           vmcb->cr_intercepts, vmcb->dr_intercepts, 
           vmcb->exception_intercepts);
    printk("general1_intercepts = 0x%08x general2_intercepts = 0x%08x\n", 
           vmcb->general1_intercepts, vmcb->general2_intercepts);
    printk("iopm_base_pa = %016llx msrpm_base_pa = 0x%016llx tsc_offset = "
            "0x%016llx\n", 
           (unsigned long long) vmcb->iopm_base_pa,
           (unsigned long long) vmcb->msrpm_base_pa,
           (unsigned long long) vmcb->tsc_offset);
    printk("tlb_control = 0x%08x vintr = 0x%016llx interrupt_shadow = "
            "0x%016llx\n", vmcb->tlb_control,
           (unsigned long long) vmcb->vintr.bytes,
           (unsigned long long) vmcb->interrupt_shadow);
    printk("exitcode = 0x%016llx exitintinfo = 0x%016llx\n", 
           (unsigned long long) vmcb->exitcode,
           (unsigned long long) vmcb->exitintinfo.bytes);
    printk("exitinfo1 = 0x%016llx exitinfo2 = 0x%016llx \n",
           (unsigned long long) vmcb->exitinfo1,
           (unsigned long long) vmcb->exitinfo2);
    printk("np_enable = 0x%016llx guest_asid = 0x%03x\n", 
           (unsigned long long) vmcb->np_enable, vmcb->guest_asid);
    printk("cpl = %d efer = 0x%016llx star = 0x%016llx lstar = 0x%016llx\n", 
           vmcb->cpl, (unsigned long long) vmcb->efer,
           (unsigned long long) vmcb->star, (unsigned long long) vmcb->lstar);
    printk("CR0 = 0x%016llx CR2 = 0x%016llx\n",
           (unsigned long long) vmcb->cr0, (unsigned long long) vmcb->cr2);
    printk("CR3 = 0x%016llx CR4 = 0x%016llx\n", 
           (unsigned long long) vmcb->cr3, (unsigned long long) vmcb->cr4);
    printk("RSP = 0x%016llx  RIP = 0x%016llx\n", 
           (unsigned long long) vmcb->rsp, (unsigned long long) vmcb->rip);
    printk("RAX = 0x%016llx  RFLAGS=0x%016llx\n",
           (unsigned long long) vmcb->rax, (unsigned long long) vmcb->rflags);
    printk("DR6 = 0x%016llx, DR7 = 0x%016llx\n", 
           (unsigned long long) vmcb->dr6, (unsigned long long) vmcb->dr7);
    printk("CSTAR = 0x%016llx SFMask = 0x%016llx\n",
           (unsigned long long) vmcb->cstar, 
           (unsigned long long) vmcb->sfmask);
    printk("KernGSBase = 0x%016llx PAT = 0x%016llx \n", 
           (unsigned long long) vmcb->kerngsbase,
           (unsigned long long) vmcb->g_pat);
    printk("H_CR3 = 0x%016llx\n", (unsigned long long)vmcb->h_cr3);

    /* print out all the selectors */
    svm_dump_sel("CS", &vmcb->cs);
    svm_dump_sel("DS", &vmcb->ds);
    svm_dump_sel("SS", &vmcb->ss);
    svm_dump_sel("ES", &vmcb->es);
    svm_dump_sel("FS", &vmcb->fs);
    svm_dump_sel("GS", &vmcb->gs);
    svm_dump_sel("GDTR", &vmcb->gdtr);
    svm_dump_sel("LDTR", &vmcb->ldtr);
    svm_dump_sel("IDTR", &vmcb->idtr);
    svm_dump_sel("TR", &vmcb->tr);
}

static void vmcb_dump(unsigned char ch)
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
            printk("\tVCPU %d\n", v->vcpu_id);
            svm_dump_vmcb("key_handler", v->arch.hvm_svm.vmcb);
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    printk("**************************************\n");
}

static struct keyhandler vmcb_dump_keyhandler = {
    .diagnostic = 1,
    .u.fn = vmcb_dump,
    .desc = "dump AMD-V VMCBs"
};

void setup_vmcb_dump(void)
{
    register_keyhandler('v', &vmcb_dump_keyhandler);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
