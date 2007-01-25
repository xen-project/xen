/*
 * vmcb.c: VMCB management
 * Copyright (c) 2005, AMD Corporation.
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
#include <xen/shadow.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/intr.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/domain_page.h>
#include <xen/keyhandler.h>

extern int svm_dbg_on;

#define GUEST_SEGMENT_LIMIT 0xffffffff

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

    memset(vmcb, 0, PAGE_SIZE);
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
        printk(XENLOG_WARNING "Warning: failed to allocate vmcb.\n");
        return NULL;
    }

    memset(hsa, 0, PAGE_SIZE);
    return hsa;
}

void free_host_save_area(struct host_save_area *hsa)
{
    free_xenheap_page(hsa);
}

static int construct_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = arch_svm->vmcb;
    svm_segment_attributes_t attrib;

    /* Always flush the TLB on VMRUN. All guests share a single ASID (1). */
    vmcb->tlb_control = 1;
    vmcb->guest_asid  = 1;

    /* SVM intercepts. */
    vmcb->general1_intercepts = 
        GENERAL1_INTERCEPT_INTR         | GENERAL1_INTERCEPT_NMI         |
        GENERAL1_INTERCEPT_SMI          | GENERAL1_INTERCEPT_INIT        |
        GENERAL1_INTERCEPT_CPUID        | GENERAL1_INTERCEPT_INVD        |
        GENERAL1_INTERCEPT_HLT          | GENERAL1_INTERCEPT_INVLPG      | 
        GENERAL1_INTERCEPT_INVLPGA      | GENERAL1_INTERCEPT_IOIO_PROT   |
        GENERAL1_INTERCEPT_MSR_PROT     | GENERAL1_INTERCEPT_SHUTDOWN_EVT;
    vmcb->general2_intercepts = 
        GENERAL2_INTERCEPT_VMRUN  | GENERAL2_INTERCEPT_VMMCALL | 
        GENERAL2_INTERCEPT_VMLOAD | GENERAL2_INTERCEPT_VMSAVE  |
        GENERAL2_INTERCEPT_STGI   | GENERAL2_INTERCEPT_CLGI    |
        GENERAL2_INTERCEPT_SKINIT | GENERAL2_INTERCEPT_RDTSCP;

    /* Intercept all debug-register writes. */
    vmcb->dr_intercepts = DR_INTERCEPT_ALL_WRITES;

    /* Intercept all control-register accesses, except to CR2. */
    vmcb->cr_intercepts = ~(CR_INTERCEPT_CR2_READ | CR_INTERCEPT_CR2_WRITE);

    /* I/O and MSR permission bitmaps. */
    arch_svm->msrpm = alloc_xenheap_pages(get_order_from_bytes(MSRPM_SIZE));
    if ( arch_svm->msrpm == NULL )
        return -ENOMEM;
    memset(arch_svm->msrpm, 0xff, MSRPM_SIZE);
    vmcb->msrpm_base_pa = (u64)virt_to_maddr(arch_svm->msrpm);
    vmcb->iopm_base_pa  = (u64)virt_to_maddr(hvm_io_bitmap);

    /* Virtualise EFLAGS.IF and LAPIC TPR (CR8). */
    vmcb->vintr.fields.intr_masking = 1;
  
    /* Initialise event injection to no-op. */
    vmcb->eventinj.bytes = 0;

    /* TSC. */
    vmcb->tsc_offset = 0;
    
    /* Guest EFER: *must* contain SVME or VMRUN will fail. */
    vmcb->efer = EFER_SVME;

    /* Guest segment limits. */
    vmcb->cs.limit = GUEST_SEGMENT_LIMIT;
    vmcb->es.limit = GUEST_SEGMENT_LIMIT;
    vmcb->ss.limit = GUEST_SEGMENT_LIMIT;
    vmcb->ds.limit = GUEST_SEGMENT_LIMIT;
    vmcb->fs.limit = GUEST_SEGMENT_LIMIT;
    vmcb->gs.limit = GUEST_SEGMENT_LIMIT;

    /* Guest segment bases. */
    vmcb->cs.base = 0;
    vmcb->es.base = 0;
    vmcb->ss.base = 0;
    vmcb->ds.base = 0;
    vmcb->fs.base = 0;
    vmcb->gs.base = 0;

    /* Guest segment AR bytes. */
    attrib.bytes = 0;
    attrib.fields.type = 0x3; /* type = 3 */
    attrib.fields.s = 1;      /* code or data, i.e. not system */
    attrib.fields.dpl = 0;    /* DPL = 0 */
    attrib.fields.p = 1;      /* segment present */
    attrib.fields.db = 1;     /* 32-bit */
    attrib.fields.g = 1;      /* 4K pages in limit */
    vmcb->es.attr = attrib;
    vmcb->ss.attr = attrib;
    vmcb->ds.attr = attrib;
    vmcb->fs.attr = attrib;
    vmcb->gs.attr = attrib;
    attrib.fields.type = 0xb; /* type=0xb -> executable/readable, accessed */
    vmcb->cs.attr = attrib;

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
    attrib.fields.type = 0xb; /* 32-bit TSS (busy) */
    vmcb->tr.attr = attrib;
    vmcb->tr.base = 0;
    vmcb->tr.limit = 0xff;

    /* Guest CR0. */
    vmcb->cr0 = read_cr0();
    arch_svm->cpu_shadow_cr0 = vmcb->cr0 & ~(X86_CR0_PG | X86_CR0_TS);
    vmcb->cr0 |= X86_CR0_WP;

    /* Guest CR4. */
    arch_svm->cpu_shadow_cr4 =
        read_cr4() & ~(X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE);
    vmcb->cr4 = arch_svm->cpu_shadow_cr4 | SVM_CR4_HOST_MASK;

    shadow_update_paging_modes(v);
    vmcb->cr3 = v->arch.hvm_vcpu.hw_cr3; 

    arch_svm->vmcb->exception_intercepts = MONITOR_DEFAULT_EXCEPTION_BITMAP;

    return 0;
}

int svm_create_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;
    int rc;

    if ( (arch_svm->vmcb = alloc_vmcb()) == NULL )
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

void svm_do_launch(struct vcpu *v)
{
    hvm_stts(v);

    /* current core is the one we intend to perform the VMRUN on */
    v->arch.hvm_svm.launch_core = smp_processor_id();

    v->arch.schedule_tail = arch_svm_do_resume;
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

    printk("**************************************\n");
}

void setup_vmcb_dump(void)
{
    register_keyhandler('v', vmcb_dump, "dump AMD-V VMCBs");
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
