/*
 * svmdebug.c: debug functions
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
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
 *
 */

#include <asm/processor.h>
#include <asm/msr-index.h>
#include <asm/hvm/svm/svmdebug.h>

static void svm_dump_sel(const char *name, svm_segment_register_t *s)
{
    printk("%s: sel=0x%04x, attr=0x%04x, limit=0x%08x, base=0x%016llx\n", 
           name, s->sel, s->attr.bytes, s->limit,
           (unsigned long long)s->base);
}

/* This function can directly access fields which are covered by clean bits. */
void svm_vmcb_dump(const char *from, struct vmcb_struct *vmcb)
{
    printk("Dumping guest's current state at %s...\n", from);
    printk("Size of VMCB = %d, paddr = %#lx, vaddr = %p\n",
           (int) sizeof(struct vmcb_struct), virt_to_maddr(vmcb), vmcb);

    printk("cr_intercepts = %#x dr_intercepts = %#x "
           "exception_intercepts = %#x\n",
           vmcb->_cr_intercepts, vmcb->_dr_intercepts, 
           vmcb->_exception_intercepts);
    printk("general1_intercepts = %#x general2_intercepts = %#x\n",
           vmcb->_general1_intercepts, vmcb->_general2_intercepts);
    printk("iopm_base_pa = %#Lx msrpm_base_pa = %#Lx tsc_offset = %#Lx\n",
           (unsigned long long)vmcb->_iopm_base_pa,
           (unsigned long long)vmcb->_msrpm_base_pa,
           (unsigned long long)vmcb->_tsc_offset);
    printk("tlb_control = %#x vintr = %#Lx interrupt_shadow = %#Lx\n",
           vmcb->tlb_control,
           (unsigned long long)vmcb->_vintr.bytes,
           (unsigned long long)vmcb->interrupt_shadow);
    printk("eventinj %016"PRIx64", valid? %d, ec? %d, type %u, vector %#x\n",
           vmcb->eventinj.bytes, vmcb->eventinj.fields.v,
           vmcb->eventinj.fields.ev, vmcb->eventinj.fields.type,
           vmcb->eventinj.fields.vector);
    printk("exitcode = %#Lx exitintinfo = %#Lx\n",
           (unsigned long long)vmcb->exitcode,
           (unsigned long long)vmcb->exitintinfo.bytes);
    printk("exitinfo1 = %#Lx exitinfo2 = %#Lx \n",
           (unsigned long long)vmcb->exitinfo1,
           (unsigned long long)vmcb->exitinfo2);
    printk("np_enable = %Lx guest_asid = %#x\n",
           (unsigned long long)vmcb->_np_enable, vmcb->_guest_asid);
    printk("cpl = %d efer = %#Lx star = %#Lx lstar = %#Lx\n",
           vmcb->_cpl, (unsigned long long)vmcb->_efer,
           (unsigned long long)vmcb->star, (unsigned long long)vmcb->lstar);
    printk("CR0 = 0x%016llx CR2 = 0x%016llx\n",
           (unsigned long long)vmcb->_cr0, (unsigned long long)vmcb->_cr2);
    printk("CR3 = 0x%016llx CR4 = 0x%016llx\n", 
           (unsigned long long)vmcb->_cr3, (unsigned long long)vmcb->_cr4);
    printk("RSP = 0x%016llx  RIP = 0x%016llx\n", 
           (unsigned long long)vmcb->rsp, (unsigned long long)vmcb->rip);
    printk("RAX = 0x%016llx  RFLAGS=0x%016llx\n",
           (unsigned long long)vmcb->rax, (unsigned long long)vmcb->rflags);
    printk("DR6 = 0x%016llx, DR7 = 0x%016llx\n", 
           (unsigned long long)vmcb->_dr6, (unsigned long long)vmcb->_dr7);
    printk("CSTAR = 0x%016llx SFMask = 0x%016llx\n",
           (unsigned long long)vmcb->cstar, 
           (unsigned long long)vmcb->sfmask);
    printk("KernGSBase = 0x%016llx PAT = 0x%016llx \n", 
           (unsigned long long)vmcb->kerngsbase,
           (unsigned long long)vmcb->_g_pat);
    printk("H_CR3 = 0x%016llx CleanBits = %#x\n",
           (unsigned long long)vmcb->_h_cr3, vmcb->cleanbits.bytes);

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

bool_t
svm_vmcb_isvalid(const char *from, struct vmcb_struct *vmcb,
                 bool_t verbose)
{
    bool_t ret = 0; /* ok */

#define PRINTF(...) \
    if (verbose) { ret = 1; printk("%s: ", from); printk(__VA_ARGS__); \
    } else return 1;

    if ((vmcb->_efer & EFER_SVME) == 0) {
        PRINTF("EFER: SVME bit not set (%#"PRIx64")\n", vmcb->_efer);
    }

    if ((vmcb->_cr0 & X86_CR0_CD) == 0 && (vmcb->_cr0 & X86_CR0_NW) != 0) {
        PRINTF("CR0: CD bit is zero and NW bit set (%#"PRIx64")\n",
                vmcb->_cr0);
    }

    if ((vmcb->_cr0 >> 32U) != 0) {
        PRINTF("CR0: bits [63:32] are not zero (%#"PRIx64")\n",
                vmcb->_cr0);
    }

    if ((vmcb->_cr3 & 0x7) != 0) {
        PRINTF("CR3: MBZ bits are set (%#"PRIx64")\n", vmcb->_cr3);
    }
    if ((vmcb->_efer & EFER_LMA) && (vmcb->_cr3 & 0xfe) != 0) {
        PRINTF("CR3: MBZ bits are set (%#"PRIx64")\n", vmcb->_cr3);
    }

    if ((vmcb->_cr4 >> 19U) != 0) {
        PRINTF("CR4: bits [63:19] are not zero (%#"PRIx64")\n",
                vmcb->_cr4);
    }

    if (((vmcb->_cr4 >> 11U) & 0x7fU) != 0) {
        PRINTF("CR4: bits [17:11] are not zero (%#"PRIx64")\n",
                vmcb->_cr4);
    }

    if ((vmcb->_dr6 >> 32U) != 0) {
        PRINTF("DR6: bits [63:32] are not zero (%#"PRIx64")\n",
                vmcb->_dr6);
    }

    if ((vmcb->_dr7 >> 32U) != 0) {
        PRINTF("DR7: bits [63:32] are not zero (%#"PRIx64")\n",
                vmcb->_dr7);
    }

    if ((vmcb->_efer >> 15U) != 0) {
        PRINTF("EFER: bits [63:15] are not zero (%#"PRIx64")\n",
                vmcb->_efer);
    }

    if ((vmcb->_efer & EFER_LME) != 0 && ((vmcb->_cr0 & X86_CR0_PG) != 0)) {
        if ((vmcb->_cr4 & X86_CR4_PAE) == 0) {
            PRINTF("EFER_LME and CR0.PG are both set and CR4.PAE is zero.\n");
        }
        if ((vmcb->_cr0 & X86_CR0_PE) == 0) {
            PRINTF("EFER_LME and CR0.PG are both set and CR0.PE is zero.\n");
        }
    }

    if ((vmcb->_efer & EFER_LME) != 0
        && (vmcb->_cr0 & X86_CR0_PG) != 0
        && (vmcb->_cr4 & X86_CR4_PAE) != 0
        && (vmcb->cs.attr.fields.l != 0)
        && (vmcb->cs.attr.fields.db != 0))
    {
        PRINTF("EFER_LME, CR0.PG, CR4.PAE, CS.L and CS.D are all non-zero.\n");
    }

    if ((vmcb->_general2_intercepts & GENERAL2_INTERCEPT_VMRUN) == 0) {
        PRINTF("GENERAL2_INTERCEPT: VMRUN intercept bit is clear (%#"PRIx32")\n",
            vmcb->_general2_intercepts);
    }

    if (vmcb->eventinj.fields.resvd1 != 0) {
        PRINTF("eventinj: MBZ bits are set (%#"PRIx64")\n",
                vmcb->eventinj.bytes);
    }

    if (vmcb->_np_enable && vmcb->_h_cr3 == 0) {
        PRINTF("nested paging enabled but host cr3 is 0\n");
    }

#undef PRINTF
    return ret;
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
