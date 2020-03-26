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

#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <asm/hvm/svm/svmdebug.h>

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
    printk("np_enable = %#"PRIx64" guest_asid = %#x\n",
           vmcb_get_np_enable(vmcb), vmcb_get_guest_asid(vmcb));
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
    printk("H_CR3 = 0x%016"PRIx64" CleanBits = %#x\n",
           vmcb_get_h_cr3(vmcb), vmcb->cleanbits.bytes);

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

bool svm_vmcb_isvalid(const char *from, const struct vmcb_struct *vmcb,
                      const struct vcpu *v, bool verbose)
{
    bool ret = false; /* ok */
    unsigned long cr0 = vmcb_get_cr0(vmcb);
    unsigned long cr3 = vmcb_get_cr3(vmcb);
    unsigned long cr4 = vmcb_get_cr4(vmcb);
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

    if ( cr4 & ~hvm_cr4_guest_valid_bits(v->domain, false) )
        PRINTF("CR4: invalid bits are set (%#"PRIx64", valid: %#"PRIx64")\n",
               cr4, hvm_cr4_guest_valid_bits(v->domain, false));

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
