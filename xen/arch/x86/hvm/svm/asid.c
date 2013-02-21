/*
 * asid.c: handling ASIDs in SVM.
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/perfc.h>
#include <asm/hvm/svm/asid.h>
#include <asm/amd.h>
#include <asm/hvm/nestedhvm.h>

void svm_asid_init(struct cpuinfo_x86 *c)
{
    int nasids = 0;

    /* Check for erratum #170, and leave ASIDs disabled if it's present. */
    if ( !cpu_has_amd_erratum(c, AMD_ERRATUM_170) )
        nasids = cpuid_ebx(0x8000000A);

    hvm_asid_init(nasids);
}

/*
 * Called directly before VMRUN.  Checks if the VCPU needs a new ASID,
 * assigns it, and if required, issues required TLB flushes.
 */
void svm_asid_handle_vmrun(void)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm_svm.vmcb;
    struct hvm_vcpu_asid *p_asid =
        nestedhvm_vcpu_in_guestmode(curr)
        ? &vcpu_nestedhvm(curr).nv_n2asid : &curr->arch.hvm_vcpu.n1asid;
    bool_t need_flush = hvm_asid_handle_vmenter(p_asid);

    /* ASID 0 indicates that ASIDs are disabled. */
    if ( p_asid->asid == 0 )
    {
        vmcb_set_guest_asid(vmcb, 1);
        vmcb->tlb_control = 1;
        return;
    }

    if (vmcb_get_guest_asid(vmcb) != p_asid->asid)
        vmcb_set_guest_asid(vmcb, p_asid->asid);
    vmcb->tlb_control = need_flush;
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
