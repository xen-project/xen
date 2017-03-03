/*
 * asid.h: handling ASIDs in SVM.
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_X86_HVM_SVM_ASID_H__
#define __ASM_X86_HVM_SVM_ASID_H__

#include <xen/types.h>
#include <asm/hvm/asid.h>
#include <asm/processor.h>

void svm_asid_init(const struct cpuinfo_x86 *c);

static inline void svm_asid_g_invlpg(struct vcpu *v, unsigned long g_vaddr)
{
#if 0
    /* Optimization? */
    svm_invlpga(g_vaddr, v->arch.hvm_svm.vmcb->guest_asid);
#endif

    /* Safe fallback. Take a new ASID. */
    hvm_asid_flush_vcpu(v);
}

#endif /* __ASM_X86_HVM_SVM_ASID_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
