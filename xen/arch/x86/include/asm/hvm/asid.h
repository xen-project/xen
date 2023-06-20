/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.h: ASID management
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2009, Citrix Systems, Inc.
 */

#ifndef __ASM_X86_HVM_ASID_H__
#define __ASM_X86_HVM_ASID_H__


struct vcpu;
struct hvm_vcpu_asid;

/* Initialise ASID management for the current physical CPU. */
void hvm_asid_init(int nasids);

/* Invalidate a particular ASID allocation: forces re-allocation. */
void hvm_asid_flush_vcpu_asid(struct hvm_vcpu_asid *asid);

/* Invalidate all ASID allocations for specified VCPU: forces re-allocation. */
void hvm_asid_flush_vcpu(struct vcpu *v);

/* Flush all ASIDs on this processor core. */
void hvm_asid_flush_core(void);

/* Called before entry to guest context. Checks ASID allocation, returns a
 * boolean indicating whether all ASIDs must be flushed. */
bool hvm_asid_handle_vmenter(struct hvm_vcpu_asid *asid);

#endif /* __ASM_X86_HVM_ASID_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
