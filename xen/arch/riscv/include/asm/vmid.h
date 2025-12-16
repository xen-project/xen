/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM_RISCV_VMID_H
#define ASM_RISCV_VMID_H

struct vcpu;
struct vcpu_vmid;

void vmid_init(void);
bool vmid_handle_vmenter(struct vcpu_vmid *vmid);
void vmid_flush_vcpu(struct vcpu *v);
void vmid_flush_hart(void);

#endif /* ASM_RISCV_VMID_H */
