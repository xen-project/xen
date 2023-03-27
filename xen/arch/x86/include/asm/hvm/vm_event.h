/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/asm-x86/hvm/vm_event.h
 *
 * Hardware virtual machine vm_event abstractions.
 */

#ifndef __ASM_X86_HVM_VM_EVENT_H__
#define __ASM_X86_HVM_VM_EVENT_H__

void hvm_vm_event_do_resume(struct vcpu *v);

#endif /* __ASM_X86_HVM_VM_EVENT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
