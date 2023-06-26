/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * svmdebug.h: SVM related debug defintions
 * Copyright (c) 2011, AMD Corporation.
 *
 */

#ifndef __ASM_X86_HVM_SVM_SVMDEBUG_H__
#define __ASM_X86_HVM_SVM_SVMDEBUG_H__

#include <xen/types.h>
#include <asm/hvm/svm/vmcb.h>

void svm_sync_vmcb(struct vcpu *v, enum vmcb_sync_state new_state);
void svm_vmcb_dump(const char *from, const struct vmcb_struct *vmcb);
bool svm_vmcb_isvalid(const char *from, const struct vmcb_struct *vmcb,
                      const struct vcpu *v, bool verbose);

#endif /* __ASM_X86_HVM_SVM_SVMDEBUG_H__ */
