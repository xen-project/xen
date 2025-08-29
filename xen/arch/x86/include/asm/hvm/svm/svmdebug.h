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

#endif /* __ASM_X86_HVM_SVM_SVMDEBUG_H__ */
