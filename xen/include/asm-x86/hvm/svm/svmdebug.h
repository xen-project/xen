/*
 * svmdebug.h: SVM related debug defintions
 * Copyright (c) 2011, AMD Corporation.
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

#ifndef __ASM_X86_HVM_SVM_SVMDEBUG_H__
#define __ASM_X86_HVM_SVM_SVMDEBUG_H__

#include <asm/types.h>
#include <asm/hvm/svm/vmcb.h>

void svm_vmcb_dump(const char *from, const struct vmcb_struct *vmcb);
bool svm_vmcb_isvalid(const char *from, const struct vmcb_struct *vmcb,
                      const struct vcpu *v, bool verbose);

#endif /* __ASM_X86_HVM_SVM_SVMDEBUG_H__ */
