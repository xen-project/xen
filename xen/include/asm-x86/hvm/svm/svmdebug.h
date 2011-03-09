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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#ifndef __ASM_X86_HVM_SVM_SVMDEBUG_H__
#define __ASM_X86_HVM_SVM_SVMDEBUG_H__

#include <asm/types.h>
#include <asm/hvm/svm/vmcb.h>

void svm_vmcb_dump(const char *from, struct vmcb_struct *vmcb);
bool_t svm_vmcb_isvalid(const char *from, struct vmcb_struct *vmcb,
                        bool_t verbose);

#endif /* __ASM_X86_HVM_SVM_SVMDEBUG_H__ */
