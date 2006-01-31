/*
 * vcpu.h: HVM per vcpu definitions
 *
 * Copyright (c) 2005, International Business Machines Corporation.
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

#ifndef __ASM_X86_HVM_VCPU_H__
#define __ASM_X86_HVM_VCPU_H__

#include <asm/hvm/io.h>
#include <asm/hvm/vlapic.h>

#ifdef CONFIG_VMX
#include <asm/hvm/vmx/vmcs.h>
#endif
#ifdef CONFIG_SVM
#include <asm/hvm/svm/vmcb.h>
#endif

struct hvm_vcpu {
    unsigned long       ioflags;
    struct mmio_op      mmio_op;
    struct vlapic       *vlapic;

    union {
#ifdef CONFIG_VMX
        struct arch_vmx_struct vmx;
#endif
#ifdef CONFIG_SVM
        struct arch_svm_struct svm;
#endif
    } u;
};

#define ARCH_HVM_IO_WAIT   1       /* Waiting for I/O completion */

#endif /* __ASM_X86_HVM_VCPU_H__ */

