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
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/svm/vmcb.h>

#define HVM_VCPU_INIT_SIPI_SIPI_STATE_NORM          0
#define HVM_VCPU_INIT_SIPI_SIPI_STATE_WAIT_SIPI     1

struct hvm_vcpu {
    unsigned long       hw_cr3;     /* value we give to HW to use */
    unsigned long       ioflags;
    struct hvm_io_op    io_op;
    struct vlapic       vlapic;
    s64                 cache_tsc_offset;
    u64                 guest_time;
    struct list_head    tm_list;

    /* For AP startup */
    unsigned long       init_sipi_sipi_state;

    int                 xen_port;

    /* Flags */
    int                 flag_dr_dirty;

    union {
        struct arch_vmx_struct vmx;
        struct arch_svm_struct svm;
    } u;
};

#define ARCH_HVM_IO_WAIT         1   /* Waiting for I/O completion */

#define HVM_CONTEXT_STACK_BYTES  (offsetof(struct cpu_user_regs, error_code))

#endif /* __ASM_X86_HVM_VCPU_H__ */

