/*
 * vmx_platform.h: VMX platform support
 * Copyright (c) 2004, Intel Corporation.
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

#ifndef __ASM_X86_VMX_PLATFORM_H__
#define __ASM_X86_VMX_PLATFORM_H__

#include <public/xen.h>
#include <asm/e820.h>
#include <asm/vmx_vpit.h>
#include <asm/vmx_intercept.h>
#include <asm/vmx_vioapic.h>
#include <asm/vmx_vpic.h>

#define MAX_OPERAND_NUM 2

#define mk_operand(size_reg, index, seg, flag) \
    (((size_reg) << 24) | ((index) << 16) | ((seg) << 8) | (flag))

#define operand_size(operand)   \
    ((operand >> 24) & 0xFF)

#define operand_index(operand)  \
    ((operand >> 16) & 0xFF)

/* for instruction.operand[].size */
#define BYTE    1
#define WORD    2
#define LONG    4
#define QUAD    8
#define BYTE_64 16

/* for instruction.operand[].flag */
#define REGISTER    0x1
#define MEMORY      0x2
#define IMMEDIATE   0x4

/* for instruction.flags */
#define REPZ    0x1
#define REPNZ   0x2
#define OVERLAP 0x4

#define INSTR_PIO   1
#define INSTR_OR    2
#define INSTR_AND   3
#define INSTR_XOR   4
#define INSTR_CMP   5
#define INSTR_MOV   6
#define INSTR_MOVS  7
#define INSTR_MOVZX 8
#define INSTR_MOVSX 9
#define INSTR_STOS  10
#define INSTR_TEST  11
#define INSTR_BT    12

struct instruction {
    __s8    instr; /* instruction type */
    __s16   op_size;    /* the operand's bit size, e.g. 16-bit or 32-bit */
    __u64   immediate;
    __u16   seg_sel;    /* segmentation selector */
    __u32   operand[MAX_OPERAND_NUM];   /* order is AT&T assembly */
    __u32   flags;
};

#define MAX_INST_LEN      32

struct vmx_platform {
    unsigned long          shared_page_va;
    unsigned int           nr_vcpus;
    unsigned int           apic_enabled;

    struct vmx_virpit      vmx_pit;
    struct vmx_io_handler  vmx_io_handler;
    struct vmx_virpic      vmx_pic;
    struct vmx_vioapic     vmx_vioapic;
    unsigned char          round_info[256];
    spinlock_t             round_robin_lock;
    int                    interrupt_request;
};

extern void handle_mmio(unsigned long, unsigned long);
extern void vmx_wait_io(void);
extern void vmx_io_assist(struct vcpu *v);

// XXX - think about this -- maybe use bit 30 of the mfn to signify an MMIO frame.
#define mmio_space(gpa) (!VALID_MFN(get_mfn_from_pfn((gpa) >> PAGE_SHIFT)))

#endif
