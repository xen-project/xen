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

#include <asm/e820.h>       /* from Linux */

#define MAX_OPERAND_NUM 3
#define I_NAME_LEN  16

#define mk_operand(size, index, seg, flag) \
    (((size) << 24) | ((index) << 16) | ((seg) << 8) | (flag))

#define operand_size(operand)   \
      ((operand >> 24) & 0xFF)

#define operand_index(operand)  \
      ((operand >> 16) & 0xFF)
      //For instruction.operand[].size
#define BYTE    1
#define WORD    2
#define LONG    4
#define QUAD    8

      //For instruction.operand[].flag
#define REGISTER    0x1
#define MEMORY      0x2
#define IMMEDIATE   0x4
#define WZEROEXTEND 0x8

      //For instruction.flags
#define REPZ    0x1
#define REPNZ   0x2

struct instruction {
    __s8    i_name[I_NAME_LEN];  //Instruction's name
    __s16   op_size;    //The operand's bit size, e.g. 16-bit or 32-bit.

    __u64   offset;     //The effective address
          //offset = Base + (Index * Scale) + Displacement

    __u64   immediate;

    __u16   seg_sel;    //Segmentation selector

    __u32   operand[MAX_OPERAND_NUM];   //The order of operand is from AT&T Assembly
    __s16   op_num; //The operand numbers

    __u32   flags; //
};

#define VGA_SPACE_START   0xA0000
#define VGA_SPACE_END     0xC0000
#define MAX_INST_LEN      32

struct mi_per_cpu_info
{
    unsigned long          mmio_target;
    struct xen_regs        *inst_decoder_regs;
};

struct virutal_platform_def {
    unsigned long          *real_mode_data; /* E820, etc. */
    unsigned long          shared_page_va;
    struct mi_per_cpu_info mpci;            /* MMIO */
};

extern void handle_mmio(unsigned long, unsigned long, unsigned long);
extern int vmx_setup_platform(struct exec_domain *, execution_context_t *);

static inline int mmio_space(unsigned long gpa)
{
    if (gpa >= VGA_SPACE_START && gpa < VGA_SPACE_END) {
        return 1;
    }
    return 0;
}

#endif
