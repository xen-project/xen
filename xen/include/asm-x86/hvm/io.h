/*
 * io.h: HVM IO support
 *
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
 */

#ifndef __ASM_X86_HVM_IO_H__
#define __ASM_X86_HVM_IO_H__

#include <asm/hvm/vpic.h>
#include <asm/hvm/vioapic.h>
#include <public/hvm/ioreq.h>
#include <public/event_channel.h>

#define operand_size(operand)   \
    ((operand >> 24) & 0xFF)

#define operand_index(operand)  \
    ((operand >> 16) & 0xFF)

/* for instruction.operand[].size */
#define BYTE       1
#define WORD       2
#define LONG       4
#define QUAD       8
#define BYTE_64    16

/* for instruction.operand[].flag */
#define REGISTER   0x1
#define MEMORY     0x2
#define IMMEDIATE  0x4

/* for instruction.flags */
#define REPZ       0x1
#define REPNZ      0x2
#define OVERLAP    0x4

/* instruction type */
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
#define INSTR_LODS  11
#define INSTR_TEST  12
#define INSTR_BT    13
#define INSTR_XCHG  14
#define INSTR_SUB   15
#define INSTR_ADD   16
#define INSTR_PUSH  17

#define MAX_INST_LEN      15 /* Maximum instruction length = 15 bytes */

struct hvm_io_op {
    unsigned int            instr;      /* instruction */
    unsigned int            flags;
    unsigned long           addr;       /* virt addr for overlap PIO/MMIO */
    struct {
        unsigned int        operand[2]; /* operands */
        unsigned long       immediate;  /* immediate portion */
    };
    struct cpu_user_regs    io_context; /* current context */
};

#define MAX_IO_HANDLER              9

#define HVM_PORTIO                  0
#define HVM_MMIO                    1

typedef int (*intercept_action_t)(ioreq_t *);
typedef unsigned long (*hvm_mmio_read_t)(struct vcpu *v,
                                         unsigned long addr,
                                         unsigned long length);

typedef void (*hvm_mmio_write_t)(struct vcpu *v,
                               unsigned long addr,
                               unsigned long length,
                               unsigned long val);

typedef int (*hvm_mmio_check_t)(struct vcpu *v, unsigned long addr);

struct io_handler {
    int                 type;
    unsigned long       addr;
    unsigned long       size;
    intercept_action_t  action;
};

struct hvm_io_handler {
    int     num_slot;
    struct  io_handler hdl_list[MAX_IO_HANDLER];
};

struct hvm_mmio_handler {
    hvm_mmio_check_t check_handler;
    hvm_mmio_read_t read_handler;
    hvm_mmio_write_t write_handler;
};

/* global io interception point in HV */
extern int hvm_io_intercept(ioreq_t *p, int type);
extern int register_io_handler(
    struct domain *d, unsigned long addr, unsigned long size,
    intercept_action_t action, int type);

static inline int hvm_portio_intercept(ioreq_t *p)
{
    return hvm_io_intercept(p, HVM_PORTIO);
}

extern int hvm_mmio_intercept(ioreq_t *p);
extern int hvm_buffered_io_send(ioreq_t *p);
extern int hvm_buffered_io_intercept(ioreq_t *p);

static inline int register_portio_handler(
    struct domain *d, unsigned long addr,
    unsigned long size, intercept_action_t action)
{
    return register_io_handler(d, addr, size, action, HVM_PORTIO);
}

#if defined(__i386__) || defined(__x86_64__)
static inline int irq_masked(unsigned long eflags)
{
    return ((eflags & X86_EFLAGS_IF) == 0);
}
#endif

extern void send_pio_req(unsigned long port, unsigned long count, int size,
                         paddr_t value, int dir, int df, int value_is_ptr);
void send_timeoffset_req(unsigned long timeoff);
extern void handle_mmio(unsigned long gpa);
extern void hvm_interrupt_post(struct vcpu *v, int vector, int type);
extern void hvm_io_assist(void);

#endif /* __ASM_X86_HVM_IO_H__ */

