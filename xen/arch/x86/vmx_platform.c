/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_platform.c: handling x86 platform related MMIO instructions
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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/shadow.h>
#include <asm/domain_page.h>
#include <asm/page.h> 
#include <xen/event.h> 
#include <xen/trace.h>
#include <asm/vmx.h>
#include <asm/vmx_platform.h>
#include <public/io/ioreq.h>

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>

#ifdef CONFIG_VMX

#define DECODE_success  1
#define DECODE_failure  0

#if defined (__x86_64__)
static void store_xen_regs(struct xen_regs *regs)
{

}

static long get_reg_value(int size, int index, int seg, struct xen_regs *regs) 
{
    return 0;
}
#elif defined (__i386__)
static void store_xen_regs(struct xen_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_ESP, &regs->esp);
    __vmread(GUEST_EFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_EIP, &regs->eip);
}

static long get_reg_value(int size, int index, int seg, struct xen_regs *regs)
{                    
    /*               
     * Reference the db_reg[] table
     */              
    switch (size) {  
    case BYTE: 
        switch (index) { 
        case 0: //%al
            return (char)(regs->eax & 0xFF);
        case 1: //%cl  
            return (char)(regs->ecx & 0xFF);
        case 2: //%dl
            return (char)(regs->edx & 0xFF); 
        case 3: //%bl
            return (char)(regs->ebx & 0xFF);
        case 4: //%ah
            return (char)((regs->eax & 0xFF00) >> 8);
        case 5: //%ch 
            return (char)((regs->ecx & 0xFF00) >> 8);
        case 6: //%dh
            return (char)((regs->edx & 0xFF00) >> 8);
        case 7: //%bh
            return (char)((regs->ebx & 0xFF00) >> 8);
        default:
            printk("(get_reg_value)size case 0 error\n"); 
            return -1; 
        }
    case WORD:
        switch (index) {
        case 0: //%ax
            return (short)(regs->eax & 0xFFFF);
        case 1: //%cx
            return (short)(regs->ecx & 0xFFFF);
        case 2: //%dx
            return (short)(regs->edx & 0xFFFF);
        case 3: //%bx
            return (short)(regs->ebx & 0xFFFF);
        case 4: //%sp
            return (short)(regs->esp & 0xFFFF);
            break;
        case 5: //%bp
            return (short)(regs->ebp & 0xFFFF);
        case 6: //%si
            return (short)(regs->esi & 0xFFFF);
        case 7: //%di
            return (short)(regs->edi & 0xFFFF);
        default:
            printk("(get_reg_value)size case 1 error\n");
            return -1;
        }
    case LONG:
        switch (index) {
        case 0: //%eax
            return regs->eax;
        case 1: //%ecx
            return regs->ecx;
        case 2: //%edx
            return regs->edx;

        case 3: //%ebx
            return regs->ebx;
        case 4: //%esp
            return regs->esp;
        case 5: //%ebp
            return regs->ebp;
        case 6: //%esi
            return regs->esi;
        case 7: //%edi
            return regs->edi;
        default:
            printk("(get_reg_value)size case 2 error\n");
            return -1;
        }
    default:
        printk("(get_reg_value)size case error\n");
        return -1;
    }
}
#endif

static inline unsigned char *check_prefix(unsigned char *inst, struct instruction *thread_inst)
{
    while (1) {
        switch (*inst) {
            case 0xf3: //REPZ
            case 0xf2: //REPNZ
            case 0xf0: //LOCK
            case 0x2e: //CS
            case 0x36: //SS
            case 0x3e: //DS
            case 0x26: //ES
            case 0x64: //FS
            case 0x65: //GS
                break;
            case 0x66: //32bit->16bit
                thread_inst->op_size = WORD;
                break;
            case 0x67:
                break;
            default:
                return inst;
        }
        inst++;
    }
}

static inline unsigned long get_immediate(const unsigned char *inst, int op_size)
{
    int mod, reg, rm;
    unsigned long val = 0;
    int i;

    mod = (*inst >> 6) & 3;
    reg = (*inst >> 3) & 7;
    rm = *inst & 7;

    inst++; //skip ModR/M byte
    if (mod != 3 && rm == 4) {
        inst++; //skip SIB byte
    }

    switch(mod) {
        case 0:
            if (rm == 5) {
                inst = inst + 4; //disp32, skip 4 bytes
            }
            break;
        case 1:
            inst++; //disp8, skip 1 byte
            break;
        case 2:
            inst = inst + 4; //disp32, skip 4 bytes
    }
    for (i = 0; i < op_size; i++) {
        val |= (*inst++ & 0xff) << (8 * i);
    }
    
    return val;
}

static inline int get_index(const unsigned char *inst)
{
    int mod, reg, rm;

    mod = (*inst >> 6) & 3;
    reg = (*inst >> 3) & 7;
    rm = *inst & 7;

    //Only one operand in the instruction is register
    if (mod == 3) {
        return rm;
    } else {
        return reg;
    }
    return 0;
}

static int vmx_decode(const unsigned char *inst, struct instruction *thread_inst)
{
    int index;

    switch(*inst) {
        case 0x88:
            /* mov r8 to m8 */
            thread_inst->op_size = BYTE;
            index = get_index((inst + 1));
            thread_inst->operand[0] = mk_operand(BYTE, index, 0, REGISTER);
            break;
        case 0x89:
            /* mov r32/16 to m32/16 */
            index = get_index((inst + 1));
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[0] = mk_operand(WORD, index, 0, REGISTER);
            } else {
                thread_inst->op_size = LONG;
                thread_inst->operand[0] = mk_operand(LONG, index, 0, REGISTER);
            }
            break;
        case 0x8a:
            /* mov m8 to r8 */
            thread_inst->op_size = BYTE;
            index = get_index((inst + 1));
            thread_inst->operand[1] = mk_operand(BYTE, index, 0, REGISTER);
            break;
        case 0x8b:
            /* mov r32/16 to m32/16 */
            index = get_index((inst + 1));
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[1] = mk_operand(WORD, index, 0, REGISTER);
            } else {
                thread_inst->op_size = LONG;
                thread_inst->operand[1] = mk_operand(LONG, index, 0, REGISTER);
            }
            break;
        case 0x8c:
        case 0x8e:
            printk("%x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
            /* Not handle it yet. */

        case 0xa0:
            /* mov byte to al */
            thread_inst->op_size = BYTE;
            thread_inst->operand[1] = mk_operand(BYTE, 0, 0, REGISTER);
            break;
        case 0xa1:
            /* mov word/doubleword to ax/eax */
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[1] = mk_operand(WORD, 0, 0, REGISTER);
            } else {
                thread_inst->op_size = LONG;
                thread_inst->operand[1] = mk_operand(LONG, 0, 0, REGISTER);
            }
            break;
        case 0xa2:
            /* mov al to (seg:offset) */
            thread_inst->op_size = BYTE;
            thread_inst->operand[0] = mk_operand(BYTE, 0, 0, REGISTER);
            break;
        case 0xa3:
            /* mov ax/eax to (seg:offset) */
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[0] = mk_operand(WORD, 0, 0, REGISTER);
            } else {
                thread_inst->op_size = LONG;
                thread_inst->operand[0] = mk_operand(LONG, 0, 0, REGISTER);
            }
            break;
        case 0xa4:
            /* movsb */
            thread_inst->op_size = BYTE;
            strcpy(thread_inst->i_name, "movs");
            
            return DECODE_success;
        case 0xa5:
            /* movsw/movsl */
            if (thread_inst->op_size == WORD) {
            } else {
                thread_inst->op_size = LONG;
            }
            
            strcpy(thread_inst->i_name, "movs");
            
            return DECODE_success;

        case 0xc6:
            /* mov imm8 to m8 */
            thread_inst->op_size = BYTE;
            thread_inst->operand[0] = mk_operand(BYTE, 0, 0, IMMEDIATE);
            thread_inst->immediate = get_immediate((inst+1), thread_inst->op_size);
            break;
        case 0xc7:
            /* mov imm16/32 to m16/32 */
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[0] = mk_operand(WORD, 0, 0, IMMEDIATE);
            } else {
                thread_inst->op_size = LONG;
                thread_inst->operand[0] = mk_operand(LONG, 0, 0, IMMEDIATE);
            }
            thread_inst->immediate = get_immediate((inst+1), thread_inst->op_size);
            break;

        case 0x0f:
            break;
        default:
            printk("%x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
    }
    
    strcpy(thread_inst->i_name, "mov");
    if (*inst != 0x0f) {
        return DECODE_success;
    }

    inst++;
    switch (*inst) {
                    
        /* movz */
        case 0xb6:
            index = get_index((inst + 1));
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[1] = mk_operand(WORD, index, 0, REGISTER);
            } else {
                thread_inst->operand[1] = mk_operand(LONG, index, 0, REGISTER);
                
            }
            thread_inst->op_size = BYTE;
            strcpy(thread_inst->i_name, "movzb");
            
            return DECODE_success;
        case 0xb7:
            thread_inst->op_size = WORD;
            index = get_index((inst + 1));
            thread_inst->operand[1] = mk_operand(LONG, index, 0, REGISTER);
            strcpy(thread_inst->i_name, "movzw");
            
            return DECODE_success;
        default:
            printk("0f %x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
    }

    /* will never reach here */
    return DECODE_failure;
}

static int inst_copy_from_guest(char *buf, unsigned long guest_eip, int inst_len)
{
    unsigned long gpte;
    unsigned long mfn;
    unsigned long ma;
    unsigned char * inst_start;
        
    if (inst_len > MAX_INST_LEN || inst_len <= 0) {
        return 0;
    }

    if ((guest_eip & PAGE_MASK) == ((guest_eip + inst_len) & PAGE_MASK)) {
        gpte = gva_to_gpte(guest_eip);
        mfn = phys_to_machine_mapping(gpte >> PAGE_SHIFT);
        ma = (mfn << PAGE_SHIFT) | (guest_eip & (PAGE_SIZE - 1));
        inst_start = (unsigned char *)map_domain_mem(ma);
                
        memcpy(buf, inst_start, inst_len);
        unmap_domain_mem(inst_start);
    } else {
        // Todo: In two page frames
        BUG();
    }
        
    return inst_len;
}

static void init_instruction(struct instruction *mmio_inst)
{
    memset(mmio_inst->i_name, '0', I_NAME_LEN);
    mmio_inst->op_size =  0;
    mmio_inst->offset = 0;
    mmio_inst->immediate = 0;
    mmio_inst->seg_sel = 0;
    mmio_inst->op_num = 0;

    mmio_inst->operand[0] = 0;
    mmio_inst->operand[1] = 0;
    mmio_inst->operand[2] = 0;
        
    mmio_inst->flags = 0;
}

static int read_from_mmio(struct instruction *inst_p)
{
    // Only for mov instruction now!!!
    if (inst_p->operand[1] & REGISTER)
        return 1;

    return 0;
}

// dir:  1 read from mmio
//       0 write to mmio
static void send_mmio_req(unsigned long gpa, 
                   struct instruction *inst_p, long value, int dir, int pvalid)
{
    struct exec_domain *d = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct mi_per_cpu_info *mpci_p;
    struct xen_regs *inst_decoder_regs;
    extern long evtchn_send(int lport);
    extern long do_block(void);

    mpci_p = &current->arch.arch_vmx.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;
    vio = (vcpu_iodata_t *) d->arch.arch_vmx.vmx_platform.shared_page_va;
        
    if (vio == NULL) {
        printk("bad shared page\n");
        domain_crash(); 
    }
    p = &vio->vp_ioreq;
        
    set_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags);
    p->dir = dir;
    p->pdata_valid = pvalid;
    p->count = 1;

    p->port_mm = 1;
    p->size = inst_p->op_size;
    p->addr = gpa;
    p->u.data = value;

    // p->state = STATE_UPSTREAM_SENDING;
    p->state = STATE_IOREQ_READY;

    // Try to use ins/outs' framework
    if (pvalid) {
        // Handle "movs"
        p->u.pdata = (void *) ((p->dir == IOREQ_WRITE) ?
                               inst_decoder_regs->esi
                               : inst_decoder_regs->edi); 
        p->u.pdata = (void *) gva_to_gpa(p->u.data);
        p->count = inst_decoder_regs->ecx;
        inst_decoder_regs->ecx = 0;
        p->df = (inst_decoder_regs->eflags & EF_DF) ? 1 : 0;
    }

    evtchn_send(IOPACKET_PORT);
    do_block(); 

}

void handle_mmio(unsigned long va, unsigned long gpa)
{
    unsigned long eip;
    unsigned long inst_len;
    struct mi_per_cpu_info *mpci_p;
    struct xen_regs *inst_decoder_regs;
    struct instruction mmio_inst;
    unsigned char inst[MAX_INST_LEN];
    int ret;
     
    mpci_p = &current->arch.arch_vmx.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    __vmread(GUEST_EIP, &eip);
    __vmread(INSTRUCTION_LEN, &inst_len);

    memset(inst, '0', MAX_INST_LEN);
    ret = inst_copy_from_guest(inst, eip, inst_len);
    if (ret != inst_len) {
        printk("handle_mmio - EXIT: get guest instruction fault\n");
        domain_crash();
    }

    init_instruction(&mmio_inst);
    
    if (vmx_decode(check_prefix(inst, &mmio_inst), &mmio_inst) == DECODE_failure)
        domain_crash();

    __vmwrite(GUEST_EIP, eip + inst_len);
    store_xen_regs(inst_decoder_regs);

    // Only handle "mov" and "movs" instructions!
    if (!strncmp(mmio_inst.i_name, "movz", 4)) {
        if (read_from_mmio(&mmio_inst)) {
            // Send the request and waiting for return value.
            mpci_p->mmio_target = mmio_inst.operand[1] | WZEROEXTEND;
            send_mmio_req(gpa, &mmio_inst, 0, 1, 0);
            return ;
        } else {
            printk("handle_mmio - EXIT: movz error!\n");
            domain_crash();
        }
    }

    if (!strncmp(mmio_inst.i_name, "movs", 4)) {
        int tmp_dir;

        tmp_dir = ((va == inst_decoder_regs->edi) ? IOREQ_WRITE : IOREQ_READ);
        send_mmio_req(gpa, &mmio_inst, 0, tmp_dir, 1);
        return;
    }

    if (!strncmp(mmio_inst.i_name, "mov", 3)) {
        long value = 0;
        int size, index;

        if (read_from_mmio(&mmio_inst)) {
            // Send the request and waiting for return value.
            mpci_p->mmio_target = mmio_inst.operand[1];
            send_mmio_req(gpa, &mmio_inst, value, 1, 0);
        } else {
            // Write to MMIO
            if (mmio_inst.operand[0] & IMMEDIATE) {
                value = mmio_inst.immediate;
            } else if (mmio_inst.operand[0] & REGISTER) {
                size = operand_size(mmio_inst.operand[0]);
                index = operand_index(mmio_inst.operand[0]);
                value = get_reg_value(size, index, 0, inst_decoder_regs);
            } else {
                domain_crash();
            }
            send_mmio_req(gpa, &mmio_inst, value, 0, 0);
            return;
        }
        domain_crash();
    }
    domain_crash();
}

#endif /* CONFIG_VMX */
