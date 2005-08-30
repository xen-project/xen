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
#include <xen/domain_page.h>
#include <asm/page.h> 
#include <xen/event.h> 
#include <xen/trace.h>
#include <asm/vmx.h>
#include <asm/vmx_platform.h>
#include <public/io/ioreq.h>

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>
#endif
#ifdef CONFIG_VMX

#define DECODE_success  1
#define DECODE_failure  0

#if defined (__x86_64__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_RSP, &regs->rsp);
    __vmread(GUEST_RFLAGS, &regs->rflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_RIP, &regs->rip);
}

static inline long __get_reg_value(unsigned long reg, int size)
{
    switch(size) {
        case BYTE_64:
            return (char)(reg & 0xFF);
        case WORD:
            return (short)(reg & 0xFFFF);
        case LONG:
            return (int)(reg & 0xFFFFFFFF);
        case QUAD:
            return (long)(reg);
        default:
            printk("Error: <__get_reg_value>Invalid reg size\n");
            domain_crash_synchronous();
    }
}

static long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs) 
{
    if (size == BYTE) {
        switch (index) { 
            case 0: //%al
                return (char)(regs->rax & 0xFF);
            case 1: //%cl  
                return (char)(regs->rcx & 0xFF);
            case 2: //%dl
                return (char)(regs->rdx & 0xFF); 
            case 3: //%bl
                return (char)(regs->rbx & 0xFF);
            case 4: //%ah
                return (char)((regs->rax & 0xFF00) >> 8);
            case 5: //%ch 
                return (char)((regs->rcx & 0xFF00) >> 8);
            case 6: //%dh
                return (char)((regs->rdx & 0xFF00) >> 8);
            case 7: //%bh
                return (char)((regs->rbx & 0xFF00) >> 8);
            default:
                printk("Error: (get_reg_value)Invalid index value\n"); 
                domain_crash_synchronous();
        }

    }
    switch (index) {
        case 0: return __get_reg_value(regs->rax, size);
        case 1: return __get_reg_value(regs->rcx, size);
        case 2: return __get_reg_value(regs->rdx, size);
        case 3: return __get_reg_value(regs->rbx, size);
        case 4: return __get_reg_value(regs->rsp, size);
        case 5: return __get_reg_value(regs->rbp, size);
        case 6: return __get_reg_value(regs->rsi, size);
        case 7: return __get_reg_value(regs->rdi, size);
        case 8: return __get_reg_value(regs->r8, size);
        case 9: return __get_reg_value(regs->r9, size);
        case 10: return __get_reg_value(regs->r10, size);
        case 11: return __get_reg_value(regs->r11, size);
        case 12: return __get_reg_value(regs->r12, size);
        case 13: return __get_reg_value(regs->r13, size);
        case 14: return __get_reg_value(regs->r14, size);
        case 15: return __get_reg_value(regs->r15, size);
        default:
            printk("Error: (get_reg_value)Invalid index value\n"); 
            domain_crash_synchronous();
    }
}
#elif defined (__i386__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_RSP, &regs->esp);
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_RIP, &regs->eip);
}

static long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs)
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
            printk("Error: (get_reg_value)size case 0 error\n"); 
            domain_crash_synchronous();
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
            printk("Error: (get_reg_value)size case 1 error\n");
            domain_crash_synchronous();
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
            printk("Error: (get_reg_value)size case 2 error\n");
            domain_crash_synchronous();
        }
    default:
        printk("Error: (get_reg_value)size case error\n");
        domain_crash_synchronous();
    }
}
#endif

static inline const unsigned char *check_prefix(const unsigned char *inst, struct instruction *thread_inst, unsigned char *rex_p)
{
    while (1) {
        switch (*inst) {
            /* rex prefix for em64t instructions*/
            case 0x40 ... 0x4e:
                *rex_p = *inst;
                break;

            case 0xf3: //REPZ
    	    	thread_inst->flags = REPZ;
	        	break;
            case 0xf2: //REPNZ
    	    	thread_inst->flags = REPNZ;
	        	break;
            case 0xf0: //LOCK
    	    	break;
            case 0x2e: //CS
            case 0x36: //SS
            case 0x3e: //DS
            case 0x26: //ES
            case 0x64: //FS
            case 0x65: //GS
		        thread_inst->seg_sel = *inst;
                break;
            case 0x66: //32bit->16bit
                thread_inst->op_size = WORD;
                break;
            case 0x67:
	        	printf("Error: Not handling 0x67 (yet)\n");
                domain_crash_synchronous();
                break;
            default:
                return inst;
        }
        inst++;
    }
}

static inline unsigned long get_immediate(int op16, const unsigned char *inst, int op_size)
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
            if (rm == 5 || rm == 4) {
                if (op16)
                    inst = inst + 2; //disp16, skip 2 bytes
                else
                    inst = inst + 4; //disp32, skip 4 bytes
            }
            break;
        case 1:
            inst++; //disp8, skip 1 byte
            break;
        case 2:
            if (op16)
                inst = inst + 2; //disp16, skip 2 bytes
            else
                inst = inst + 4; //disp32, skip 4 bytes
            break;
    }

    if (op_size == QUAD)
        op_size = LONG;

    for (i = 0; i < op_size; i++) {
        val |= (*inst++ & 0xff) << (8 * i);
    }

    return val;
}

static inline int get_index(const unsigned char *inst, unsigned char rex)
{
    int mod, reg, rm;
    int rex_r, rex_b;

    mod = (*inst >> 6) & 3;
    reg = (*inst >> 3) & 7;
    rm = *inst & 7;

    rex_r = (rex >> 2) & 1;
    rex_b = rex & 1;

    //Only one operand in the instruction is register
    if (mod == 3) {
        return (rm + (rex_b << 3)); 
    } else {
        return (reg + (rex_r << 3)); 
    }
    return 0;
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

#define GET_OP_SIZE_FOR_BYTE(op_size)   \
    do {if (rex) op_size = BYTE_64;else op_size = BYTE;} while(0)

#define GET_OP_SIZE_FOR_NONEBYTE(op_size)   \
    do {if (rex & 0x8) op_size = QUAD; else if (op_size != WORD) op_size = LONG;} while(0)

static int vmx_decode(const unsigned char *inst, struct instruction *thread_inst)
{
    unsigned long eflags;
    int index, vm86 = 0;
    unsigned char rex = 0;
    unsigned char tmp_size = 0;


    init_instruction(thread_inst);

    inst = check_prefix(inst, thread_inst, &rex);

    __vmread(GUEST_RFLAGS, &eflags);
    if (eflags & X86_EFLAGS_VM)
        vm86 = 1;

    if (vm86) { /* meaning is reversed */
       if (thread_inst->op_size == WORD)
           thread_inst->op_size = LONG;
       else if (thread_inst->op_size == LONG)
           thread_inst->op_size = WORD;
       else if (thread_inst->op_size == 0)
           thread_inst->op_size = WORD;
    }

    switch(*inst) {
        case 0x81:
            /* This is only a workaround for cmpl instruction*/
            strcpy((char *)thread_inst->i_name, "cmp");
            return DECODE_success;

        case 0x88:
            /* mov r8 to m8 */
            thread_inst->op_size = BYTE;
            index = get_index((inst + 1), rex);
            GET_OP_SIZE_FOR_BYTE(tmp_size);
            thread_inst->operand[0] = mk_operand(tmp_size, index, 0, REGISTER);

            break;
        case 0x89:
            /* mov r32/16 to m32/16 */
            index = get_index((inst + 1), rex);
            GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
            thread_inst->operand[0] = mk_operand(thread_inst->op_size, index, 0, REGISTER);

            break;
        case 0x8a:
            /* mov m8 to r8 */
            thread_inst->op_size = BYTE;
            index = get_index((inst + 1), rex);
            GET_OP_SIZE_FOR_BYTE(tmp_size);
            thread_inst->operand[1] = mk_operand(tmp_size, index, 0, REGISTER);
            break;
        case 0x8b:
            /* mov r32/16 to m32/16 */
            index = get_index((inst + 1), rex);
            GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
            thread_inst->operand[1] = mk_operand(thread_inst->op_size, index, 0, REGISTER);
            break;
        case 0x8c:
        case 0x8e:
            printk("%x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
            /* Not handle it yet. */
        case 0xa0:
            /* mov byte to al */
            thread_inst->op_size = BYTE;
            GET_OP_SIZE_FOR_BYTE(tmp_size);
            thread_inst->operand[1] = mk_operand(tmp_size, 0, 0, REGISTER);
            break;
        case 0xa1:
            /* mov word/doubleword to ax/eax */
	    GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
	    thread_inst->operand[1] = mk_operand(thread_inst->op_size, 0, 0, REGISTER);

            break;
        case 0xa2:
            /* mov al to (seg:offset) */
            thread_inst->op_size = BYTE;
            GET_OP_SIZE_FOR_BYTE(tmp_size);
            thread_inst->operand[0] = mk_operand(tmp_size, 0, 0, REGISTER);
            break;
        case 0xa3:
            /* mov ax/eax to (seg:offset) */
            GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
            thread_inst->operand[0] = mk_operand(thread_inst->op_size, 0, 0, REGISTER);
            break;
        case 0xa4:
            /* movsb */
            thread_inst->op_size = BYTE;
            strcpy((char *)thread_inst->i_name, "movs");
            return DECODE_success;
        case 0xa5:
            /* movsw/movsl */
            GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
	    strcpy((char *)thread_inst->i_name, "movs");
            return DECODE_success;
        case 0xaa:
            /* stosb */
            thread_inst->op_size = BYTE;
            strcpy((char *)thread_inst->i_name, "stosb");
            return DECODE_success;
       case 0xab:
            /* stosw/stosl */
            if (thread_inst->op_size == WORD) {
                strcpy((char *)thread_inst->i_name, "stosw");
            } else {
                thread_inst->op_size = LONG;
                strcpy((char *)thread_inst->i_name, "stosl");
            }
            return DECODE_success;
        case 0xc6:
            /* mov imm8 to m8 */
            thread_inst->op_size = BYTE;
            thread_inst->operand[0] = mk_operand(BYTE, 0, 0, IMMEDIATE);
            thread_inst->immediate = get_immediate(vm86,
					(inst+1), thread_inst->op_size);
            break;
        case 0xc7:
            /* mov imm16/32 to m16/32 */
            GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
            thread_inst->operand[0] = mk_operand(thread_inst->op_size, 0, 0, IMMEDIATE);
            thread_inst->immediate = get_immediate(vm86, (inst+1), thread_inst->op_size);
            
            break;
        case 0x0f:
            break;
        default:
            printk("%x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
    }
    
    strcpy((char *)thread_inst->i_name, "mov");
    if (*inst != 0x0f) {
        return DECODE_success;
    }

    inst++;
    switch (*inst) {
                    
        /* movz */
        case 0xb6:
            index = get_index((inst + 1), rex);
            GET_OP_SIZE_FOR_NONEBYTE(thread_inst->op_size);
            thread_inst->operand[1] = mk_operand(thread_inst->op_size, index, 0, REGISTER);
            thread_inst->op_size = BYTE;
            strcpy((char *)thread_inst->i_name, "movzb");
            
            return DECODE_success;
        case 0xb7:
	    index = get_index((inst + 1), rex);
	    if (rex & 0x8) {
		    thread_inst->op_size = LONG;
		    thread_inst->operand[1] = mk_operand(QUAD, index, 0, REGISTER);
	    } else {
		    thread_inst->op_size = WORD;
		    thread_inst->operand[1] = mk_operand(LONG, index, 0, REGISTER);
	    }
            
            strcpy((char *)thread_inst->i_name, "movzw");
            
            return DECODE_success;
        default:
            printk("0f %x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
    }

    /* will never reach here */
    return DECODE_failure;
}

int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip, int inst_len)
{
    unsigned long gpa;
    unsigned long mfn;
    unsigned char *inst_start;
    int remaining = 0;
        
    if ( (inst_len > MAX_INST_LEN) || (inst_len <= 0) )
        return 0;

    if ( vmx_paging_enabled(current) )
    {
        gpa = gva_to_gpa(guest_eip);
        mfn = get_mfn_from_pfn(gpa >> PAGE_SHIFT);

        /* Does this cross a page boundary ? */
        if ( (guest_eip & PAGE_MASK) != ((guest_eip + inst_len) & PAGE_MASK) )
        {
            remaining = (guest_eip + inst_len) & ~PAGE_MASK;
            inst_len -= remaining;
        }
    }
    else
    {
        mfn = get_mfn_from_pfn(guest_eip >> PAGE_SHIFT);
    }

    inst_start = map_domain_page(mfn);
    memcpy((char *)buf, inst_start + (guest_eip & ~PAGE_MASK), inst_len);
    unmap_domain_page(inst_start);

    if ( remaining )
    {
        gpa = gva_to_gpa(guest_eip+inst_len+remaining);
        mfn = get_mfn_from_pfn(gpa >> PAGE_SHIFT);

        inst_start = map_domain_page(mfn);
        memcpy((char *)buf+inst_len, inst_start, remaining);
        unmap_domain_page(inst_start);
    }

    return inst_len+remaining;
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
    struct vcpu *d = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;
    int vm86;
    struct mi_per_cpu_info *mpci_p;
    struct cpu_user_regs *inst_decoder_regs;
    extern long evtchn_send(int lport);

    mpci_p = &current->domain->arch.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    vio = get_vio(d->domain, d->vcpu_id);

    if (vio == NULL) {
        printk("bad shared page\n");
        domain_crash_synchronous(); 
    }
    p = &vio->vp_ioreq;

    vm86 = inst_decoder_regs->eflags & X86_EFLAGS_VM;

    if (test_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags)) {
        printf("VMX I/O has not yet completed\n");
        domain_crash_synchronous();
    }

    set_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags);
    p->dir = dir;
    p->pdata_valid = pvalid;

    p->port_mm = 1;
    p->size = inst_p->op_size;
    p->addr = gpa;
    p->u.data = value;

    p->state = STATE_IOREQ_READY;

    if (inst_p->flags & REPZ) {
        if (vm86)
            p->count = inst_decoder_regs->ecx & 0xFFFF;
        else
            p->count = inst_decoder_regs->ecx;
        p->df = (inst_decoder_regs->eflags & EF_DF) ? 1 : 0;
    } else
        p->count = 1;

    if ((pvalid) && vmx_paging_enabled(current))
        p->u.pdata = (void *) gva_to_gpa(p->u.data);

    if (vmx_mmio_intercept(p)){
        p->state = STATE_IORESP_READY;
        vmx_io_assist(d);
        return;
    }

    evtchn_send(iopacket_port(d->domain));
    vmx_wait_io();
}

void handle_mmio(unsigned long va, unsigned long gpa)
{
    unsigned long eip, eflags, cs;
    unsigned long inst_len, inst_addr;
    struct mi_per_cpu_info *mpci_p;
    struct cpu_user_regs *inst_decoder_regs;
    struct instruction mmio_inst;
    unsigned char inst[MAX_INST_LEN];
    int vm86, ret;
     
    mpci_p = &current->domain->arch.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    __vmread(GUEST_RIP, &eip);
    __vmread(INSTRUCTION_LEN, &inst_len);
    __vmread(GUEST_RFLAGS, &eflags);
    vm86 = eflags & X86_EFLAGS_VM;

    if (vm86) {
        __vmread(GUEST_CS_SELECTOR, &cs);
        inst_addr = (cs << 4) + eip;
    } else
        inst_addr = eip; /* XXX should really look at GDT[cs].base too */

    memset(inst, '0', MAX_INST_LEN);
    ret = inst_copy_from_guest(inst, inst_addr, inst_len);
    if (ret != inst_len) {
        printk("handle_mmio - EXIT: get guest instruction fault\n");
        domain_crash_synchronous();
    }


    init_instruction(&mmio_inst);
    
    if (vmx_decode(inst, &mmio_inst) == DECODE_failure) {
        printk("vmx decode failure: eip=%lx, va=%lx\n %x %x %x %x\n", eip, va, 
               inst[0], inst[1], inst[2], inst[3]);
        domain_crash_synchronous();
    }

    __vmwrite(GUEST_RIP, eip + inst_len);
    store_cpu_user_regs(inst_decoder_regs);

    // Only handle "mov" and "movs" instructions!
    if (!strncmp((char *)mmio_inst.i_name, "movz", 4)) {
        if (read_from_mmio(&mmio_inst)) {
            // Send the request and waiting for return value.
            mpci_p->mmio_target = mmio_inst.operand[1] | WZEROEXTEND;
            send_mmio_req(gpa, &mmio_inst, 0, IOREQ_READ, 0);
            return ;
        } else {
            printk("handle_mmio - EXIT: movz error!\n");
            domain_crash_synchronous();
        }
    }

    if (!strncmp((char *)mmio_inst.i_name, "movs", 4)) {
	unsigned long addr = 0;
	int dir;

	if (vm86) {
	    unsigned long seg;

	    __vmread(GUEST_ES_SELECTOR, &seg);
	    if (((seg << 4) + (inst_decoder_regs->edi & 0xFFFF)) == va) {
		dir = IOREQ_WRITE;
		__vmread(GUEST_DS_SELECTOR, &seg);
		addr = (seg << 4) + (inst_decoder_regs->esi & 0xFFFF);
	    } else {
		dir = IOREQ_READ;
		addr = (seg << 4) + (inst_decoder_regs->edi & 0xFFFF);
	    }
	} else { /* XXX should really look at GDT[ds/es].base too */
	    if (va == inst_decoder_regs->edi) {
		dir = IOREQ_WRITE;
		addr = inst_decoder_regs->esi;
	    } else {
		dir = IOREQ_READ;
		addr = inst_decoder_regs->edi;
	    }
	}

	send_mmio_req(gpa, &mmio_inst, addr, dir, 1);
        return;
    }

    if (!strncmp((char *)mmio_inst.i_name, "mov", 3)) {
        long value = 0;
        int size, index;

        if (read_from_mmio(&mmio_inst)) {
            // Send the request and waiting for return value.
            mpci_p->mmio_target = mmio_inst.operand[1];
            send_mmio_req(gpa, &mmio_inst, value, IOREQ_READ, 0);
            return;
        } else {
            // Write to MMIO
            if (mmio_inst.operand[0] & IMMEDIATE) {
                value = mmio_inst.immediate;
            } else if (mmio_inst.operand[0] & REGISTER) {
                size = operand_size(mmio_inst.operand[0]);
                index = operand_index(mmio_inst.operand[0]);
                value = get_reg_value(size, index, 0, inst_decoder_regs);
            } else {
                domain_crash_synchronous();
            }
            send_mmio_req(gpa, &mmio_inst, value, IOREQ_WRITE, 0);
            return;
        }
    }

    if (!strncmp((char *)mmio_inst.i_name, "stos", 4)) {
        send_mmio_req(gpa, &mmio_inst,
            inst_decoder_regs->eax, IOREQ_WRITE, 0);
        return;
    }
    /* Workaround for cmp instruction */
    if (!strncmp((char *)mmio_inst.i_name, "cmp", 3)) {
        inst_decoder_regs->eflags &= ~X86_EFLAGS_ZF;
        __vmwrite(GUEST_RFLAGS, inst_decoder_regs->eflags);
        return;
    }

    domain_crash_synchronous();
}

#endif /* CONFIG_VMX */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
