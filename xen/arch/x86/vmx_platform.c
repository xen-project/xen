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
static void store_cpu_user_regs(struct cpu_user_regs *regs)
{

}

static long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs) 
{
    return 0;
}
#elif defined (__i386__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_ESP, &regs->esp);
    __vmread(GUEST_EFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_EIP, &regs->eip);
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
		printf("Not handling 0x67 (yet)\n");
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
            if (rm == 5) {
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
    unsigned long eflags;
    int index, vm86 = 0;

    __vmread(GUEST_EFLAGS, &eflags);
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
            strcpy((char *)thread_inst->i_name, "movs");
            return DECODE_success;
        case 0xa5:
            /* movsw/movsl */
            if (thread_inst->op_size == WORD) {
            } else {
                thread_inst->op_size = LONG;
            }
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
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[0] = mk_operand(WORD, 0, 0, IMMEDIATE);
            } else {
                thread_inst->op_size = LONG;
                thread_inst->operand[0] = mk_operand(LONG, 0, 0, IMMEDIATE);
            }
            thread_inst->immediate = get_immediate(vm86,
					(inst+1), thread_inst->op_size);
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
            index = get_index((inst + 1));
            if (thread_inst->op_size == WORD) {
                thread_inst->operand[1] = mk_operand(WORD, index, 0, REGISTER);
            } else {
                thread_inst->operand[1] = mk_operand(LONG, index, 0, REGISTER);
                
            }
            thread_inst->op_size = BYTE;
            strcpy((char *)thread_inst->i_name, "movzb");
            
            return DECODE_success;
        case 0xb7:
            thread_inst->op_size = WORD;
            index = get_index((inst + 1));
            thread_inst->operand[1] = mk_operand(LONG, index, 0, REGISTER);
            strcpy((char *)thread_inst->i_name, "movzw");
            
            return DECODE_success;
        default:
            printk("0f %x, This opcode hasn't been handled yet!", *inst);
            return DECODE_failure;
    }

    /* will never reach here */
    return DECODE_failure;
}

static int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip, int inst_len)
{
    l1_pgentry_t gpte;
    unsigned long mfn;
    unsigned long ma;
    unsigned char * inst_start;
        
    if (inst_len > MAX_INST_LEN || inst_len <= 0) {
        return 0;
    }

    if ((guest_eip & PAGE_MASK) == ((guest_eip + inst_len) & PAGE_MASK)) {
        gpte = gva_to_gpte(guest_eip);
        mfn = phys_to_machine_mapping(l1e_get_pfn(gpte));
        ma = (mfn << PAGE_SHIFT) | (guest_eip & (PAGE_SIZE - 1));
        inst_start = (unsigned char *)map_domain_mem(ma);
                
        memcpy((char *)buf, inst_start, inst_len);
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
    int vm86;
    struct mi_per_cpu_info *mpci_p;
    struct cpu_user_regs *inst_decoder_regs;
    extern long evtchn_send(int lport);
    extern long do_block(void);

    mpci_p = &current->arch.arch_vmx.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    vio = (vcpu_iodata_t *) d->arch.arch_vmx.vmx_platform.shared_page_va;
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

    if (pvalid)
        p->u.pdata = (void *) gva_to_gpa(p->u.data);

#if 0
    printf("send_mmio_req: eip 0x%lx:0x%lx, dir %d, pdata_valid %d, ",
	inst_decoder_regs->cs, inst_decoder_regs->eip, p->dir, p->pdata_valid);
    printf("port_mm %d, size %lld, addr 0x%llx, value 0x%lx, count %lld\n",
	p->port_mm, p->size, p->addr, value, p->count);
#endif

    evtchn_send(IOPACKET_PORT);
    do_block(); 
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
     
    mpci_p = &current->arch.arch_vmx.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    __vmread(GUEST_EIP, &eip);
    __vmread(INSTRUCTION_LEN, &inst_len);

    __vmread(GUEST_EFLAGS, &eflags);
    vm86 = eflags & X86_EFLAGS_VM;

    if (vm86) {
        __vmread(GUEST_CS_SELECTOR, &cs);
        inst_addr = (cs << 4) | eip;
    } else
        inst_addr = eip; /* XXX should really look at GDT[cs].base too */

    memset(inst, '0', MAX_INST_LEN);
    ret = inst_copy_from_guest(inst, inst_addr, inst_len);
    if (ret != inst_len) {
        printk("handle_mmio - EXIT: get guest instruction fault\n");
        domain_crash_synchronous();
    }

#if 0
    printk("handle_mmio: cs:eip 0x%lx:0x%lx(0x%lx): opcode",
        cs, eip, inst_addr, inst_len);
    for (ret = 0; ret < inst_len; ret++)
        printk(" %02x", inst[ret]);
    printk("\n");
#endif

    init_instruction(&mmio_inst);
    
    if (vmx_decode(check_prefix(inst, &mmio_inst), &mmio_inst) == DECODE_failure)
        domain_crash_synchronous();

    __vmwrite(GUEST_EIP, eip + inst_len);
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
	    if (((seg << 4) | (inst_decoder_regs->edi & 0xFFFF)) == va) {
		dir = IOREQ_WRITE;
		__vmread(GUEST_DS_SELECTOR, &seg);
		addr = (seg << 4) | (inst_decoder_regs->esi & 0xFFFF);
	    } else {
		dir = IOREQ_READ;
		addr = (seg << 4) | (inst_decoder_regs->edi & 0xFFFF);
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
