/*
 * vvmx.c: Support virtual VMX for nested virtualization.
 *
 * Copyright (c) 2010, Intel Corporation.
 * Author: Qing He <qing.he@intel.com>
 *         Eddie Dong <eddie.dong@intel.com>
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
#include <asm/types.h>
#include <asm/mtrr.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vvmx.h>
#include <asm/hvm/nestedhvm.h>

static void nvmx_purge_vvmcs(struct vcpu *v);

int nvmx_vcpu_initialise(struct vcpu *v)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    nvcpu->nv_n2vmcx = alloc_xenheap_page();
    if ( !nvcpu->nv_n2vmcx )
    {
        gdprintk(XENLOG_ERR, "nest: allocation for shadow vmcs failed\n");
	goto out;
    }
    nvmx->vmxon_region_pa = 0;
    nvcpu->nv_vvmcx = NULL;
    nvcpu->nv_vvmcxaddr = VMCX_EADDR;
    nvmx->intr.intr_info = 0;
    nvmx->intr.error_code = 0;
    nvmx->iobitmap[0] = NULL;
    nvmx->iobitmap[1] = NULL;
    return 0;
out:
    return -ENOMEM;
}
 
void nvmx_vcpu_destroy(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    nvmx_purge_vvmcs(v);
    if ( nvcpu->nv_n2vmcx ) {
        __vmpclear(virt_to_maddr(nvcpu->nv_n2vmcx));
        free_xenheap_page(nvcpu->nv_n2vmcx);
        nvcpu->nv_n2vmcx = NULL;
    }
}
 
int nvmx_vcpu_reset(struct vcpu *v)
{
    return 0;
}

uint64_t nvmx_vcpu_guestcr3(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

uint64_t nvmx_vcpu_hostcr3(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

uint32_t nvmx_vcpu_asid(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

enum x86_segment sreg_to_index[] = {
    [VMX_SREG_ES] = x86_seg_es,
    [VMX_SREG_CS] = x86_seg_cs,
    [VMX_SREG_SS] = x86_seg_ss,
    [VMX_SREG_DS] = x86_seg_ds,
    [VMX_SREG_FS] = x86_seg_fs,
    [VMX_SREG_GS] = x86_seg_gs,
};

struct vmx_inst_decoded {
#define VMX_INST_MEMREG_TYPE_MEMORY 0
#define VMX_INST_MEMREG_TYPE_REG    1
    int type;
    union {
        struct {
            unsigned long mem;
            unsigned int  len;
        };
        enum vmx_regs_enc reg1;
    };

    enum vmx_regs_enc reg2;
};

enum vmx_ops_result {
    VMSUCCEED,
    VMFAIL_VALID,
    VMFAIL_INVALID,
};

#define CASE_SET_REG(REG, reg)      \
    case VMX_REG_ ## REG: regs->reg = value; break
#define CASE_GET_REG(REG, reg)      \
    case VMX_REG_ ## REG: value = regs->reg; break

static int vvmcs_offset(u32 width, u32 type, u32 index)
{
    int offset;

    offset = (index & 0x1f) | type << 5 | width << 7;

    if ( offset == 0 )    /* vpid */
        offset = 0x3f;

    return offset;
}

u64 __get_vvmcs(void *vvmcs, u32 vmcs_encoding)
{
    union vmcs_encoding enc;
    u64 *content = (u64 *) vvmcs;
    int offset;
    u64 res;

    enc.word = vmcs_encoding;
    offset = vvmcs_offset(enc.width, enc.type, enc.index);
    res = content[offset];

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res &= 0xffff;
        break;
   case VVMCS_WIDTH_64:
        if ( enc.access_type )
            res >>= 32;
        break;
    case VVMCS_WIDTH_32:
        res &= 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        break;
    }

    return res;
}

void __set_vvmcs(void *vvmcs, u32 vmcs_encoding, u64 val)
{
    union vmcs_encoding enc;
    u64 *content = (u64 *) vvmcs;
    int offset;
    u64 res;

    enc.word = vmcs_encoding;
    offset = vvmcs_offset(enc.width, enc.type, enc.index);
    res = content[offset];

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res = val & 0xffff;
        break;
    case VVMCS_WIDTH_64:
        if ( enc.access_type )
        {
            res &= 0xffffffff;
            res |= val << 32;
        }
        else
            res = val;
        break;
    case VVMCS_WIDTH_32:
        res = val & 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        res = val;
        break;
    }

    content[offset] = res;
}

static unsigned long reg_read(struct cpu_user_regs *regs,
                              enum vmx_regs_enc index)
{
    unsigned long value = 0;

    switch ( index ) {
    CASE_GET_REG(RAX, eax);
    CASE_GET_REG(RCX, ecx);
    CASE_GET_REG(RDX, edx);
    CASE_GET_REG(RBX, ebx);
    CASE_GET_REG(RBP, ebp);
    CASE_GET_REG(RSI, esi);
    CASE_GET_REG(RDI, edi);
    CASE_GET_REG(RSP, esp);
#ifdef CONFIG_X86_64
    CASE_GET_REG(R8, r8);
    CASE_GET_REG(R9, r9);
    CASE_GET_REG(R10, r10);
    CASE_GET_REG(R11, r11);
    CASE_GET_REG(R12, r12);
    CASE_GET_REG(R13, r13);
    CASE_GET_REG(R14, r14);
    CASE_GET_REG(R15, r15);
#endif
    default:
        break;
    }

    return value;
}

static void reg_write(struct cpu_user_regs *regs,
                      enum vmx_regs_enc index,
                      unsigned long value)
{
    switch ( index ) {
    CASE_SET_REG(RAX, eax);
    CASE_SET_REG(RCX, ecx);
    CASE_SET_REG(RDX, edx);
    CASE_SET_REG(RBX, ebx);
    CASE_SET_REG(RBP, ebp);
    CASE_SET_REG(RSI, esi);
    CASE_SET_REG(RDI, edi);
    CASE_SET_REG(RSP, esp);
#ifdef CONFIG_X86_64
    CASE_SET_REG(R8, r8);
    CASE_SET_REG(R9, r9);
    CASE_SET_REG(R10, r10);
    CASE_SET_REG(R11, r11);
    CASE_SET_REG(R12, r12);
    CASE_SET_REG(R13, r13);
    CASE_SET_REG(R14, r14);
    CASE_SET_REG(R15, r15);
#endif
    default:
        break;
    }
}

static inline u32 __n2_exec_control(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    return __get_vvmcs(nvcpu->nv_vvmcx, CPU_BASED_VM_EXEC_CONTROL);
}

static int vmx_inst_check_privilege(struct cpu_user_regs *regs, int vmxop_check)
{
    struct vcpu *v = current;
    struct segment_register cs;

    hvm_get_segment_register(v, x86_seg_cs, &cs);

    if ( vmxop_check )
    {
        if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) ||
             !(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_VMXE) )
            goto invalid_op;
    }
    else if ( !vcpu_2_nvmx(v).vmxon_region_pa )
        goto invalid_op;

    if ( (regs->eflags & X86_EFLAGS_VM) ||
         (hvm_long_mode_enabled(v) && cs.attr.fields.l == 0) )
        goto invalid_op;
    else if ( nestedhvm_vcpu_in_guestmode(v) )
        goto vmexit;

    if ( (cs.sel & 3) > 0 )
        goto gp_fault;

    return X86EMUL_OKAY;

vmexit:
    gdprintk(XENLOG_ERR, "vmx_inst_check_privilege: vmexit\n");
    vcpu_nestedhvm(v).nv_vmexit_pending = 1;
    return X86EMUL_EXCEPTION;
    
invalid_op:
    gdprintk(XENLOG_ERR, "vmx_inst_check_privilege: invalid_op\n");
    hvm_inject_exception(TRAP_invalid_op, 0, 0);
    return X86EMUL_EXCEPTION;

gp_fault:
    gdprintk(XENLOG_ERR, "vmx_inst_check_privilege: gp_fault\n");
    hvm_inject_exception(TRAP_gp_fault, 0, 0);
    return X86EMUL_EXCEPTION;
}

static int decode_vmx_inst(struct cpu_user_regs *regs,
                           struct vmx_inst_decoded *decode,
                           unsigned long *poperandS, int vmxon_check)
{
    struct vcpu *v = current;
    union vmx_inst_info info;
    struct segment_register seg;
    unsigned long base, index, seg_base, disp, offset;
    int scale, size;

    if ( vmx_inst_check_privilege(regs, vmxon_check) != X86EMUL_OKAY )
        return X86EMUL_EXCEPTION;

    info.word = __vmread(VMX_INSTRUCTION_INFO);

    if ( info.fields.memreg ) {
        decode->type = VMX_INST_MEMREG_TYPE_REG;
        decode->reg1 = info.fields.reg1;
        if ( poperandS != NULL )
            *poperandS = reg_read(regs, decode->reg1);
    }
    else
    {
        bool_t mode_64bit = 0;

        decode->type = VMX_INST_MEMREG_TYPE_MEMORY;

        if ( hvm_long_mode_enabled(v) )
        {
            hvm_get_segment_register(v, x86_seg_cs, &seg);
            mode_64bit = seg.attr.fields.l;
        }

        if ( info.fields.segment > VMX_SREG_GS )
            goto gp_fault;
        hvm_get_segment_register(v, sreg_to_index[info.fields.segment], &seg);
        seg_base = seg.base;

        base = info.fields.base_reg_invalid ? 0 :
            reg_read(regs, info.fields.base_reg);

        index = info.fields.index_reg_invalid ? 0 :
            reg_read(regs, info.fields.index_reg);

        scale = 1 << info.fields.scaling;

        disp = __vmread(EXIT_QUALIFICATION);

        size = 1 << (info.fields.addr_size + 1);

        offset = base + index * scale + disp;
        base = !mode_64bit || info.fields.segment >= VMX_SREG_FS ?
               seg_base + offset : offset;
        if ( offset + size - 1 < offset ||
             (mode_64bit ?
              !is_canonical_address((long)base < 0 ? base :
                                    base + size - 1) :
              offset + size - 1 > seg.limit) )
            goto gp_fault;

        if ( poperandS != NULL &&
             hvm_copy_from_guest_virt(poperandS, base, size, 0)
                  != HVMCOPY_okay )
            return X86EMUL_EXCEPTION;
        decode->mem = base;
        decode->len = size;
    }

    decode->reg2 = info.fields.reg2;

    return X86EMUL_OKAY;

gp_fault:
    hvm_inject_exception(TRAP_gp_fault, 0, 0);
    return X86EMUL_EXCEPTION;
}

static void vmreturn(struct cpu_user_regs *regs, enum vmx_ops_result ops_res)
{
    unsigned long eflags = regs->eflags;
    unsigned long mask = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
                         X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF;

    eflags &= ~mask;

    switch ( ops_res ) {
    case VMSUCCEED:
        break;
    case VMFAIL_VALID:
        /* TODO: error number, useful for guest VMM debugging */
        eflags |= X86_EFLAGS_ZF;
        break;
    case VMFAIL_INVALID:
    default:
        eflags |= X86_EFLAGS_CF;
        break;
    }

    regs->eflags = eflags;
}

int nvmx_intercepts_exception(struct vcpu *v, unsigned int trap,
                               int error_code)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    u32 exception_bitmap, pfec_match=0, pfec_mask=0;
    int r;

    ASSERT ( trap < 32 );

    exception_bitmap = __get_vvmcs(nvcpu->nv_vvmcx, EXCEPTION_BITMAP);
    r = exception_bitmap & (1 << trap) ? 1: 0;

    if ( trap == TRAP_page_fault ) {
        pfec_match = __get_vvmcs(nvcpu->nv_vvmcx, PAGE_FAULT_ERROR_CODE_MATCH);
        pfec_mask  = __get_vvmcs(nvcpu->nv_vvmcx, PAGE_FAULT_ERROR_CODE_MASK);
        if ( (error_code & pfec_mask) != pfec_match )
            r = !r;
    }
    return r;
}

/*
 * Nested VMX uses "strict" condition to exit from 
 * L2 guest if either L1 VMM or L0 VMM expect to exit.
 */
static inline u32 __shadow_control(struct vcpu *v,
                                 unsigned int field,
                                 u32 host_value)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    return (u32) __get_vvmcs(nvcpu->nv_vvmcx, field) | host_value;
}

static void set_shadow_control(struct vcpu *v,
                               unsigned int field,
                               u32 host_value)
{
    __vmwrite(field, __shadow_control(v, field, host_value));
}

unsigned long *_shadow_io_bitmap(struct vcpu *v)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    int port80, portED;
    u8 *bitmap;

    bitmap = nvmx->iobitmap[0];
    port80 = bitmap[0x80 >> 3] & (1 << (0x80 & 0x7)) ? 1 : 0;
    portED = bitmap[0xed >> 3] & (1 << (0xed & 0x7)) ? 1 : 0;

    return nestedhvm_vcpu_iomap_get(port80, portED);
}

void nvmx_update_exec_control(struct vcpu *v, u32 host_cntrl)
{
    u32 pio_cntrl = (CPU_BASED_ACTIVATE_IO_BITMAP
                     | CPU_BASED_UNCOND_IO_EXITING);
    unsigned long *bitmap; 
    u32 shadow_cntrl;
 
    shadow_cntrl = __n2_exec_control(v);
    pio_cntrl &= shadow_cntrl;
    /* Enforce the removed features */
    shadow_cntrl &= ~(CPU_BASED_TPR_SHADOW
                      | CPU_BASED_ACTIVATE_MSR_BITMAP
                      | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
                      | CPU_BASED_ACTIVATE_IO_BITMAP
                      | CPU_BASED_UNCOND_IO_EXITING);
    shadow_cntrl |= host_cntrl;
    if ( pio_cntrl == CPU_BASED_UNCOND_IO_EXITING ) {
        /* L1 VMM intercepts all I/O instructions */
        shadow_cntrl |= CPU_BASED_UNCOND_IO_EXITING;
        shadow_cntrl &= ~CPU_BASED_ACTIVATE_IO_BITMAP;
    }
    else {
        /* Use IO_BITMAP in shadow */
        if ( pio_cntrl == 0 ) {
            /* 
             * L1 VMM doesn't intercept IO instruction.
             * Use host configuration and reset IO_BITMAP
             */
            bitmap = hvm_io_bitmap;
        }
        else {
            /* use IO bitmap */
            bitmap = _shadow_io_bitmap(v);
        }
        __vmwrite(IO_BITMAP_A, virt_to_maddr(bitmap));
        __vmwrite(IO_BITMAP_B, virt_to_maddr(bitmap) + PAGE_SIZE);
    }

    /* TODO: change L0 intr window to MTF or NMI window */
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, shadow_cntrl);
}

void nvmx_update_secondary_exec_control(struct vcpu *v,
                                            unsigned long value)
{
    set_shadow_control(v, SECONDARY_VM_EXEC_CONTROL, value);
}

static void nvmx_update_pin_control(struct vcpu *v, unsigned long host_cntrl)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, PIN_BASED_VM_EXEC_CONTROL);
    shadow_cntrl &= ~PIN_BASED_PREEMPT_TIMER;
    shadow_cntrl |= host_cntrl;
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, shadow_cntrl);
}

static void nvmx_update_exit_control(struct vcpu *v, unsigned long host_cntrl)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_CONTROLS);
    shadow_cntrl &= ~(VM_EXIT_SAVE_DEBUG_CNTRLS 
                      | VM_EXIT_SAVE_GUEST_PAT
                      | VM_EXIT_SAVE_GUEST_EFER
                      | VM_EXIT_SAVE_PREEMPT_TIMER);
    shadow_cntrl |= host_cntrl;
    __vmwrite(VM_EXIT_CONTROLS, shadow_cntrl);
}

static void nvmx_update_entry_control(struct vcpu *v)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, VM_ENTRY_CONTROLS);
    shadow_cntrl &= ~(VM_ENTRY_LOAD_GUEST_PAT | VM_ENTRY_LOAD_GUEST_EFER);
    __vmwrite(VM_ENTRY_CONTROLS, shadow_cntrl);
}

void nvmx_update_exception_bitmap(struct vcpu *v, unsigned long value)
{
    set_shadow_control(v, EXCEPTION_BITMAP, value);
}

static void __clear_current_vvmcs(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    
    if ( nvcpu->nv_n2vmcx )
        __vmpclear(virt_to_maddr(nvcpu->nv_n2vmcx));
}

static void __map_io_bitmap(struct vcpu *v, u64 vmcs_reg)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    unsigned long gpa;
    int index;

    index = vmcs_reg == IO_BITMAP_A ? 0 : 1;
    if (nvmx->iobitmap[index])
        hvm_unmap_guest_frame (nvmx->iobitmap[index]); 
    gpa = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx, vmcs_reg);
    nvmx->iobitmap[index] = hvm_map_guest_frame_ro(gpa >> PAGE_SHIFT);
}

static inline void map_io_bitmap_all(struct vcpu *v)
{
   __map_io_bitmap (v, IO_BITMAP_A);
   __map_io_bitmap (v, IO_BITMAP_B);
}

static void nvmx_purge_vvmcs(struct vcpu *v)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    int i;

    __clear_current_vvmcs(v);
    if ( nvcpu->nv_vvmcxaddr != VMCX_EADDR )
        hvm_unmap_guest_frame(nvcpu->nv_vvmcx);
    nvcpu->nv_vvmcx = NULL;
    nvcpu->nv_vvmcxaddr = VMCX_EADDR;
    for (i=0; i<2; i++) {
        if ( nvmx->iobitmap[i] ) {
            hvm_unmap_guest_frame(nvmx->iobitmap[i]); 
            nvmx->iobitmap[i] = NULL;
        }
    }
}

u64 nvmx_get_tsc_offset(struct vcpu *v)
{
    u64 offset = 0;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    if ( __get_vvmcs(nvcpu->nv_vvmcx, CPU_BASED_VM_EXEC_CONTROL) &
         CPU_BASED_USE_TSC_OFFSETING )
        offset = __get_vvmcs(nvcpu->nv_vvmcx, TSC_OFFSET);

    return offset;
}

/*
 * Context synchronized between shadow and virtual VMCS.
 */
static unsigned long vmcs_gstate_field[] = {
    /* 16 BITS */
    GUEST_ES_SELECTOR,
    GUEST_CS_SELECTOR,
    GUEST_SS_SELECTOR,
    GUEST_DS_SELECTOR,
    GUEST_FS_SELECTOR,
    GUEST_GS_SELECTOR,
    GUEST_LDTR_SELECTOR,
    GUEST_TR_SELECTOR,
    /* 64 BITS */
    VMCS_LINK_POINTER,
    GUEST_IA32_DEBUGCTL,
#ifndef CONFIG_X86_64
    VMCS_LINK_POINTER_HIGH,
    GUEST_IA32_DEBUGCTL_HIGH,
#endif
    /* 32 BITS */
    GUEST_ES_LIMIT,
    GUEST_CS_LIMIT,
    GUEST_SS_LIMIT,
    GUEST_DS_LIMIT,
    GUEST_FS_LIMIT,
    GUEST_GS_LIMIT,
    GUEST_LDTR_LIMIT,
    GUEST_TR_LIMIT,
    GUEST_GDTR_LIMIT,
    GUEST_IDTR_LIMIT,
    GUEST_ES_AR_BYTES,
    GUEST_CS_AR_BYTES,
    GUEST_SS_AR_BYTES,
    GUEST_DS_AR_BYTES,
    GUEST_FS_AR_BYTES,
    GUEST_GS_AR_BYTES,
    GUEST_LDTR_AR_BYTES,
    GUEST_TR_AR_BYTES,
    GUEST_INTERRUPTIBILITY_INFO,
    GUEST_ACTIVITY_STATE,
    GUEST_SYSENTER_CS,
    /* natural */
    GUEST_ES_BASE,
    GUEST_CS_BASE,
    GUEST_SS_BASE,
    GUEST_DS_BASE,
    GUEST_FS_BASE,
    GUEST_GS_BASE,
    GUEST_LDTR_BASE,
    GUEST_TR_BASE,
    GUEST_GDTR_BASE,
    GUEST_IDTR_BASE,
    GUEST_DR7,
    /*
     * Following guest states are in local cache (cpu_user_regs)
     GUEST_RSP,
     GUEST_RIP,
     */
    GUEST_RFLAGS,
    GUEST_PENDING_DBG_EXCEPTIONS,
    GUEST_SYSENTER_ESP,
    GUEST_SYSENTER_EIP,
};

/*
 * Context: shadow -> virtual VMCS
 */
static unsigned long vmcs_ro_field[] = {
    GUEST_PHYSICAL_ADDRESS,
    VM_INSTRUCTION_ERROR,
    VM_EXIT_REASON,
    VM_EXIT_INTR_INFO,
    VM_EXIT_INTR_ERROR_CODE,
    IDT_VECTORING_INFO,
    IDT_VECTORING_ERROR_CODE,
    VM_EXIT_INSTRUCTION_LEN,
    VMX_INSTRUCTION_INFO,
    EXIT_QUALIFICATION,
    GUEST_LINEAR_ADDRESS
};

static struct vmcs_host_to_guest {
    unsigned long host_field;
    unsigned long guest_field;
} vmcs_h2g_field[] = {
    {HOST_ES_SELECTOR, GUEST_ES_SELECTOR},
    {HOST_CS_SELECTOR, GUEST_CS_SELECTOR},
    {HOST_SS_SELECTOR, GUEST_SS_SELECTOR},
    {HOST_DS_SELECTOR, GUEST_DS_SELECTOR},
    {HOST_FS_SELECTOR, GUEST_FS_SELECTOR},
    {HOST_GS_SELECTOR, GUEST_GS_SELECTOR},
    {HOST_TR_SELECTOR, GUEST_TR_SELECTOR},
    {HOST_SYSENTER_CS, GUEST_SYSENTER_CS},
    {HOST_FS_BASE, GUEST_FS_BASE},
    {HOST_GS_BASE, GUEST_GS_BASE},
    {HOST_TR_BASE, GUEST_TR_BASE},
    {HOST_GDTR_BASE, GUEST_GDTR_BASE},
    {HOST_IDTR_BASE, GUEST_IDTR_BASE},
    {HOST_SYSENTER_ESP, GUEST_SYSENTER_ESP},
    {HOST_SYSENTER_EIP, GUEST_SYSENTER_EIP},
};

static void vvmcs_to_shadow(void *vvmcs, unsigned int field)
{
    u64 value;

    value = __get_vvmcs(vvmcs, field);
    __vmwrite(field, value);
}

static void shadow_to_vvmcs(void *vvmcs, unsigned int field)
{
    u64 value;
    int rc;

    value = __vmread_safe(field, &rc);
    if ( !rc )
        __set_vvmcs(vvmcs, field, value);
}

static void load_shadow_control(struct vcpu *v)
{
    /*
     * Set shadow controls:  PIN_BASED, CPU_BASED, EXIT, ENTRY
     * and EXCEPTION
     * Enforce the removed features
     */
    nvmx_update_pin_control(v, vmx_pin_based_exec_control);
    vmx_update_cpu_exec_control(v);
    nvmx_update_exit_control(v, vmx_vmexit_control);
    nvmx_update_entry_control(v);
    vmx_update_exception_bitmap(v);
}

static void load_shadow_guest_state(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;
    int i;

    /* vvmcs.gstate to shadow vmcs.gstate */
    for ( i = 0; i < ARRAY_SIZE(vmcs_gstate_field); i++ )
        vvmcs_to_shadow(vvmcs, vmcs_gstate_field[i]);

    hvm_set_cr0(__get_vvmcs(vvmcs, GUEST_CR0));
    hvm_set_cr4(__get_vvmcs(vvmcs, GUEST_CR4));
    hvm_set_cr3(__get_vvmcs(vvmcs, GUEST_CR3));

    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);

    vvmcs_to_shadow(vvmcs, VM_ENTRY_INTR_INFO);
    vvmcs_to_shadow(vvmcs, VM_ENTRY_EXCEPTION_ERROR_CODE);
    vvmcs_to_shadow(vvmcs, VM_ENTRY_INSTRUCTION_LEN);

    vvmcs_to_shadow(vvmcs, CR0_READ_SHADOW);
    vvmcs_to_shadow(vvmcs, CR4_READ_SHADOW);
    vvmcs_to_shadow(vvmcs, CR0_GUEST_HOST_MASK);
    vvmcs_to_shadow(vvmcs, CR4_GUEST_HOST_MASK);

    /* TODO: PDPTRs for nested ept */
    /* TODO: CR3 target control */
}

static void virtual_vmentry(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;
#ifdef __x86_64__
    unsigned long lm_l1, lm_l2;
#endif

    vmx_vmcs_switch(v->arch.hvm_vmx.vmcs, nvcpu->nv_n2vmcx);

    nestedhvm_vcpu_enter_guestmode(v);
    nvcpu->nv_vmentry_pending = 0;
    nvcpu->nv_vmswitch_in_progress = 1;

#ifdef __x86_64__
    /*
     * EFER handling:
     * hvm_set_efer won't work if CR0.PG = 1, so we change the value
     * directly to make hvm_long_mode_enabled(v) work in L2.
     * An additional update_paging_modes is also needed if
     * there is 32/64 switch. v->arch.hvm_vcpu.guest_efer doesn't
     * need to be saved, since its value on vmexit is determined by
     * L1 exit_controls
     */
    lm_l1 = !!hvm_long_mode_enabled(v);
    lm_l2 = !!(__get_vvmcs(vvmcs, VM_ENTRY_CONTROLS) &
                           VM_ENTRY_IA32E_MODE);

    if ( lm_l2 )
        v->arch.hvm_vcpu.guest_efer |= EFER_LMA | EFER_LME;
    else
        v->arch.hvm_vcpu.guest_efer &= ~(EFER_LMA | EFER_LME);
#endif

    load_shadow_control(v);
    load_shadow_guest_state(v);

#ifdef __x86_64__
    if ( lm_l1 != lm_l2 )
        paging_update_paging_modes(v);
#endif

    regs->eip = __get_vvmcs(vvmcs, GUEST_RIP);
    regs->esp = __get_vvmcs(vvmcs, GUEST_RSP);
    regs->eflags = __get_vvmcs(vvmcs, GUEST_RFLAGS);

    /* updating host cr0 to sync TS bit */
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);

    /* TODO: EPT_POINTER */
}

static void sync_vvmcs_guest_state(struct vcpu *v, struct cpu_user_regs *regs)
{
    int i;
    unsigned long mask;
    unsigned long cr;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;

    /* copy shadow vmcs.gstate back to vvmcs.gstate */
    for ( i = 0; i < ARRAY_SIZE(vmcs_gstate_field); i++ )
        shadow_to_vvmcs(vvmcs, vmcs_gstate_field[i]);
    /* RIP, RSP are in user regs */
    __set_vvmcs(vvmcs, GUEST_RIP, regs->eip);
    __set_vvmcs(vvmcs, GUEST_RSP, regs->esp);

    /* SDM 20.6.6: L2 guest execution may change GUEST CR0/CR4 */
    mask = __get_vvmcs(vvmcs, CR0_GUEST_HOST_MASK);
    if ( ~mask )
    {
        cr = __get_vvmcs(vvmcs, GUEST_CR0);
        cr = (cr & mask) | (__vmread(GUEST_CR0) & ~mask);
        __set_vvmcs(vvmcs, GUEST_CR0, cr);
    }

    mask = __get_vvmcs(vvmcs, CR4_GUEST_HOST_MASK);
    if ( ~mask )
    {
        cr = __get_vvmcs(vvmcs, GUEST_CR4);
        cr = (cr & mask) | (__vmread(GUEST_CR4) & ~mask);
        __set_vvmcs(vvmcs, GUEST_CR4, cr);
    }

    /* CR3 sync if exec doesn't want cr3 load exiting: i.e. nested EPT */
    if ( !(__n2_exec_control(v) & CPU_BASED_CR3_LOAD_EXITING) )
        shadow_to_vvmcs(vvmcs, GUEST_CR3);
}

static void sync_vvmcs_ro(struct vcpu *v)
{
    int i;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    for ( i = 0; i < ARRAY_SIZE(vmcs_ro_field); i++ )
        shadow_to_vvmcs(nvcpu->nv_vvmcx, vmcs_ro_field[i]);
}

static void load_vvmcs_host_state(struct vcpu *v)
{
    int i;
    u64 r;
    void *vvmcs = vcpu_nestedhvm(v).nv_vvmcx;

    for ( i = 0; i < ARRAY_SIZE(vmcs_h2g_field); i++ )
    {
        r = __get_vvmcs(vvmcs, vmcs_h2g_field[i].host_field);
        __vmwrite(vmcs_h2g_field[i].guest_field, r);
    }

    hvm_set_cr0(__get_vvmcs(vvmcs, HOST_CR0));
    hvm_set_cr4(__get_vvmcs(vvmcs, HOST_CR4));
    hvm_set_cr3(__get_vvmcs(vvmcs, HOST_CR3));

    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);

    __set_vvmcs(vvmcs, VM_ENTRY_INTR_INFO, 0);
}

static void sync_exception_state(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);

    if ( !(nvmx->intr.intr_info & INTR_INFO_VALID_MASK) )
        return;

    switch ( (nvmx->intr.intr_info & INTR_INFO_INTR_TYPE_MASK) >> 8 )
    {
    case X86_EVENTTYPE_EXT_INTR:
        /* rename exit_reason to EXTERNAL_INTERRUPT */
        __set_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_REASON,
                    EXIT_REASON_EXTERNAL_INTERRUPT);
        __set_vvmcs(nvcpu->nv_vvmcx, EXIT_QUALIFICATION, 0);
        __set_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_INTR_INFO,
                    nvmx->intr.intr_info);
        break;

    case X86_EVENTTYPE_HW_EXCEPTION:
    case X86_EVENTTYPE_SW_INTERRUPT:
    case X86_EVENTTYPE_SW_EXCEPTION:
        /* throw to L1 */
        __set_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_INTR_INFO,
                    nvmx->intr.intr_info);
        __set_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_INTR_ERROR_CODE,
                    nvmx->intr.error_code);
        break;
    case X86_EVENTTYPE_NMI:
    default:
        gdprintk(XENLOG_ERR, "Exception state %lx not handled\n",
               nvmx->intr.intr_info); 
        break;
    }
}

static void virtual_vmexit(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
#ifdef __x86_64__
    unsigned long lm_l1, lm_l2;
#endif

    sync_vvmcs_ro(v);
    sync_vvmcs_guest_state(v, regs);
    sync_exception_state(v);

    vmx_vmcs_switch(v->arch.hvm_vmx.vmcs, nvcpu->nv_n1vmcx);

    nestedhvm_vcpu_exit_guestmode(v);
    nvcpu->nv_vmexit_pending = 0;

#ifdef __x86_64__
    lm_l2 = !!hvm_long_mode_enabled(v);
    lm_l1 = !!(__get_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_CONTROLS) &
                           VM_EXIT_IA32E_MODE);

    if ( lm_l1 )
        v->arch.hvm_vcpu.guest_efer |= EFER_LMA | EFER_LME;
    else
        v->arch.hvm_vcpu.guest_efer &= ~(EFER_LMA | EFER_LME);
#endif

    vmx_update_cpu_exec_control(v);
    vmx_update_exception_bitmap(v);

    load_vvmcs_host_state(v);

#ifdef __x86_64__
    if ( lm_l1 != lm_l2 )
        paging_update_paging_modes(v);
#endif

    regs->eip = __get_vvmcs(nvcpu->nv_vvmcx, HOST_RIP);
    regs->esp = __get_vvmcs(nvcpu->nv_vvmcx, HOST_RSP);
    regs->eflags = __vmread(GUEST_RFLAGS);

    /* updating host cr0 to sync TS bit */
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);

    vmreturn(regs, VMSUCCEED);
}

void nvmx_switch_guest(void)
{
    struct vcpu *v = current;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    /*
     * a softirq may interrupt us between a virtual vmentry is
     * just handled and the true vmentry. If during this window,
     * a L1 virtual interrupt causes another virtual vmexit, we
     * cannot let that happen or VM_ENTRY_INTR_INFO will be lost.
     */
    if ( unlikely(nvcpu->nv_vmswitch_in_progress) )
        return;

    if ( nestedhvm_vcpu_in_guestmode(v) && nvcpu->nv_vmexit_pending )
        virtual_vmexit(regs);
    else if ( !nestedhvm_vcpu_in_guestmode(v) && nvcpu->nv_vmentry_pending )
        virtual_vmentry(regs);
}

/*
 * VMX instructions handling
 */

int nvmx_handle_vmxon(struct cpu_user_regs *regs)
{
    struct vcpu *v=current;
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    struct vmx_inst_decoded decode;
    unsigned long gpa = 0;
    int rc;

    rc = decode_vmx_inst(regs, &decode, &gpa, 1);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( nvmx->vmxon_region_pa )
        gdprintk(XENLOG_WARNING, 
                 "vmxon again: orig %"PRIpaddr" new %lx\n",
                 nvmx->vmxon_region_pa, gpa);

    nvmx->vmxon_region_pa = gpa;

    /*
     * `fork' the host vmcs to shadow_vmcs
     * vmcs_lock is not needed since we are on current
     */
    nvcpu->nv_n1vmcx = v->arch.hvm_vmx.vmcs;
    __vmpclear(virt_to_maddr(v->arch.hvm_vmx.vmcs));
    memcpy(nvcpu->nv_n2vmcx, v->arch.hvm_vmx.vmcs, PAGE_SIZE);
    __vmptrld(virt_to_maddr(v->arch.hvm_vmx.vmcs));
    v->arch.hvm_vmx.launched = 0;
    vmreturn(regs, VMSUCCEED);

    return X86EMUL_OKAY;
}

int nvmx_handle_vmxoff(struct cpu_user_regs *regs)
{
    struct vcpu *v=current;
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    int rc;

    rc = vmx_inst_check_privilege(regs, 0);
    if ( rc != X86EMUL_OKAY )
        return rc;

    nvmx_purge_vvmcs(v);
    nvmx->vmxon_region_pa = 0;

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

int nvmx_vmresume(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    int rc;

    rc = vmx_inst_check_privilege(regs, 0);
    if ( rc != X86EMUL_OKAY )
        return rc;

    /* check VMCS is valid and IO BITMAP is set */
    if ( (nvcpu->nv_vvmcxaddr != VMCX_EADDR) &&
            ((nvmx->iobitmap[0] && nvmx->iobitmap[1]) ||
            !(__n2_exec_control(v) & CPU_BASED_ACTIVATE_IO_BITMAP) ) )
        nvcpu->nv_vmentry_pending = 1;
    else
        vmreturn(regs, VMFAIL_INVALID);

    return X86EMUL_OKAY;
}

int nvmx_handle_vmresume(struct cpu_user_regs *regs)
{
    int launched;
    struct vcpu *v = current;

    if ( vcpu_nestedhvm(v).nv_vvmcxaddr == VMCX_EADDR )
    {
        vmreturn (regs, VMFAIL_INVALID);
        return X86EMUL_OKAY;        
    }

    launched = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx,
                           NVMX_LAUNCH_STATE);
    if ( !launched ) {
       vmreturn (regs, VMFAIL_VALID);
       return X86EMUL_OKAY;
    }
    return nvmx_vmresume(v,regs);
}

int nvmx_handle_vmlaunch(struct cpu_user_regs *regs)
{
    int launched;
    int rc;
    struct vcpu *v = current;

    if ( vcpu_nestedhvm(v).nv_vvmcxaddr == VMCX_EADDR )
    {
        vmreturn (regs, VMFAIL_INVALID);
        return X86EMUL_OKAY;        
    }

    launched = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx,
                           NVMX_LAUNCH_STATE);
    if ( launched ) {
       vmreturn (regs, VMFAIL_VALID);
       return X86EMUL_OKAY;
    }
    else {
        rc = nvmx_vmresume(v,regs);
        if ( rc == X86EMUL_OKAY )
            __set_vvmcs(vcpu_nestedhvm(v).nv_vvmcx,
                        NVMX_LAUNCH_STATE, 1);
    }
    return rc;
}

int nvmx_handle_vmptrld(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmx_inst_decoded decode;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    unsigned long gpa = 0;
    int rc;

    rc = decode_vmx_inst(regs, &decode, &gpa, 0);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( gpa == vcpu_2_nvmx(v).vmxon_region_pa || gpa & 0xfff )
    {
        vmreturn(regs, VMFAIL_INVALID);
        goto out;
    }

    if ( nvcpu->nv_vvmcxaddr != gpa )
        nvmx_purge_vvmcs(v);

    if ( nvcpu->nv_vvmcxaddr == VMCX_EADDR )
    {
        nvcpu->nv_vvmcx = hvm_map_guest_frame_rw(gpa >> PAGE_SHIFT);
        nvcpu->nv_vvmcxaddr = gpa;
        map_io_bitmap_all (v);
    }

    vmreturn(regs, VMSUCCEED);

out:
    return X86EMUL_OKAY;
}

int nvmx_handle_vmptrst(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmx_inst_decoded decode;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    unsigned long gpa = 0;
    int rc;

    rc = decode_vmx_inst(regs, &decode, &gpa, 0);
    if ( rc != X86EMUL_OKAY )
        return rc;

    gpa = nvcpu->nv_vvmcxaddr;

    rc = hvm_copy_to_guest_virt(decode.mem, &gpa, decode.len, 0);
    if ( rc != HVMCOPY_okay )
        return X86EMUL_EXCEPTION;

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

int nvmx_handle_vmclear(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmx_inst_decoded decode;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    unsigned long gpa = 0;
    void *vvmcs;
    int rc;

    rc = decode_vmx_inst(regs, &decode, &gpa, 0);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( gpa & 0xfff )
    {
        vmreturn(regs, VMFAIL_INVALID);
        return X86EMUL_OKAY;
    }
    
    if ( gpa == nvcpu->nv_vvmcxaddr ) 
    {
        __set_vvmcs(nvcpu->nv_vvmcx, NVMX_LAUNCH_STATE, 0);
        nvmx_purge_vvmcs(v);
    }
    else 
    {
        /* Even if this VMCS isn't the current one, we must clear it. */
        vvmcs = hvm_map_guest_frame_rw(gpa >> PAGE_SHIFT);
        if ( vvmcs ) 
            __set_vvmcs(vvmcs, NVMX_LAUNCH_STATE, 0);
        hvm_unmap_guest_frame(vvmcs);
    }

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

int nvmx_handle_vmread(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmx_inst_decoded decode;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    u64 value = 0;
    int rc;

    rc = decode_vmx_inst(regs, &decode, NULL, 0);
    if ( rc != X86EMUL_OKAY )
        return rc;

    value = __get_vvmcs(nvcpu->nv_vvmcx, reg_read(regs, decode.reg2));

    switch ( decode.type ) {
    case VMX_INST_MEMREG_TYPE_MEMORY:
        rc = hvm_copy_to_guest_virt(decode.mem, &value, decode.len, 0);
        if ( rc != HVMCOPY_okay )
            return X86EMUL_EXCEPTION;
        break;
    case VMX_INST_MEMREG_TYPE_REG:
        reg_write(regs, decode.reg1, value);
        break;
    }

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

int nvmx_handle_vmwrite(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmx_inst_decoded decode;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    unsigned long operand; 
    u64 vmcs_encoding;

    if ( decode_vmx_inst(regs, &decode, &operand, 0)
             != X86EMUL_OKAY )
        return X86EMUL_EXCEPTION;

    vmcs_encoding = reg_read(regs, decode.reg2);
    __set_vvmcs(nvcpu->nv_vvmcx, vmcs_encoding, operand);

    if ( vmcs_encoding == IO_BITMAP_A || vmcs_encoding == IO_BITMAP_A_HIGH )
        __map_io_bitmap (v, IO_BITMAP_A);
    else if ( vmcs_encoding == IO_BITMAP_B || 
              vmcs_encoding == IO_BITMAP_B_HIGH )
        __map_io_bitmap (v, IO_BITMAP_B);

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

/*
 * Capability reporting
 */
int nvmx_msr_read_intercept(unsigned int msr, u64 *msr_content)
{
    u64 data = 0, tmp;
    int r = 1;

    if ( !nestedhvm_enabled(current->domain) )
        return 0;

    /*
     * Remove unsupport features from n1 guest capability MSR
     */
    switch (msr) {
    case MSR_IA32_VMX_BASIC:
        data = VVMCS_REVISION | ((u64)PAGE_SIZE) << 32 | 
               ((u64)MTRR_TYPE_WRBACK) << 50 | (1ULL << 55);
        break;
    case MSR_IA32_VMX_PINBASED_CTLS:
        /* 1-seetings */
        data = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
        data <<= 32;
	/* 0-settings */
        data |= 0;
        break;
    case MSR_IA32_VMX_PROCBASED_CTLS:
        /* 1-seetings */
        data = (CPU_BASED_HLT_EXITING |
               CPU_BASED_VIRTUAL_INTR_PENDING |
               CPU_BASED_CR8_LOAD_EXITING |
               CPU_BASED_CR8_STORE_EXITING |
               CPU_BASED_INVLPG_EXITING |
               CPU_BASED_CR3_LOAD_EXITING |
               CPU_BASED_CR3_STORE_EXITING |
               CPU_BASED_MONITOR_EXITING |
               CPU_BASED_MWAIT_EXITING |
               CPU_BASED_MOV_DR_EXITING |
               CPU_BASED_ACTIVATE_IO_BITMAP |
               CPU_BASED_USE_TSC_OFFSETING |
               CPU_BASED_UNCOND_IO_EXITING |
               CPU_BASED_RDTSC_EXITING);
        /* bit 1, 4-6,8,13-16,26 must be 1 (refer G4 of SDM) */
        tmp = ( (1<<26) | (0xf << 13) | 0x100 | (0x7 << 4) | 0x2);
        /* 0-settings */
        data = ((data | tmp) << 32) | (tmp);
        break;
    case MSR_IA32_VMX_EXIT_CTLS:
        /* 1-seetings */
        /* bit 0-8, 10,11,13,14,16,17 must be 1 (refer G4 of SDM) */
        tmp = 0x36dff;
        data = VM_EXIT_ACK_INTR_ON_EXIT;
#ifdef __x86_64__
        data |= VM_EXIT_IA32E_MODE;
#endif
	/* 0-settings */
        data = ((data | tmp) << 32) | tmp;
        break;
    case MSR_IA32_VMX_ENTRY_CTLS:
        /* bit 0-8, and 12 must be 1 (refer G5 of SDM) */
        data = 0x11ff;
        data |= VM_ENTRY_IA32E_MODE;
        data = (data << 32) | data;
        break;

    case IA32_FEATURE_CONTROL_MSR:
        data = IA32_FEATURE_CONTROL_MSR_LOCK | 
               IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX;
        break;
    case MSR_IA32_VMX_VMCS_ENUM:
        /* The max index of VVMCS encoding is 0x1f. */
        data = 0x1f << 1;
        break;
    case MSR_IA32_VMX_CR0_FIXED0:
        /* PG, PE bits must be 1 in VMX operation */
        data = X86_CR0_PE | X86_CR0_PG;
        break;
    case MSR_IA32_VMX_CR0_FIXED1:
        /* allow 0-settings for all bits */
        data = 0xffffffff;
        break;
    case MSR_IA32_VMX_CR4_FIXED0:
        /* VMXE bit must be 1 in VMX operation */
        data = X86_CR4_VMXE;
        break;
    case MSR_IA32_VMX_CR4_FIXED1:
        /* allow 0-settings except SMXE */
        data = 0x267ff & ~X86_CR4_SMXE;
        break;
    case MSR_IA32_VMX_MISC:
        gdprintk(XENLOG_WARNING, "VMX MSR %x not fully supported yet.\n", msr);
        break;
    default:
        r = 0;
        break;
    }

    *msr_content = data;
    return r;
}

int nvmx_msr_write_intercept(unsigned int msr, u64 msr_content)
{
    /* silently ignore for now */
    return 1;
}

void nvmx_idtv_handling(void)
{
    struct vcpu *v = current;
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    unsigned int idtv_info = __vmread(IDT_VECTORING_INFO);

    if ( likely(!(idtv_info & INTR_INFO_VALID_MASK)) )
        return;

    /*
     * If L0 can solve the fault that causes idt vectoring, it should
     * be reinjected, otherwise, pass to L1.
     */
    if ( (__vmread(VM_EXIT_REASON) != EXIT_REASON_EPT_VIOLATION &&
          !(nvmx->intr.intr_info & INTR_INFO_VALID_MASK)) ||
         (__vmread(VM_EXIT_REASON) == EXIT_REASON_EPT_VIOLATION &&
          !nvcpu->nv_vmexit_pending) )
    {
        __vmwrite(VM_ENTRY_INTR_INFO, idtv_info & ~INTR_INFO_RESVD_BITS_MASK);
        if ( idtv_info & INTR_INFO_DELIVER_CODE_MASK )
           __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE,
                        __vmread(IDT_VECTORING_ERROR_CODE));
        /*
         * SDM 23.2.4, if L1 tries to inject a software interrupt
         * and the delivery fails, VM_EXIT_INSTRUCTION_LEN receives
         * the value of previous VM_ENTRY_INSTRUCTION_LEN.
         *
         * This means EXIT_INSTRUCTION_LEN is always valid here, for
         * software interrupts both injected by L1, and generated in L2.
         */
        __vmwrite(VM_ENTRY_INSTRUCTION_LEN, __vmread(VM_EXIT_INSTRUCTION_LEN));
   }
}

/*
 * L2 VMExit handling
 *    return 1: Done or skip the normal layer 0 hypervisor process.
 *              Typically it requires layer 1 hypervisor processing
 *              or it may be already processed here.
 *           0: Require the normal layer 0 process.
 */
int nvmx_n2_vmexit_handler(struct cpu_user_regs *regs,
                               unsigned int exit_reason)
{
    struct vcpu *v = current;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    u32 ctrl;
    u16 port;
    u8 *bitmap;

    nvcpu->nv_vmexit_pending = 0;
    nvmx->intr.intr_info = 0;
    nvmx->intr.error_code = 0;

    switch (exit_reason) {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        u32 intr_info = __vmread(VM_EXIT_INTR_INFO);
        u32 valid_mask = (X86_EVENTTYPE_HW_EXCEPTION << 8) |
                         INTR_INFO_VALID_MASK;
        u64 exec_bitmap;
        int vector = intr_info & INTR_INFO_VECTOR_MASK;

        /*
         * decided by L0 and L1 exception bitmap, if the vetor is set by
         * both, L0 has priority on #PF and #NM, L1 has priority on others
         */
        if ( vector == TRAP_page_fault )
        {
            if ( paging_mode_hap(v->domain) )
                nvcpu->nv_vmexit_pending = 1;
        }
        else if ( vector == TRAP_no_device )
        {
            if ( v->fpu_dirtied )
                nvcpu->nv_vmexit_pending = 1;
        }
        else if ( (intr_info & valid_mask) == valid_mask )
        {
            exec_bitmap =__get_vvmcs(nvcpu->nv_vvmcx, EXCEPTION_BITMAP);

            if ( exec_bitmap & (1 << vector) )
                nvcpu->nv_vmexit_pending = 1;
        }
        break;
    }
    case EXIT_REASON_WBINVD:
    case EXIT_REASON_EPT_VIOLATION:
    case EXIT_REASON_EPT_MISCONFIG:
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        /* pass to L0 handler */
        break;
    case VMX_EXIT_REASONS_FAILED_VMENTRY:
    case EXIT_REASON_TRIPLE_FAULT:
    case EXIT_REASON_TASK_SWITCH:
    case EXIT_REASON_CPUID:
    case EXIT_REASON_MSR_READ:
    case EXIT_REASON_MSR_WRITE:
    case EXIT_REASON_VMCALL:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_INVEPT:
        /* inject to L1 */
        nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_IO_INSTRUCTION:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_ACTIVATE_IO_BITMAP )
        {
            port = __vmread(EXIT_QUALIFICATION) >> 16;
            bitmap = nvmx->iobitmap[port >> 15];
            if ( bitmap[(port & 0x7fff) >> 4] & (1 << (port & 0x7)) )
                nvcpu->nv_vmexit_pending = 1;
            if ( !nvcpu->nv_vmexit_pending )
               gdprintk(XENLOG_WARNING, "L0 PIO %x.\n", port);
        }
        else if ( ctrl & CPU_BASED_UNCOND_IO_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;

    case EXIT_REASON_PENDING_VIRT_INTR:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_VIRTUAL_INTR_PENDING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_PENDING_VIRT_NMI:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_VIRTUAL_NMI_PENDING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    /* L1 has priority handling several other types of exits */
    case EXIT_REASON_HLT:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_HLT_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_RDTSC:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_RDTSC_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        else
        {
            uint64_t tsc;

            /*
             * special handler is needed if L1 doesn't intercept rdtsc,
             * avoiding changing guest_tsc and messing up timekeeping in L1
             */
            tsc = hvm_get_guest_tsc(v);
            tsc += __get_vvmcs(nvcpu->nv_vvmcx, TSC_OFFSET);
            regs->eax = (uint32_t)tsc;
            regs->edx = (uint32_t)(tsc >> 32);

            return 1;
        }
        break;
    case EXIT_REASON_RDPMC:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_RDPMC_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_MWAIT_INSTRUCTION:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_MWAIT_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_PAUSE_INSTRUCTION:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_PAUSE_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_MONITOR_INSTRUCTION:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_MONITOR_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_DR_ACCESS:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_MOV_DR_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_INVLPG:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_INVLPG_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_CR_ACCESS:
    {
        u64 exit_qualification = __vmread(EXIT_QUALIFICATION);
        int cr = exit_qualification & 15;
        int write = (exit_qualification >> 4) & 3;
        u32 mask = 0;

        /* also according to guest exec_control */
        ctrl = __n2_exec_control(v);

        if ( cr == 3 )
        {
            mask = write? CPU_BASED_CR3_STORE_EXITING:
                          CPU_BASED_CR3_LOAD_EXITING;
            if ( ctrl & mask )
                nvcpu->nv_vmexit_pending = 1;
        }
        else if ( cr == 8 )
        {
            mask = write? CPU_BASED_CR8_STORE_EXITING:
                          CPU_BASED_CR8_LOAD_EXITING;
            if ( ctrl & mask )
                nvcpu->nv_vmexit_pending = 1;
        }
        else  /* CR0, CR4, CLTS, LMSW */
            nvcpu->nv_vmexit_pending = 1;

        break;
    }
    default:
        gdprintk(XENLOG_WARNING, "Unknown nested vmexit reason %x.\n",
                 exit_reason);
    }

    return ( nvcpu->nv_vmexit_pending == 1 );
}

