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
    nvmx->ept.enabled = 0;
    nvmx->guest_vpid = 0;
    nvmx->vmxon_region_pa = 0;
    nvcpu->nv_vvmcx = NULL;
    nvcpu->nv_vvmcxaddr = VMCX_EADDR;
    nvmx->intr.intr_info = 0;
    nvmx->intr.error_code = 0;
    nvmx->iobitmap[0] = NULL;
    nvmx->iobitmap[1] = NULL;
    nvmx->msrbitmap = NULL;
    return 0;
out:
    return -ENOMEM;
}
 
void nvmx_vcpu_destroy(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    /* 
     * When destroying the vcpu, it may be running on behalf of L2 guest.
     * Therefore we need to switch the VMCS pointer back to the L1 VMCS,
     * in order to avoid double free of L2 VMCS and the possible memory
     * leak of L1 VMCS page.
     */
    if ( nvcpu->nv_n1vmcx )
        v->arch.hvm_vmx.vmcs = nvcpu->nv_n1vmcx;

    if ( nvcpu->nv_n2vmcx ) {
        __vmpclear(virt_to_maddr(nvcpu->nv_n2vmcx));
        free_xenheap_page(nvcpu->nv_n2vmcx);
        nvcpu->nv_n2vmcx = NULL;
    }
}
 
void nvmx_domain_relinquish_resources(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        nvmx_purge_vvmcs(v);
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

uint64_t nvmx_vcpu_eptp_base(struct vcpu *v)
{
    uint64_t eptp_base;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    eptp_base = __get_vvmcs(nvcpu->nv_vvmcx, EPT_POINTER);
    return eptp_base & PAGE_MASK;
}

uint32_t nvmx_vcpu_asid(struct vcpu *v)
{
    /* TODO */
    ASSERT(0);
    return 0;
}

bool_t nvmx_ept_enabled(struct vcpu *v)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);

    return !!(nvmx->ept.enabled);
}

static const enum x86_segment sreg_to_index[] = {
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
    unsigned long *pval = decode_register(index, regs, 0);

    return *pval;
}

static void reg_write(struct cpu_user_regs *regs,
                      enum vmx_regs_enc index,
                      unsigned long value)
{
    unsigned long *pval = decode_register(index, regs, 0);

    *pval = value;
}

static inline u32 __n2_pin_exec_control(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    return __get_vvmcs(nvcpu->nv_vvmcx, PIN_BASED_VM_EXEC_CONTROL);
}

static inline u32 __n2_exec_control(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    return __get_vvmcs(nvcpu->nv_vvmcx, CPU_BASED_VM_EXEC_CONTROL);
}

static inline u32 __n2_secondary_exec_control(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    u64 second_ctrl = 0;

    if ( __n2_exec_control(v) & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS )
        second_ctrl = __get_vvmcs(nvcpu->nv_vvmcx, SECONDARY_VM_EXEC_CONTROL);

    return second_ctrl;
}

static int vmx_inst_check_privilege(struct cpu_user_regs *regs, int vmxop_check)
{
    struct vcpu *v = current;
    struct segment_register cs;

    if ( vmxop_check )
    {
        if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) ||
             !(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_VMXE) )
            goto invalid_op;
    }
    else if ( !vcpu_2_nvmx(v).vmxon_region_pa )
        goto invalid_op;

    vmx_get_segment_register(v, x86_seg_cs, &cs);

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
    hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
    return X86EMUL_EXCEPTION;

gp_fault:
    gdprintk(XENLOG_ERR, "vmx_inst_check_privilege: gp_fault\n");
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
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
            vmx_get_segment_register(v, x86_seg_cs, &seg);
            mode_64bit = seg.attr.fields.l;
        }

        if ( info.fields.segment > VMX_SREG_GS )
            goto gp_fault;
        vmx_get_segment_register(v, sreg_to_index[info.fields.segment], &seg);
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
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
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
    shadow_cntrl &= ~(CPU_BASED_ACTIVATE_MSR_BITMAP
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
                                        unsigned long host_cntrl)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, SECONDARY_VM_EXEC_CONTROL);
    nvmx->ept.enabled = !!(shadow_cntrl & SECONDARY_EXEC_ENABLE_EPT);
    shadow_cntrl |= host_cntrl;
    __vmwrite(SECONDARY_VM_EXEC_CONTROL, shadow_cntrl);
}

static void nvmx_update_pin_control(struct vcpu *v, unsigned long host_cntrl)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, PIN_BASED_VM_EXEC_CONTROL);
    shadow_cntrl |= host_cntrl;
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, shadow_cntrl);
}

static void nvmx_update_exit_control(struct vcpu *v, unsigned long host_cntrl)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_CONTROLS);
    shadow_cntrl &= ~(VM_EXIT_SAVE_DEBUG_CNTRLS 
                      | VM_EXIT_LOAD_HOST_PAT
                      | VM_EXIT_LOAD_HOST_EFER
                      | VM_EXIT_LOAD_PERF_GLOBAL_CTRL);
    shadow_cntrl |= host_cntrl;
    __vmwrite(VM_EXIT_CONTROLS, shadow_cntrl);
}

static void nvmx_update_entry_control(struct vcpu *v)
{
    u32 shadow_cntrl;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    shadow_cntrl = __get_vvmcs(nvcpu->nv_vvmcx, VM_ENTRY_CONTROLS);
    shadow_cntrl &= ~(VM_ENTRY_LOAD_GUEST_PAT
                      | VM_ENTRY_LOAD_GUEST_EFER
                      | VM_ENTRY_LOAD_PERF_GLOBAL_CTRL);
    __vmwrite(VM_ENTRY_CONTROLS, shadow_cntrl);
}

void nvmx_update_exception_bitmap(struct vcpu *v, unsigned long value)
{
    set_shadow_control(v, EXCEPTION_BITMAP, value);
}

static void nvmx_update_apic_access_address(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    u64 apic_gpfn, apic_mfn;
    u32 ctrl;
    void *apic_va;

    ctrl = __n2_secondary_exec_control(v);
    if ( ctrl & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES )
    {
        apic_gpfn = __get_vvmcs(nvcpu->nv_vvmcx, APIC_ACCESS_ADDR) >> PAGE_SHIFT;
        apic_va = hvm_map_guest_frame_ro(apic_gpfn);
        apic_mfn = virt_to_mfn(apic_va);
        __vmwrite(APIC_ACCESS_ADDR, (apic_mfn << PAGE_SHIFT));
        hvm_unmap_guest_frame(apic_va); 
    }
    else
        __vmwrite(APIC_ACCESS_ADDR, 0);
}

static void nvmx_update_virtual_apic_address(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    u64 vapic_gpfn, vapic_mfn;
    u32 ctrl;
    void *vapic_va;

    ctrl = __n2_exec_control(v);
    if ( ctrl & CPU_BASED_TPR_SHADOW )
    {
        vapic_gpfn = __get_vvmcs(nvcpu->nv_vvmcx, VIRTUAL_APIC_PAGE_ADDR) >> PAGE_SHIFT;
        vapic_va = hvm_map_guest_frame_ro(vapic_gpfn);
        vapic_mfn = virt_to_mfn(vapic_va);
        __vmwrite(VIRTUAL_APIC_PAGE_ADDR, (vapic_mfn << PAGE_SHIFT));
        hvm_unmap_guest_frame(vapic_va); 
    }
    else
        __vmwrite(VIRTUAL_APIC_PAGE_ADDR, 0);
}

static void nvmx_update_tpr_threshold(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    u32 ctrl = __n2_exec_control(v);
    if ( ctrl & CPU_BASED_TPR_SHADOW )
        __vmwrite(TPR_THRESHOLD, __get_vvmcs(nvcpu->nv_vvmcx, TPR_THRESHOLD));
    else
        __vmwrite(TPR_THRESHOLD, 0);
}

static void nvmx_update_pfec(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;

    __vmwrite(PAGE_FAULT_ERROR_CODE_MASK,
        __get_vvmcs(vvmcs, PAGE_FAULT_ERROR_CODE_MASK));
    __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH,
        __get_vvmcs(vvmcs, PAGE_FAULT_ERROR_CODE_MATCH));
}

static void __clear_current_vvmcs(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    
    if ( nvcpu->nv_n2vmcx )
        __vmpclear(virt_to_maddr(nvcpu->nv_n2vmcx));
}

static void __map_msr_bitmap(struct vcpu *v)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    unsigned long gpa;

    if ( nvmx->msrbitmap )
        hvm_unmap_guest_frame (nvmx->msrbitmap); 
    gpa = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx, MSR_BITMAP);
    nvmx->msrbitmap = hvm_map_guest_frame_ro(gpa >> PAGE_SHIFT);
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
    if ( nvmx->msrbitmap ) {
        hvm_unmap_guest_frame(nvmx->msrbitmap);
        nvmx->msrbitmap = NULL;
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
static const u16 vmcs_gstate_field[] = {
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
    GUEST_PAT,
    GUEST_EFER,
    GUEST_PERF_GLOBAL_CTRL,
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
    GUEST_PREEMPTION_TIMER,
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
static const u16 vmcs_ro_field[] = {
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
    u16 host_field;
    u16 guest_field;
} const vmcs_h2g_field[] = {
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
    vmx_update_secondary_exec_control(v);
    nvmx_update_exit_control(v, vmx_vmexit_control);
    nvmx_update_entry_control(v);
    vmx_update_exception_bitmap(v);
    nvmx_update_apic_access_address(v);
    nvmx_update_virtual_apic_address(v);
    nvmx_update_tpr_threshold(v);
    nvmx_update_pfec(v);
}

static void load_shadow_guest_state(struct vcpu *v)
{
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;
    int i;
    u32 control;
    u64 cr_gh_mask, cr_read_shadow;

    /* vvmcs.gstate to shadow vmcs.gstate */
    for ( i = 0; i < ARRAY_SIZE(vmcs_gstate_field); i++ )
        vvmcs_to_shadow(vvmcs, vmcs_gstate_field[i]);

    hvm_set_cr0(__get_vvmcs(vvmcs, GUEST_CR0));
    hvm_set_cr4(__get_vvmcs(vvmcs, GUEST_CR4));
    hvm_set_cr3(__get_vvmcs(vvmcs, GUEST_CR3));

    control = __get_vvmcs(vvmcs, VM_ENTRY_CONTROLS);
    if ( control & VM_ENTRY_LOAD_GUEST_PAT )
        hvm_set_guest_pat(v, __get_vvmcs(vvmcs, GUEST_PAT));
    if ( control & VM_ENTRY_LOAD_PERF_GLOBAL_CTRL )
        hvm_msr_write_intercept(MSR_CORE_PERF_GLOBAL_CTRL, __get_vvmcs(vvmcs, GUEST_PERF_GLOBAL_CTRL));

    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);

    vvmcs_to_shadow(vvmcs, VM_ENTRY_INTR_INFO);
    vvmcs_to_shadow(vvmcs, VM_ENTRY_EXCEPTION_ERROR_CODE);
    vvmcs_to_shadow(vvmcs, VM_ENTRY_INSTRUCTION_LEN);

    /*
     * While emulate CR0 and CR4 for nested virtualization, set the CR0/CR4
     * guest host mask to 0xffffffff in shadow VMCS (follow the host L1 VMCS),
     * then calculate the corresponding read shadow separately for CR0 and CR4.
     */
    cr_gh_mask = __get_vvmcs(vvmcs, CR0_GUEST_HOST_MASK);
    cr_read_shadow = (__get_vvmcs(vvmcs, GUEST_CR0) & ~cr_gh_mask) |
                     (__get_vvmcs(vvmcs, CR0_READ_SHADOW) & cr_gh_mask);
    __vmwrite(CR0_READ_SHADOW, cr_read_shadow);

    cr_gh_mask = __get_vvmcs(vvmcs, CR4_GUEST_HOST_MASK);
    cr_read_shadow = (__get_vvmcs(vvmcs, GUEST_CR4) & ~cr_gh_mask) |
                     (__get_vvmcs(vvmcs, CR4_READ_SHADOW) & cr_gh_mask);
    __vmwrite(CR4_READ_SHADOW, cr_read_shadow);

    if ( nvmx_ept_enabled(v) && hvm_pae_enabled(v) &&
         (v->arch.hvm_vcpu.guest_efer & EFER_LMA) )
    {
        vvmcs_to_shadow(vvmcs, GUEST_PDPTR0);
        vvmcs_to_shadow(vvmcs, GUEST_PDPTR1);
        vvmcs_to_shadow(vvmcs, GUEST_PDPTR2);
        vvmcs_to_shadow(vvmcs, GUEST_PDPTR3);
    }

    /* TODO: CR3 target control */
}

uint64_t get_shadow_eptp(struct vcpu *v)
{
    uint64_t np2m_base = nvmx_vcpu_eptp_base(v);
    struct p2m_domain *p2m = p2m_get_nestedp2m(v, np2m_base);
    struct ept_data *ept = &p2m->ept;

    ept->asr = pagetable_get_pfn(p2m_get_pagetable(p2m));
    return ept_get_eptp(ept);
}

static bool_t nvmx_vpid_enabled(struct nestedvcpu *nvcpu)
{
    uint32_t second_cntl;

    second_cntl = __get_vvmcs(nvcpu->nv_vvmcx, SECONDARY_VM_EXEC_CONTROL);
    if ( second_cntl & SECONDARY_EXEC_ENABLE_VPID )
        return 1;
    return 0;
}

static void virtual_vmentry(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;
    unsigned long lm_l1, lm_l2;

    vmx_vmcs_switch(v->arch.hvm_vmx.vmcs, nvcpu->nv_n2vmcx);

    nestedhvm_vcpu_enter_guestmode(v);
    nvcpu->nv_vmentry_pending = 0;
    nvcpu->nv_vmswitch_in_progress = 1;

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

    load_shadow_control(v);
    load_shadow_guest_state(v);

    if ( lm_l1 != lm_l2 )
        paging_update_paging_modes(v);

    regs->eip = __get_vvmcs(vvmcs, GUEST_RIP);
    regs->esp = __get_vvmcs(vvmcs, GUEST_RSP);
    regs->eflags = __get_vvmcs(vvmcs, GUEST_RFLAGS);

    /* updating host cr0 to sync TS bit */
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);

    /* Setup virtual ETP for L2 guest*/
    if ( nestedhvm_paging_mode_hap(v) )
        __vmwrite(EPT_POINTER, get_shadow_eptp(v));

    /* nested VPID support! */
    if ( cpu_has_vmx_vpid && nvmx_vpid_enabled(nvcpu) )
    {
        struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
        uint32_t new_vpid =  __get_vvmcs(vvmcs, VIRTUAL_PROCESSOR_ID);

        if ( nvmx->guest_vpid != new_vpid )
        {
            hvm_asid_flush_vcpu_asid(&vcpu_nestedhvm(v).nv_n2asid);
            nvmx->guest_vpid = new_vpid;
        }
    }

}

static void sync_vvmcs_guest_state(struct vcpu *v, struct cpu_user_regs *regs)
{
    int i;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    void *vvmcs = nvcpu->nv_vvmcx;

    /* copy shadow vmcs.gstate back to vvmcs.gstate */
    for ( i = 0; i < ARRAY_SIZE(vmcs_gstate_field); i++ )
        shadow_to_vvmcs(vvmcs, vmcs_gstate_field[i]);
    /* RIP, RSP are in user regs */
    __set_vvmcs(vvmcs, GUEST_RIP, regs->eip);
    __set_vvmcs(vvmcs, GUEST_RSP, regs->esp);

    /* CR3 sync if exec doesn't want cr3 load exiting: i.e. nested EPT */
    if ( !(__n2_exec_control(v) & CPU_BASED_CR3_LOAD_EXITING) )
        shadow_to_vvmcs(vvmcs, GUEST_CR3);
}

static void sync_vvmcs_ro(struct vcpu *v)
{
    int i;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);
    void *vvmcs = nvcpu->nv_vvmcx;

    for ( i = 0; i < ARRAY_SIZE(vmcs_ro_field); i++ )
        shadow_to_vvmcs(nvcpu->nv_vvmcx, vmcs_ro_field[i]);

    /* Adjust exit_reason/exit_qualifciation for violation case */
    if ( __get_vvmcs(vvmcs, VM_EXIT_REASON) == EXIT_REASON_EPT_VIOLATION )
    {
        __set_vvmcs(vvmcs, EXIT_QUALIFICATION, nvmx->ept.exit_qual);
        __set_vvmcs(vvmcs, VM_EXIT_REASON, nvmx->ept.exit_reason);
    }
}

static void load_vvmcs_host_state(struct vcpu *v)
{
    int i;
    u64 r;
    void *vvmcs = vcpu_nestedhvm(v).nv_vvmcx;
    u32 control;

    for ( i = 0; i < ARRAY_SIZE(vmcs_h2g_field); i++ )
    {
        r = __get_vvmcs(vvmcs, vmcs_h2g_field[i].host_field);
        __vmwrite(vmcs_h2g_field[i].guest_field, r);
    }

    hvm_set_cr0(__get_vvmcs(vvmcs, HOST_CR0));
    hvm_set_cr4(__get_vvmcs(vvmcs, HOST_CR4));
    hvm_set_cr3(__get_vvmcs(vvmcs, HOST_CR3));

    control = __get_vvmcs(vvmcs, VM_EXIT_CONTROLS);
    if ( control & VM_EXIT_LOAD_HOST_PAT )
        hvm_set_guest_pat(v, __get_vvmcs(vvmcs, HOST_PAT));
    if ( control & VM_EXIT_LOAD_PERF_GLOBAL_CTRL )
        hvm_msr_write_intercept(MSR_CORE_PERF_GLOBAL_CTRL, __get_vvmcs(vvmcs, HOST_PERF_GLOBAL_CTRL));

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
    unsigned long lm_l1, lm_l2;

    sync_vvmcs_ro(v);
    sync_vvmcs_guest_state(v, regs);
    sync_exception_state(v);

    vmx_vmcs_switch(v->arch.hvm_vmx.vmcs, nvcpu->nv_n1vmcx);

    nestedhvm_vcpu_exit_guestmode(v);
    nvcpu->nv_vmexit_pending = 0;

    lm_l2 = !!hvm_long_mode_enabled(v);
    lm_l1 = !!(__get_vvmcs(nvcpu->nv_vvmcx, VM_EXIT_CONTROLS) &
                           VM_EXIT_IA32E_MODE);

    if ( lm_l1 )
        v->arch.hvm_vcpu.guest_efer |= EFER_LMA | EFER_LME;
    else
        v->arch.hvm_vcpu.guest_efer &= ~(EFER_LMA | EFER_LME);

    vmx_update_cpu_exec_control(v);
    vmx_update_secondary_exec_control(v);
    vmx_update_exception_bitmap(v);

    load_vvmcs_host_state(v);

    if ( lm_l1 != lm_l2 )
        paging_update_paging_modes(v);

    regs->eip = __get_vvmcs(nvcpu->nv_vvmcx, HOST_RIP);
    regs->esp = __get_vvmcs(nvcpu->nv_vvmcx, HOST_RSP);
    /* VM exit clears all bits except bit 1 */
    regs->eflags = 0x2;

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
        __map_msr_bitmap(v);
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

    if ( vmcs_encoding == MSR_BITMAP || vmcs_encoding == MSR_BITMAP_HIGH )
        __map_msr_bitmap(v);

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

int nvmx_handle_invept(struct cpu_user_regs *regs)
{
    struct vmx_inst_decoded decode;
    unsigned long eptp;
    int ret;

    if ( (ret = decode_vmx_inst(regs, &decode, &eptp, 0)) != X86EMUL_OKAY )
        return ret;

    switch ( reg_read(regs, decode.reg2) )
    {
    case INVEPT_SINGLE_CONTEXT:
    {
        struct p2m_domain *p2m = vcpu_nestedhvm(current).nv_p2m;
        if ( p2m )
        {
            p2m_flush(current, p2m);
            ept_sync_domain(p2m);
        }
        break;
    }
    case INVEPT_ALL_CONTEXT:
        p2m_flush_nestedp2m(current->domain);
        __invept(INVEPT_ALL_CONTEXT, 0, 0);
        break;
    default:
        vmreturn(regs, VMFAIL_INVALID);
        return X86EMUL_OKAY;
    }
    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

int nvmx_handle_invvpid(struct cpu_user_regs *regs)
{
    struct vmx_inst_decoded decode;
    unsigned long vpid;
    int ret;

    if ( (ret = decode_vmx_inst(regs, &decode, &vpid, 0)) != X86EMUL_OKAY )
        return ret;

    switch ( reg_read(regs, decode.reg2) )
    {
    /* Just invalidate all tlb entries for all types! */
    case INVVPID_INDIVIDUAL_ADDR:
    case INVVPID_SINGLE_CONTEXT:
    case INVVPID_ALL_CONTEXT:
        hvm_asid_flush_vcpu_asid(&vcpu_nestedhvm(current).nv_n2asid);
        break;
    default:
        vmreturn(regs, VMFAIL_INVALID);
        return X86EMUL_OKAY;
    }

    vmreturn(regs, VMSUCCEED);
    return X86EMUL_OKAY;
}

#define __emul_value(enable1, default1) \
    ((enable1 | default1) << 32 | (default1))

#define gen_vmx_msr(enable1, default1, host_value) \
    (((__emul_value(enable1, default1) & host_value) & (~0ul << 32)) | \
    ((uint32_t)(__emul_value(enable1, default1) | host_value)))

/*
 * Capability reporting
 */
int nvmx_msr_read_intercept(unsigned int msr, u64 *msr_content)
{
    u64 data = 0, host_data = 0;
    int r = 1;

    if ( !nestedhvm_enabled(current->domain) )
        return 0;

    rdmsrl(msr, host_data);

    /*
     * Remove unsupport features from n1 guest capability MSR
     */
    switch (msr) {
    case MSR_IA32_VMX_BASIC:
        data = (host_data & (~0ul << 32)) | VVMCS_REVISION;
        break;
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
        /* 1-seetings */
        data = PIN_BASED_EXT_INTR_MASK |
               PIN_BASED_NMI_EXITING |
               PIN_BASED_PREEMPT_TIMER;
        data = gen_vmx_msr(data, VMX_PINBASED_CTLS_DEFAULT1, host_data);
        break;
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    {
        u32 default1_bits = VMX_PROCBASED_CTLS_DEFAULT1;
        /* 1-seetings */
        data = CPU_BASED_HLT_EXITING |
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
               CPU_BASED_RDTSC_EXITING |
               CPU_BASED_MONITOR_TRAP_FLAG |
               CPU_BASED_VIRTUAL_NMI_PENDING |
               CPU_BASED_ACTIVATE_MSR_BITMAP |
               CPU_BASED_PAUSE_EXITING |
               CPU_BASED_RDPMC_EXITING |
               CPU_BASED_TPR_SHADOW |
               CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

        if ( msr == MSR_IA32_VMX_TRUE_PROCBASED_CTLS )
            default1_bits &= ~(CPU_BASED_CR3_LOAD_EXITING |
                               CPU_BASED_CR3_STORE_EXITING |
                               CPU_BASED_INVLPG_EXITING);

        data = gen_vmx_msr(data, default1_bits, host_data);
        break;
    }
    case MSR_IA32_VMX_PROCBASED_CTLS2:
        /* 1-seetings */
        data = SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING |
               SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
               SECONDARY_EXEC_ENABLE_VPID |
               SECONDARY_EXEC_ENABLE_EPT;
        data = gen_vmx_msr(data, 0, host_data);
        break;
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
        /* 1-seetings */
        data = VM_EXIT_ACK_INTR_ON_EXIT |
               VM_EXIT_IA32E_MODE |
               VM_EXIT_SAVE_PREEMPT_TIMER |
               VM_EXIT_SAVE_GUEST_PAT |
               VM_EXIT_LOAD_HOST_PAT |
               VM_EXIT_SAVE_GUEST_EFER |
               VM_EXIT_LOAD_HOST_EFER |
               VM_EXIT_LOAD_PERF_GLOBAL_CTRL;
        data = gen_vmx_msr(data, VMX_EXIT_CTLS_DEFAULT1, host_data);
        break;
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
        /* 1-seetings */
        data = VM_ENTRY_LOAD_GUEST_PAT |
               VM_ENTRY_LOAD_GUEST_EFER |
               VM_ENTRY_LOAD_PERF_GLOBAL_CTRL |
               VM_ENTRY_IA32E_MODE;
        data = gen_vmx_msr(data, VMX_ENTRY_CTLS_DEFAULT1, host_data);
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
        /* Do not support CR3-target feature now */
        data = host_data & ~VMX_MISC_CR3_TARGET;
        break;
    case MSR_IA32_VMX_EPT_VPID_CAP:
        data = nept_get_ept_vpid_cap();
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

/* This function uses L2_gpa to walk the P2M page table in L1. If the
 * walk is successful, the translated value is returned in
 * L1_gpa. The result value tells what to do next.
 */
int
nvmx_hap_walk_L1_p2m(struct vcpu *v, paddr_t L2_gpa, paddr_t *L1_gpa,
                     unsigned int *page_order, uint8_t *p2m_acc,
                     bool_t access_r, bool_t access_w, bool_t access_x)
{
    int rc;
    unsigned long gfn;
    uint64_t exit_qual = __vmread(EXIT_QUALIFICATION);
    uint32_t exit_reason = EXIT_REASON_EPT_VIOLATION;
    uint32_t rwx_rights = (access_x << 2) | (access_w << 1) | access_r;
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);

    rc = nept_translate_l2ga(v, L2_gpa, page_order, rwx_rights, &gfn, p2m_acc,
                             &exit_qual, &exit_reason);
    switch ( rc )
    {
    case EPT_TRANSLATE_SUCCEED:
        *L1_gpa = (gfn << PAGE_SHIFT) + (L2_gpa & ~PAGE_MASK);
        rc = NESTEDHVM_PAGEFAULT_DONE;
        break;
    case EPT_TRANSLATE_VIOLATION:
    case EPT_TRANSLATE_MISCONFIG:
        rc = NESTEDHVM_PAGEFAULT_INJECT;
        nvmx->ept.exit_reason = exit_reason;
        nvmx->ept.exit_qual = exit_qual;
        break;
    case EPT_TRANSLATE_RETRY:
        rc = NESTEDHVM_PAGEFAULT_RETRY;
        break;
    default:
        gdprintk(XENLOG_ERR, "GUEST EPT translation error!:%d\n", rc);
        BUG();
        break;
    }

    return rc;
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
    case EXIT_REASON_XSETBV:
        /* inject to L1 */
        nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_MSR_READ:
    case EXIT_REASON_MSR_WRITE:
    {
        int status;
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_ACTIVATE_MSR_BITMAP )
        {
            status = vmx_check_msr_bitmap(nvmx->msrbitmap, regs->ecx,
                         !!(exit_reason == EXIT_REASON_MSR_WRITE));
            if ( status )
                nvcpu->nv_vmexit_pending = 1;
        }
        else
            nvcpu->nv_vmexit_pending = 1;
        break;
    }
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
    case EXIT_REASON_MONITOR_TRAP_FLAG:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_MONITOR_TRAP_FLAG)
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_ACCESS_GDTR_OR_IDTR:
    case EXIT_REASON_ACCESS_LDTR_OR_TR:
        ctrl = __n2_secondary_exec_control(v);
        if ( ctrl & SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        ctrl = __n2_pin_exec_control(v);
        if ( ctrl & PIN_BASED_PREEMPT_TIMER )
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
            update_guest_eip();

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
        if ( (ctrl & CPU_BASED_MOV_DR_EXITING) &&
            v->arch.hvm_vcpu.flag_dr_dirty )
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
        {
            /*
             * While getting the VM exit for CR0/CR4 access, check if L1 VMM owns
             * the bit.
             * If so, inject the VM exit to L1 VMM.
             * Otherwise, L0 will handle it and sync the value to L1 virtual VMCS.
             */
            unsigned long old_val, val, changed_bits;
            switch ( VMX_CONTROL_REG_ACCESS_TYPE(exit_qualification) )
            {
            case VMX_CONTROL_REG_ACCESS_TYPE_MOV_TO_CR:
            {
                unsigned long gp = VMX_CONTROL_REG_ACCESS_GPR(exit_qualification);
                unsigned long *reg;

                if ( (reg = decode_register(gp, guest_cpu_user_regs(), 0)) == NULL )
                {
                    gdprintk(XENLOG_ERR, "invalid gpr: %lx\n", gp);
                    break;
                }
                val = *reg;
                if ( cr == 0 )
                {
                    u64 cr0_gh_mask = __get_vvmcs(nvcpu->nv_vvmcx, CR0_GUEST_HOST_MASK);

                    old_val = __vmread(CR0_READ_SHADOW);
                    changed_bits = old_val ^ val;
                    if ( changed_bits & cr0_gh_mask )
                        nvcpu->nv_vmexit_pending = 1;
                    else
                    {
                        u64 guest_cr0 = __get_vvmcs(nvcpu->nv_vvmcx, GUEST_CR0);
                        __set_vvmcs(nvcpu->nv_vvmcx, GUEST_CR0,
                                    (guest_cr0 & cr0_gh_mask) | (val & ~cr0_gh_mask));
                    }
                }
                else if ( cr == 4 )
                {
                    u64 cr4_gh_mask = __get_vvmcs(nvcpu->nv_vvmcx, CR4_GUEST_HOST_MASK);

                    old_val = __vmread(CR4_READ_SHADOW);
                    changed_bits = old_val ^ val;
                    if ( changed_bits & cr4_gh_mask )
                        nvcpu->nv_vmexit_pending = 1;
                    else
                    {
                        u64 guest_cr4 = __get_vvmcs(nvcpu->nv_vvmcx, GUEST_CR4);
                        __set_vvmcs(nvcpu->nv_vvmcx, GUEST_CR4,
                                    (guest_cr4 & cr4_gh_mask) | (val & ~cr4_gh_mask));
                    }
                }
                else
                    nvcpu->nv_vmexit_pending = 1;
                break;
            }
            case VMX_CONTROL_REG_ACCESS_TYPE_CLTS:
            {
                u64 cr0_gh_mask = __get_vvmcs(nvcpu->nv_vvmcx, CR0_GUEST_HOST_MASK);

                if ( cr0_gh_mask & X86_CR0_TS )
                    nvcpu->nv_vmexit_pending = 1;
                else
                {
                    u64 guest_cr0 = __get_vvmcs(nvcpu->nv_vvmcx, GUEST_CR0);
                    __set_vvmcs(nvcpu->nv_vvmcx, GUEST_CR0, (guest_cr0 & ~X86_CR0_TS));
                }
                break;
            }
            case VMX_CONTROL_REG_ACCESS_TYPE_LMSW:
            {
                u64 cr0_gh_mask = __get_vvmcs(nvcpu->nv_vvmcx, CR0_GUEST_HOST_MASK);

                old_val = __vmread(CR0_READ_SHADOW) & 0xf;
                val = (exit_qualification >> 16) & 0xf;
                changed_bits = old_val ^ val;
                if ( changed_bits & cr0_gh_mask )
                    nvcpu->nv_vmexit_pending = 1;
                else
                {
                    u64 guest_cr0 = __get_vvmcs(nvcpu->nv_vvmcx, GUEST_CR0);
                    __set_vvmcs(nvcpu->nv_vvmcx, GUEST_CR0, (guest_cr0 & cr0_gh_mask) | (val & ~cr0_gh_mask));
                }
                break;
            }
            default:
                break;
            }
        }
        break;
    }
    case EXIT_REASON_APIC_ACCESS:
        ctrl = __n2_secondary_exec_control(v);
        if ( ctrl & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES )
            nvcpu->nv_vmexit_pending = 1;
        break;
    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        ctrl = __n2_exec_control(v);
        if ( ctrl & CPU_BASED_TPR_SHADOW )
            nvcpu->nv_vmexit_pending = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "Unknown nested vmexit reason %x.\n",
                 exit_reason);
    }

    return ( nvcpu->nv_vmexit_pending == 1 );
}

