/*
 * emulate.c: handling SVM emulate instructions help.
 * Copyright (c) 2005 AMD Corporation.
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/err.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>

static unsigned long svm_nextrip_insn_length(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( !cpu_has_svm_nrips )
        return 0;

#ifndef NDEBUG
    switch ( vmcb->exitcode )
    {
    case VMEXIT_CR0_READ ... VMEXIT_DR15_WRITE:
        /* faults due to instruction intercepts */
        /* (exitcodes 84-95) are reserved */
    case VMEXIT_IDTR_READ ... VMEXIT_TR_WRITE:
    case VMEXIT_RDTSC ... VMEXIT_MSR:
    case VMEXIT_VMRUN ... VMEXIT_XSETBV:
        /* ...and the rest of the #VMEXITs */
    case VMEXIT_CR0_SEL_WRITE:
    case VMEXIT_EXCEPTION_BP:
        break;
    default:
        BUG();
    }
#endif

    return vmcb->nextrip - vmcb->rip;
}

static const struct {
    unsigned int opcode;
    struct {
        unsigned int rm:3;
        unsigned int reg:3;
        unsigned int mod:2;
#define MODRM(mod, reg, rm) { rm, reg, mod }
    } modrm;
} opc_tab[INSTR_MAX_COUNT] = {
    [INSTR_PAUSE]   = { X86EMUL_OPC_F3(0, 0x90) },
    [INSTR_INT3]    = { X86EMUL_OPC(   0, 0xcc) },
    [INSTR_HLT]     = { X86EMUL_OPC(   0, 0xf4) },
    [INSTR_XSETBV]  = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 2, 1) },
    [INSTR_VMRUN]   = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 0) },
    [INSTR_VMCALL]  = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 1) },
    [INSTR_VMLOAD]  = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 2) },
    [INSTR_VMSAVE]  = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 3) },
    [INSTR_STGI]    = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 4) },
    [INSTR_CLGI]    = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 5) },
    [INSTR_INVLPGA] = { X86EMUL_OPC(0x0f, 0x01), MODRM(3, 3, 7) },
    [INSTR_INVD]    = { X86EMUL_OPC(0x0f, 0x08) },
    [INSTR_WBINVD]  = { X86EMUL_OPC(0x0f, 0x09) },
    [INSTR_WRMSR]   = { X86EMUL_OPC(0x0f, 0x30) },
    [INSTR_RDTSC]   = { X86EMUL_OPC(0x0f, 0x31) },
    [INSTR_RDMSR]   = { X86EMUL_OPC(0x0f, 0x32) },
    [INSTR_CPUID]   = { X86EMUL_OPC(0x0f, 0xa2) },
};

int __get_instruction_length_from_list(struct vcpu *v,
        const enum instruction_index *list, unsigned int list_count)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct hvm_emulate_ctxt ctxt;
    struct x86_emulate_state *state;
    unsigned long inst_len, j;
    unsigned int modrm_rm, modrm_reg;
    int modrm_mod;

    /*
     * In debug builds, always use x86_decode_insn() and compare with
     * hardware.
     */
#ifdef NDEBUG
    if ( (inst_len = svm_nextrip_insn_length(v)) > MAX_INST_LEN )
        gprintk(XENLOG_WARNING, "NRip reported inst_len %lu\n", inst_len);
    else if ( inst_len != 0 )
        return inst_len;

    if ( vmcb->exitcode == VMEXIT_IOIO )
        return vmcb->exitinfo2 - vmcb->rip;
#endif

    ASSERT(v == current);
    hvm_emulate_init_once(&ctxt, guest_cpu_user_regs());
    hvm_emulate_init_per_insn(&ctxt, NULL, 0);
    state = x86_decode_insn(&ctxt.ctxt, hvmemul_insn_fetch);
    if ( IS_ERR_OR_NULL(state) )
        return 0;

    inst_len = x86_insn_length(state, &ctxt.ctxt);
    modrm_mod = x86_insn_modrm(state, &modrm_rm, &modrm_reg);
    x86_emulate_free_state(state);
#ifndef NDEBUG
    if ( vmcb->exitcode == VMEXIT_IOIO )
        j = vmcb->exitinfo2 - vmcb->rip;
    else
        j = svm_nextrip_insn_length(v);
    if ( j && j != inst_len )
    {
        gprintk(XENLOG_WARNING, "insn-len[%02x]=%lu (exp %lu)\n",
                ctxt.ctxt.opcode, inst_len, j);
        return j;
    }
#endif

    for ( j = 0; j < list_count; j++ )
    {
        unsigned int instr = list[j];

        if ( instr >= ARRAY_SIZE(opc_tab) )
        {
            ASSERT_UNREACHABLE();
            break;
        }
        if ( opc_tab[instr].opcode == ctxt.ctxt.opcode )
        {
            if ( !opc_tab[instr].modrm.mod )
                return inst_len;

            if ( modrm_mod == opc_tab[instr].modrm.mod &&
                 (modrm_rm & 7) == opc_tab[instr].modrm.rm &&
                 (modrm_reg & 7) == opc_tab[instr].modrm.reg )
                return inst_len;
        }
    }

    gdprintk(XENLOG_WARNING,
             "%s: Mismatch between expected and actual instruction: "
             "eip = %lx\n",  __func__, (unsigned long)vmcb->rip);
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
