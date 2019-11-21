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
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

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

/*
 * Early processors with SVM didn't have the NextRIP feature, meaning that
 * when we take a fault-style VMExit, we have to decode the instruction stream
 * to calculate how many bytes to move %rip forwards by.
 *
 * In debug builds, always compare the hardware reported instruction length
 * (if available) with the result from x86_decode_insn().
 */
unsigned int svm_get_insn_len(struct vcpu *v, unsigned int instr_enc)
{
    struct hvm_emulate_ctxt ctxt;
    struct x86_emulate_state *state;
    unsigned long nrip_len, emul_len;
    unsigned int instr_opcode, instr_modrm;
    unsigned int modrm_rm, modrm_reg;
    int modrm_mod;

    nrip_len = svm_nextrip_insn_length(v);

#ifdef NDEBUG
    if ( nrip_len > MAX_INST_LEN )
        gprintk(XENLOG_WARNING, "NRip reported inst_len %lu\n", nrip_len);
    else if ( nrip_len != 0 )
        return nrip_len;
#endif

    ASSERT(v == current);
    hvm_emulate_init_once(&ctxt, NULL, guest_cpu_user_regs());
    hvm_emulate_init_per_insn(&ctxt, NULL, 0);
    state = x86_decode_insn(&ctxt.ctxt, hvmemul_insn_fetch);
    if ( IS_ERR_OR_NULL(state) )
        return 0;

    emul_len = x86_insn_length(state, &ctxt.ctxt);
    modrm_mod = x86_insn_modrm(state, &modrm_rm, &modrm_reg);
    x86_emulate_free_state(state);

    /* Extract components from instr_enc. */
    instr_modrm  = instr_enc & 0xff;
    instr_opcode = instr_enc >> 8;

    if ( instr_opcode == ctxt.ctxt.opcode )
    {
        if ( !instr_modrm )
            return emul_len;

        if ( modrm_mod       == MASK_EXTR(instr_modrm, 0300) &&
             (modrm_reg & 7) == MASK_EXTR(instr_modrm, 0070) &&
             (modrm_rm  & 7) == MASK_EXTR(instr_modrm, 0007) )
            return emul_len;
    }

    printk(XENLOG_G_WARNING
           "Insn mismatch: Expected opcode %#x, modrm %#x, got nrip_len %lu, emul_len %lu\n",
           instr_opcode, instr_modrm, nrip_len, emul_len);
    hvm_dump_emulation_state(XENLOG_G_WARNING, "SVM Insn len",
                             &ctxt, X86EMUL_UNHANDLEABLE);

    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return 0;
}

/*
 * TASK_SWITCH vmexits never provide an instruction length.  We must always
 * decode under %rip to find the answer.
 */
unsigned int svm_get_task_switch_insn_len(void)
{
    struct hvm_emulate_ctxt ctxt;
    struct x86_emulate_state *state;
    unsigned int emul_len, modrm_reg;

    hvm_emulate_init_once(&ctxt, NULL, guest_cpu_user_regs());
    hvm_emulate_init_per_insn(&ctxt, NULL, 0);
    state = x86_decode_insn(&ctxt.ctxt, hvmemul_insn_fetch);
    if ( IS_ERR_OR_NULL(state) )
        return 0;

    emul_len = x86_insn_length(state, &ctxt.ctxt);

    /*
     * Check for an instruction which can cause a task switch.  Any far
     * jmp/call/ret, any software interrupt/exception with trap semantics
     * (except icebp - handled specially), and iret.
     */
    switch ( ctxt.ctxt.opcode )
    {
    case 0xff: /* Grp 5 */
        /* call / jmp (far, absolute indirect) */
        if ( (unsigned int)x86_insn_modrm(state, NULL, &modrm_reg) >= 3 ||
             (modrm_reg != 3 && modrm_reg != 5) )
        {
    default:
            printk(XENLOG_G_WARNING "Bad instruction for task switch\n");
            hvm_dump_emulation_state(XENLOG_G_WARNING, "SVM Insn len",
                                     &ctxt, X86EMUL_UNHANDLEABLE);
            emul_len = 0;
            break;
        }
        /* Fallthrough */
    case 0x9a: /* call (far, absolute) */
    case 0xca: /* ret imm16 (far) */
    case 0xcb: /* ret (far) */
    case 0xcc: /* int3 */
    case 0xcd: /* int imm8 */
    case 0xce: /* into */
    case 0xcf: /* iret */
    case 0xea: /* jmp (far, absolute) */
        break;
    }

    x86_emulate_free_state(state);

    return emul_len;
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
