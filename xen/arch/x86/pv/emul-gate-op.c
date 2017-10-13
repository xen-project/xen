/******************************************************************************
 * arch/x86/pv/emul-gate-op.c
 *
 * Emulate gate op for PV guests
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/errno.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <xen/spinlock.h>
#include <xen/trace.h>

#include <asm/apic.h>
#include <asm/debugreg.h>
#include <asm/hpet.h>
#include <asm/hypercall.h>
#include <asm/mc146818rtc.h>
#include <asm/p2m.h>
#include <asm/pv/traps.h>
#include <asm/shared.h>
#include <asm/traps.h>
#include <asm/x86_emulate.h>

#include <xsm/xsm.h>

#include "emulate.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

static int read_gate_descriptor(unsigned int gate_sel,
                                const struct vcpu *v,
                                unsigned int *sel,
                                unsigned long *off,
                                unsigned int *ar)
{
    struct desc_struct desc;
    const struct desc_struct *pdesc = gdt_ldt_desc_ptr(gate_sel);

    if ( (gate_sel < 4) ||
         ((gate_sel >= FIRST_RESERVED_GDT_BYTE) && !(gate_sel & 4)) ||
         __get_user(desc, pdesc) )
        return 0;

    *sel = (desc.a >> 16) & 0x0000fffc;
    *off = (desc.a & 0x0000ffff) | (desc.b & 0xffff0000);
    *ar = desc.b & 0x0000ffff;

    /*
     * check_descriptor() clears the DPL field and stores the
     * guest requested DPL in the selector's RPL field.
     */
    if ( *ar & _SEGMENT_DPL )
        return 0;
    *ar |= (desc.a >> (16 - 13)) & _SEGMENT_DPL;

    if ( !is_pv_32bit_vcpu(v) )
    {
        if ( (*ar & 0x1f00) != 0x0c00 ||
             (gate_sel >= FIRST_RESERVED_GDT_BYTE - 8 && !(gate_sel & 4)) ||
             __get_user(desc, pdesc + 1) ||
             (desc.b & 0x1f00) )
            return 0;

        *off |= (unsigned long)desc.a << 32;
        return 1;
    }

    switch ( *ar & 0x1f00 )
    {
    case 0x0400:
        *off &= 0xffff;
        break;
    case 0x0c00:
        break;
    default:
        return 0;
    }

    return 1;
}

static inline bool check_stack_limit(unsigned int ar, unsigned int limit,
                                     unsigned int esp, unsigned int decr)
{
    return (((esp - decr) < (esp - 1)) &&
            (!(ar & _SEGMENT_EC) ? (esp - 1) <= limit : (esp - decr) > limit));
}

struct gate_op_ctxt {
    struct x86_emulate_ctxt ctxt;
    struct {
        unsigned long base, limit;
    } cs;
    bool insn_fetch;
};

static int read_mem(enum x86_segment seg, unsigned long offset, void *p_data,
                    unsigned int bytes, struct x86_emulate_ctxt *ctxt)
{
    const struct gate_op_ctxt *goc =
        container_of(ctxt, struct gate_op_ctxt, ctxt);
    unsigned int rc = bytes, sel = 0;
    unsigned long addr = offset, limit = 0;

    switch ( seg )
    {
    case x86_seg_cs:
        addr += goc->cs.base;
        limit = goc->cs.limit;
        break;
    case x86_seg_ds:
        sel = read_sreg(ds);
        break;
    case x86_seg_es:
        sel = read_sreg(es);
        break;
    case x86_seg_fs:
        sel = read_sreg(fs);
        break;
    case x86_seg_gs:
        sel = read_sreg(gs);
        break;
    case x86_seg_ss:
        sel = ctxt->regs->ss;
        break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }
    if ( sel )
    {
        unsigned int ar;

        ASSERT(!goc->insn_fetch);
        if ( !pv_emul_read_descriptor(sel, current, &addr, &limit, &ar, 0) ||
             !(ar & _SEGMENT_S) ||
             !(ar & _SEGMENT_P) ||
             ((ar & _SEGMENT_CODE) && !(ar & _SEGMENT_WR)) )
            return X86EMUL_UNHANDLEABLE;
        addr += offset;
    }
    else if ( seg != x86_seg_cs )
        return X86EMUL_UNHANDLEABLE;

    /* We don't mean to emulate any branches. */
    if ( limit < bytes - 1 || offset > limit - bytes + 1 )
        return X86EMUL_UNHANDLEABLE;

    addr = (uint32_t)addr;

    if ( (rc = __copy_from_user(p_data, (void *)addr, bytes)) )
    {
        /*
         * TODO: This should report PFEC_insn_fetch when goc->insn_fetch &&
         * cpu_has_nx, but we'd then need a "fetch" variant of
         * __copy_from_user() respecting NX, SMEP, and protection keys.
         */
        x86_emul_pagefault(0, addr + bytes - rc, ctxt);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

void pv_emulate_gate_op(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    unsigned int sel, ar, dpl, nparm, insn_len;
    struct gate_op_ctxt ctxt = { .ctxt.regs = regs, .insn_fetch = true };
    struct x86_emulate_state *state;
    unsigned long off, base, limit;
    uint16_t opnd_sel = 0;
    int jump = -1, rc = X86EMUL_OKAY;

    /* Check whether this fault is due to the use of a call gate. */
    if ( !read_gate_descriptor(regs->error_code, v, &sel, &off, &ar) ||
         (((ar >> 13) & 3) < (regs->cs & 3)) ||
         ((ar & _SEGMENT_TYPE) != 0xc00) )
    {
        pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
        return;
    }
    if ( !(ar & _SEGMENT_P) )
    {
        pv_inject_hw_exception(TRAP_no_segment, regs->error_code);
        return;
    }
    dpl = (ar >> 13) & 3;
    nparm = ar & 0x1f;

    /*
     * Decode instruction (and perhaps operand) to determine RPL,
     * whether this is a jump or a call, and the call return offset.
     */
    if ( !pv_emul_read_descriptor(regs->cs, v, &ctxt.cs.base, &ctxt.cs.limit,
                                  &ar, 0) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         !(ar & _SEGMENT_CODE) )
    {
        pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
        return;
    }

    ctxt.ctxt.addr_size = ar & _SEGMENT_DB ? 32 : 16;
    /* Leave zero in ctxt.ctxt.sp_size, as it's not needed for decoding. */
    state = x86_decode_insn(&ctxt.ctxt, read_mem);
    ctxt.insn_fetch = false;
    if ( IS_ERR_OR_NULL(state) )
    {
        if ( PTR_ERR(state) == -X86EMUL_EXCEPTION )
            pv_inject_event(&ctxt.ctxt.event);
        else
            pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
        return;
    }

    switch ( ctxt.ctxt.opcode )
    {
        unsigned int modrm_345;

    case 0xea:
        ++jump;
        /* fall through */
    case 0x9a:
        ++jump;
        opnd_sel = x86_insn_immediate(state, 1);
        break;
    case 0xff:
        if ( x86_insn_modrm(state, NULL, &modrm_345) >= 3 )
            break;
        switch ( modrm_345 & 7 )
        {
            enum x86_segment seg;

        case 5:
            ++jump;
            /* fall through */
        case 3:
            ++jump;
            base = x86_insn_operand_ea(state, &seg);
            rc = read_mem(seg, base + (x86_insn_opsize(state) >> 3),
                          &opnd_sel, sizeof(opnd_sel), &ctxt.ctxt);
            break;
        }
        break;
    }

    insn_len = x86_insn_length(state, &ctxt.ctxt);
    x86_emulate_free_state(state);

    if ( rc == X86EMUL_EXCEPTION )
    {
        pv_inject_event(&ctxt.ctxt.event);
        return;
    }

    if ( rc != X86EMUL_OKAY ||
         jump < 0 ||
         (opnd_sel & ~3) != regs->error_code ||
         dpl < (opnd_sel & 3) )
    {
        pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
        return;
    }

    if ( !pv_emul_read_descriptor(sel, v, &base, &limit, &ar, 0) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_CODE) ||
         (!jump || (ar & _SEGMENT_EC) ?
          ((ar >> 13) & 3) > (regs->cs & 3) :
          ((ar >> 13) & 3) != (regs->cs & 3)) )
    {
        pv_inject_hw_exception(TRAP_gp_fault, sel);
        return;
    }
    if ( !(ar & _SEGMENT_P) )
    {
        pv_inject_hw_exception(TRAP_no_segment, sel);
        return;
    }
    if ( off > limit )
    {
        pv_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    if ( !jump )
    {
        unsigned int ss, esp, *stkp;
        int rc;
#define push(item) do \
        { \
            --stkp; \
            esp -= 4; \
            rc = __put_user(item, stkp); \
            if ( rc ) \
            { \
                pv_inject_page_fault(PFEC_write_access, \
                                     (unsigned long)(stkp + 1) - rc); \
                return; \
            } \
        } while ( 0 )

        if ( ((ar >> 13) & 3) < (regs->cs & 3) )
        {
            sel |= (ar >> 13) & 3;
            /* Inner stack known only for kernel ring. */
            if ( (sel & 3) != GUEST_KERNEL_RPL(v->domain) )
            {
                pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
                return;
            }
            esp = v->arch.pv_vcpu.kernel_sp;
            ss = v->arch.pv_vcpu.kernel_ss;
            if ( (ss & 3) != (sel & 3) ||
                 !pv_emul_read_descriptor(ss, v, &base, &limit, &ar, 0) ||
                 ((ar >> 13) & 3) != (sel & 3) ||
                 !(ar & _SEGMENT_S) ||
                 (ar & _SEGMENT_CODE) ||
                 !(ar & _SEGMENT_WR) )
            {
                pv_inject_hw_exception(TRAP_invalid_tss, ss & ~3);
                return;
            }
            if ( !(ar & _SEGMENT_P) ||
                 !check_stack_limit(ar, limit, esp, (4 + nparm) * 4) )
            {
                pv_inject_hw_exception(TRAP_stack_error, ss & ~3);
                return;
            }
            stkp = (unsigned int *)(unsigned long)((unsigned int)base + esp);
            if ( !compat_access_ok(stkp - 4 - nparm, 16 + nparm * 4) )
            {
                pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
                return;
            }
            push(regs->ss);
            push(regs->rsp);
            if ( nparm )
            {
                const unsigned int *ustkp;

                if ( !pv_emul_read_descriptor(regs->ss, v, &base,
                                              &limit, &ar, 0) ||
                     ((ar >> 13) & 3) != (regs->cs & 3) ||
                     !(ar & _SEGMENT_S) ||
                     (ar & _SEGMENT_CODE) ||
                     !(ar & _SEGMENT_WR) ||
                     !check_stack_limit(ar, limit, esp + nparm * 4, nparm * 4) )
                    return pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
                ustkp = (unsigned int *)(unsigned long)
                        ((unsigned int)base + regs->esp + nparm * 4);
                if ( !compat_access_ok(ustkp - nparm, 0 + nparm * 4) )
                {
                    pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
                    return;
                }
                do
                {
                    unsigned int parm;

                    --ustkp;
                    rc = __get_user(parm, ustkp);
                    if ( rc )
                    {
                        pv_inject_page_fault(0, (unsigned long)(ustkp + 1) - rc);
                        return;
                    }
                    push(parm);
                } while ( --nparm );
            }
        }
        else
        {
            sel |= (regs->cs & 3);
            esp = regs->rsp;
            ss = regs->ss;
            if ( !pv_emul_read_descriptor(ss, v, &base, &limit, &ar, 0) ||
                 ((ar >> 13) & 3) != (sel & 3) )
            {
                pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
                return;
            }
            if ( !check_stack_limit(ar, limit, esp, 2 * 4) )
            {
                pv_inject_hw_exception(TRAP_stack_error, 0);
                return;
            }
            stkp = (unsigned int *)(unsigned long)((unsigned int)base + esp);
            if ( !compat_access_ok(stkp - 2, 2 * 4) )
            {
                pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
                return;
            }
        }
        push(regs->cs);
        push(regs->rip + insn_len);
#undef push
        regs->rsp = esp;
        regs->ss = ss;
    }
    else
        sel |= (regs->cs & 3);

    regs->cs = sel;
    pv_emul_instruction_done(regs, off);
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
