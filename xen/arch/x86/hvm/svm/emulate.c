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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>

static unsigned int is_prefix(u8 opc)
{
    switch ( opc )
    {
    case 0x66:
    case 0x67:
    case 0x2E:
    case 0x3E:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x36:
    case 0xF0:
    case 0xF3:
    case 0xF2:
    case 0x40 ... 0x4f:
        return 1;
    }
    return 0;
}

static unsigned long svm_rip2pointer(struct vcpu *v, unsigned long *limit)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long p = vmcb->cs.base + vmcb->rip;

    if ( !(vmcb->cs.attr.fields.l && hvm_long_mode_enabled(v)) )
    {
        *limit = vmcb->cs.limit;
        return (u32)p; /* mask to 32 bits */
    }
    *limit = ~0UL;
    return p;
}

static unsigned long svm_nextrip_insn_length(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( !cpu_has_svm_nrips || (vmcb->nextrip <= vmcb->rip) )
        return 0;

#ifndef NDEBUG
    switch ( vmcb->exitcode )
    {
    case VMEXIT_CR0_READ... VMEXIT_DR15_WRITE:
        /* faults due to instruction intercepts */
        /* (exitcodes 84-95) are reserved */
    case VMEXIT_IDTR_READ ... VMEXIT_TR_WRITE:
    case VMEXIT_RDTSC ... VMEXIT_MSR:
    case VMEXIT_VMRUN ...  VMEXIT_XSETBV:
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

/* First byte: Length. Following bytes: Opcode bytes. */
#define MAKE_INSTR(nm, ...) static const u8 OPCODE_##nm[] = { __VA_ARGS__ }
MAKE_INSTR(INVD,   2, 0x0f, 0x08);
MAKE_INSTR(WBINVD, 2, 0x0f, 0x09);
MAKE_INSTR(CPUID,  2, 0x0f, 0xa2);
MAKE_INSTR(RDMSR,  2, 0x0f, 0x32);
MAKE_INSTR(WRMSR,  2, 0x0f, 0x30);
MAKE_INSTR(VMCALL, 3, 0x0f, 0x01, 0xd9);
MAKE_INSTR(HLT,    1, 0xf4);
MAKE_INSTR(INT3,   1, 0xcc);
MAKE_INSTR(RDTSC,  2, 0x0f, 0x31);
MAKE_INSTR(PAUSE,  1, 0x90);
MAKE_INSTR(XSETBV, 3, 0x0f, 0x01, 0xd1);
MAKE_INSTR(VMRUN,  3, 0x0f, 0x01, 0xd8);
MAKE_INSTR(VMLOAD, 3, 0x0f, 0x01, 0xda);
MAKE_INSTR(VMSAVE, 3, 0x0f, 0x01, 0xdb);
MAKE_INSTR(STGI,   3, 0x0f, 0x01, 0xdc);
MAKE_INSTR(CLGI,   3, 0x0f, 0x01, 0xdd);
MAKE_INSTR(INVLPGA,3, 0x0f, 0x01, 0xdf);

static const u8 *const opc_bytes[INSTR_MAX_COUNT] =
{
    [INSTR_INVD]   = OPCODE_INVD,
    [INSTR_WBINVD] = OPCODE_WBINVD,
    [INSTR_CPUID]  = OPCODE_CPUID,
    [INSTR_RDMSR]  = OPCODE_RDMSR,
    [INSTR_WRMSR]  = OPCODE_WRMSR,
    [INSTR_VMCALL] = OPCODE_VMCALL,
    [INSTR_HLT]    = OPCODE_HLT,
    [INSTR_INT3]   = OPCODE_INT3,
    [INSTR_RDTSC]  = OPCODE_RDTSC,
    [INSTR_PAUSE]  = OPCODE_PAUSE,
    [INSTR_XSETBV] = OPCODE_XSETBV,
    [INSTR_VMRUN]  = OPCODE_VMRUN,
    [INSTR_VMLOAD] = OPCODE_VMLOAD,
    [INSTR_VMSAVE] = OPCODE_VMSAVE,
    [INSTR_STGI]   = OPCODE_STGI,
    [INSTR_CLGI]   = OPCODE_CLGI,
    [INSTR_INVLPGA] = OPCODE_INVLPGA,
};

static bool_t fetch(const struct vmcb_struct *vmcb, u8 *buf,
                    unsigned long addr, unsigned int len)
{
    uint32_t pfec = (vmcb_get_cpl(vmcb) == 3) ? PFEC_user_mode : 0;

    switch ( hvm_fetch_from_guest_virt(buf, addr, len, pfec) )
    {
    case HVMCOPY_okay:
        break;
    case HVMCOPY_bad_gva_to_gfn:
        /* OK just to give up; we'll have injected #PF already */
        return 0;
    default:
        /* Not OK: fetches from non-RAM pages are not supportable. */
        gdprintk(XENLOG_WARNING, "Bad instruction fetch at %#lx (%#lx)\n",
                 vmcb->rip, addr);
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return 0;
    }
    return 1;
}

int __get_instruction_length_from_list(struct vcpu *v,
        const enum instruction_index *list, unsigned int list_count)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int i, j, inst_len = 0;
    enum instruction_index instr = 0;
    u8 buf[MAX_INST_LEN];
    const u8 *opcode = NULL;
    unsigned long fetch_addr, fetch_limit;
    unsigned int fetch_len, max_len;

    if ( (inst_len = svm_nextrip_insn_length(v)) != 0 )
        return inst_len;

    if ( vmcb->exitcode == VMEXIT_IOIO )
        return vmcb->exitinfo2 - vmcb->rip;

    /* Fetch up to the next page break; we'll fetch from the next page
     * later if we have to. */
    fetch_addr = svm_rip2pointer(v, &fetch_limit);
    if ( vmcb->rip > fetch_limit )
        return 0;
    max_len = min(fetch_limit - vmcb->rip + 1, MAX_INST_LEN + 0UL);
    fetch_len = min_t(unsigned int, max_len,
                      PAGE_SIZE - (fetch_addr & ~PAGE_MASK));
    if ( !fetch(vmcb, buf, fetch_addr, fetch_len) )
        return 0;

    while ( (inst_len < max_len) && is_prefix(buf[inst_len]) )
    {
        inst_len++;
        if ( inst_len >= fetch_len )
        {
            if ( !fetch(vmcb, buf + fetch_len, fetch_addr + fetch_len,
                        max_len - fetch_len) )
                return 0;
            fetch_len = max_len;
        }
    }

    for ( j = 0; j < list_count; j++ )
    {
        instr = list[j];
        opcode = opc_bytes[instr];

        for ( i = 0; (i < opcode[0]) && ((inst_len + i) < max_len); i++ )
        {
            if ( (inst_len + i) >= fetch_len ) 
            {
                if ( !fetch(vmcb, buf + fetch_len, fetch_addr + fetch_len,
                            max_len - fetch_len) )
                    return 0;
                fetch_len = max_len;
            }

            if ( buf[inst_len+i] != opcode[i+1] )
                goto mismatch;
        }
        goto done;
    mismatch: ;
    }

    gdprintk(XENLOG_WARNING,
             "%s: Mismatch between expected and actual instruction bytes: "
             "eip = %lx\n",  __func__, (unsigned long)vmcb->rip);
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return 0;

 done:
    inst_len += opcode[0];
    ASSERT(inst_len <= max_len);
    return inst_len;
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
