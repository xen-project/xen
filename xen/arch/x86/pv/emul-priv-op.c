/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/pv/emul-priv-op.c
 *
 * Emulate privileged instructions for PV guests
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 */

#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/iocap.h>

#include <asm/amd.h>
#include <asm/debugreg.h>
#include <asm/endbr.h>
#include <asm/hpet.h>
#include <asm/mc146818rtc.h>
#include <asm/pv/domain.h>
#include <asm/pv/trace.h>
#include <asm/shared.h>

#include <xsm/xsm.h>

#include "../x86_64/mmconfig.h"
#include "emulate.h"
#include "mm.h"

struct priv_op_ctxt {
    struct x86_emulate_ctxt ctxt;
    struct {
        unsigned long base, limit;
    } cs;
    char *io_emul_stub;
    unsigned int bpmatch;
};

/* I/O emulation helpers.  Use non-standard calling conventions. */
void nocall load_guest_gprs(struct cpu_user_regs *);
void nocall save_guest_gprs(void);

typedef void io_emul_stub_t(struct cpu_user_regs *);

static io_emul_stub_t *io_emul_stub_setup(struct priv_op_ctxt *ctxt, u8 opcode,
                                          unsigned int port, unsigned int bytes)
{
    /*
     * Construct a stub for IN/OUT emulation.
     *
     * Some platform drivers communicate with the SMM handler using GPRs as a
     * mailbox.  Therefore, we must perform the emulation with the hardware
     * domain's registers in view.
     *
     * We write a stub of the following form, using the guest load/save
     * helpers (non-standard ABI), and one of several possible stubs
     * performing the real I/O.
     */
    static const char prologue[] = {
        0x53,       /* push %rbx */
        0x55,       /* push %rbp */
        0x41, 0x54, /* push %r12 */
        0x41, 0x55, /* push %r13 */
        0x41, 0x56, /* push %r14 */
        0x41, 0x57, /* push %r15 */
        0x57,       /* push %rdi (param for save_guest_gprs) */
    };              /* call load_guest_gprs */
                    /* <I/O stub> */
                    /* call save_guest_gprs */
    static const char epilogue[] = {
        0x5f,       /* pop %rdi  */
        0x41, 0x5f, /* pop %r15  */
        0x41, 0x5e, /* pop %r14  */
        0x41, 0x5d, /* pop %r13  */
        0x41, 0x5c, /* pop %r12  */
        0x5d,       /* pop %rbp  */
        0x5b,       /* pop %rbx  */
        0xc3,       /* ret       */
    };

    const struct stubs *this_stubs = &this_cpu(stubs);
    const void *stub_va = (void *)this_stubs->addr + STUB_BUF_SIZE / 2;
    unsigned int quirk_bytes = 0;
    char *p;

    /* Helpers - Read outer scope but only modify p. */
#define APPEND_BUFF(b) ({ memcpy(p, b, sizeof(b)); p += sizeof(b); })
#define APPEND_CALL(f)                                                  \
    ({                                                                  \
        long disp = (void *)(f) - (stub_va + (p - ctxt->io_emul_stub) + 5); \
        BUG_ON((int32_t)disp != disp);                                  \
        *p++ = 0xe8;                                                    \
        *(int32_t *)p = disp; p += 4;                                   \
    })

    if ( !ctxt->io_emul_stub )
        ctxt->io_emul_stub =
            map_domain_page(_mfn(this_stubs->mfn)) + PAGE_OFFSET(stub_va);

    p = ctxt->io_emul_stub;

    if ( cpu_has_xen_ibt )
    {
        place_endbr64(p);
        p += 4;
    }

    APPEND_BUFF(prologue);
    APPEND_CALL(load_guest_gprs);

    /* Some platforms might need to quirk the stub for specific inputs. */
    if ( unlikely(ioemul_handle_quirk) )
    {
        quirk_bytes = ioemul_handle_proliant_quirk(opcode, p, ctxt->ctxt.regs);
        p += quirk_bytes;
    }

    /* Default I/O stub. */
    if ( likely(!quirk_bytes) )
    {
        *p++ = (bytes != 2) ? 0x90 : 0x66;  /* data16 or nop */
        *p++ = opcode;                      /* <opcode>      */
        *p++ = !(opcode & 8) ? port : 0x90; /* imm8 or nop   */
    }

    APPEND_CALL(save_guest_gprs);
    APPEND_BUFF(epilogue);

    /* Build-time best effort attempt to catch problems. */
    BUILD_BUG_ON(STUB_BUF_SIZE / 2 <
                 (sizeof(prologue) + sizeof(epilogue) + 10 /* 2x call */ +
                  MAX(3 /* default stub */, IOEMUL_QUIRK_STUB_BYTES)));
    /* Runtime confirmation that we haven't clobbered an adjacent stub. */
    BUG_ON(STUB_BUF_SIZE / 2 < (p - ctxt->io_emul_stub));

    block_speculation(); /* SCSB */

    /* Handy function-typed pointer to the stub. */
    return stub_va;

#undef APPEND_CALL
#undef APPEND_BUFF
}


/* Perform IOPL check between the vcpu's shadowed IOPL, and the assumed cpl. */
static bool iopl_ok(const struct vcpu *v, const struct cpu_user_regs *regs)
{
    unsigned int cpl = guest_kernel_mode(v, regs) ?
        (VM_ASSIST(v->domain, architectural_iopl) ? 0 : 1) : 3;

    ASSERT((v->arch.pv.iopl & ~X86_EFLAGS_IOPL) == 0);

    return IOPL(cpl) <= v->arch.pv.iopl;
}

/* Has the guest requested sufficient permission for this I/O access? */
static int guest_io_okay(unsigned int port, unsigned int bytes,
                         struct x86_emulate_ctxt *ctxt)
{
    const struct cpu_user_regs *regs = ctxt->regs;
    struct vcpu *v = current;
    /* If in user mode, switch to kernel mode just to read I/O bitmap. */
    const bool user_mode = !(v->arch.flags & TF_kernel_mode);

    if ( iopl_ok(v, regs) )
        return X86EMUL_OKAY;

    /*
     * When @iobmp_nr is non-zero, Xen, like real CPUs and the TSS IOPB,
     * always reads 2 bytes from @iobmp, which might be one byte @iobmp_nr.
     */
    if ( (port + bytes) <= v->arch.pv.iobmp_nr )
    {
        const void *__user addr = v->arch.pv.iobmp.p + (port >> 3);
        uint16_t mask;
        int rc;

        /* Grab permission bytes from guest space. */
        if ( user_mode )
            toggle_guest_pt(v);

        rc = __copy_from_guest_pv(&mask, addr, 2);

        if ( user_mode )
            toggle_guest_pt(v);

        if ( rc )
        {
            x86_emul_pagefault(0, (unsigned long)addr + bytes - rc, ctxt);
            return X86EMUL_EXCEPTION;
        }

        if ( (mask & (((1 << bytes) - 1) << (port & 7))) == 0 )
            return X86EMUL_OKAY;
    }

    x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);

    return X86EMUL_EXCEPTION;
}

/* Has the administrator granted sufficient permission for this I/O access? */
static bool admin_io_okay(unsigned int port, unsigned int bytes,
                          const struct domain *d)
{
    /*
     * Port 0xcf8 (CONFIG_ADDRESS) is only visible for DWORD accesses.
     * We never permit direct access to that register.
     */
    if ( (port == 0xcf8) && (bytes == 4) )
        return false;

    /* We also never permit direct access to the RTC/CMOS registers. */
    if ( is_cmos_port(port, bytes, d) )
        return false;

    return ioports_access_permitted(d, port, port + bytes - 1);
}

static bool pci_cfg_ok(struct domain *currd, unsigned int start,
                       unsigned int size, uint32_t *write)
{
    uint32_t machine_bdf;

    if ( !is_hardware_domain(currd) )
        return false;

    if ( !CF8_ENABLED(currd->arch.pci_cf8) )
        return true;

    machine_bdf = CF8_BDF(currd->arch.pci_cf8);
    if ( write )
    {
        const unsigned long *ro_map = pci_get_ro_map(0);

        if ( ro_map && test_bit(machine_bdf, ro_map) )
            return false;
    }
    start |= CF8_ADDR_LO(currd->arch.pci_cf8);
    /* AMD extended configuration space access? */
    if ( CF8_ADDR_HI(currd->arch.pci_cf8) &&
         boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
         boot_cpu_data.x86 >= 0x10 && boot_cpu_data.x86 < 0x17 )
    {
        uint64_t msr_val;

        if ( rdmsr_safe(MSR_AMD64_NB_CFG, msr_val) )
            return false;
        if ( msr_val & (1ULL << AMD64_NB_CFG_CF8_EXT_ENABLE_BIT) )
            start |= CF8_ADDR_HI(currd->arch.pci_cf8);
    }

    return !write ?
           xsm_pci_config_permission(XSM_HOOK, currd, machine_bdf,
                                     start, start + size - 1, 0) == 0 :
           pci_conf_write_intercept(0, machine_bdf, start, size, write) >= 0;
}

static uint32_t guest_io_read(unsigned int port, unsigned int bytes,
                              struct domain *currd)
{
    uint32_t data = 0;
    unsigned int shift = 0;

    if ( admin_io_okay(port, bytes, currd) )
    {
        switch ( bytes )
        {
        case 1: return inb(port);
        case 2: return inw(port);
        case 4: return inl(port);
        }
    }

    while ( bytes != 0 )
    {
        unsigned int size = 1;
        uint32_t sub_data = ~0;

        if ( (port == 0x42) || (port == 0x43) || (port == 0x61) )
        {
            sub_data = pv_pit_handler(port, 0, 0);
        }
        else if ( is_cmos_port(port, 1, currd) )
        {
            sub_data = rtc_guest_read(port);
        }
        else if ( (port == 0xcf8) && (bytes == 4) )
        {
            size = 4;
            sub_data = currd->arch.pci_cf8;
        }
        else if ( (port & 0xfffc) == 0xcfc )
        {
            size = min(bytes, 4 - (port & 3));
            if ( size == 3 )
                size = 2;
            if ( pci_cfg_ok(currd, port & 3, size, NULL) )
                sub_data = pci_conf_read(currd->arch.pci_cf8, port & 3, size);
        }
        else if ( ioports_access_permitted(currd, port, port) )
        {
            if ( bytes > 1 && !(port & 1) &&
                 ioports_access_permitted(currd, port, port + 1) )
            {
                sub_data = inw(port);
                size = 2;
            }
            else
                sub_data = inb(port);
        }

        if ( size == 4 )
            return sub_data;

        data |= (sub_data & ((1u << (size * 8)) - 1)) << shift;
        shift += size * 8;
        port += size;
        bytes -= size;
    }

    return data;
}

static unsigned int check_guest_io_breakpoint(struct vcpu *v,
                                              unsigned int port,
                                              unsigned int len)
{
    unsigned int i, match = 0;

    if ( !v->arch.pv.dr7_emul || !(v->arch.pv.ctrlreg[4] & X86_CR4_DE) )
        return 0;

    for ( i = 0; i < 4; i++ )
    {
        unsigned long start;
        unsigned int width;

        if ( !(v->arch.pv.dr7_emul & (3 << (i * DR_ENABLE_SIZE))) )
            continue;

        width = x86_bp_width(v->arch.dr7, i);
        start = v->arch.dr[i] & ~(width - 1UL);

        if ( (start < (port + len)) && ((start + width) > port) )
            match |= 1u << i;
    }

    return match;
}

static int cf_check read_io(
    unsigned int port, unsigned int bytes, unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    struct priv_op_ctxt *poc = container_of(ctxt, struct priv_op_ctxt, ctxt);
    struct vcpu *curr = current;
    struct domain *currd = current->domain;
    int rc;

    /* INS must not come here. */
    ASSERT((ctxt->opcode & ~9) == 0xe4);

    rc = guest_io_okay(port, bytes, ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    poc->bpmatch = check_guest_io_breakpoint(curr, port, bytes);

    if ( admin_io_okay(port, bytes, currd) )
    {
        io_emul_stub_t *io_emul =
            io_emul_stub_setup(poc, ctxt->opcode, port, bytes);

        io_emul(ctxt->regs);
        return X86EMUL_DONE;
    }

    *val = guest_io_read(port, bytes, currd);

    return X86EMUL_OKAY;
}

static void _guest_io_write(unsigned int port, unsigned int bytes,
                            uint32_t data)
{
    switch ( bytes )
    {
    case 1:
        outb(data, port);
        if ( amd_acpi_c1e_quirk )
            amd_check_disable_c1e(port, data);
        break;

    case 2:
        outw(data, port);
        break;

    case 4:
        outl(data, port);
        break;

    default:
        ASSERT_UNREACHABLE();
    }
}

static void guest_io_write(unsigned int port, unsigned int bytes,
                           uint32_t data, struct domain *currd)
{
    if ( admin_io_okay(port, bytes, currd) )
    {
        _guest_io_write(port, bytes, data);
        return;
    }

    while ( bytes != 0 )
    {
        unsigned int size = 1;

        if ( (port == 0x42) || (port == 0x43) || (port == 0x61) )
        {
            pv_pit_handler(port, (uint8_t)data, 1);
        }
        else if ( is_cmos_port(port, 1, currd) )
        {
            rtc_guest_write(port, data);
        }
        else if ( (port == 0xcf8) && (bytes == 4) )
        {
            size = 4;
            currd->arch.pci_cf8 = data;
        }
        else if ( (port & 0xfffc) == 0xcfc )
        {
            size = min(bytes, 4 - (port & 3));
            if ( size == 3 )
                size = 2;
            if ( pci_cfg_ok(currd, port & 3, size, &data) )
                pci_conf_write(currd->arch.pci_cf8, port & 3, size, data);
        }
        else if ( ioports_access_permitted(currd, port, port) )
        {
            if ( bytes > 1 && !(port & 1) &&
                 ioports_access_permitted(currd, port, port + 1) )
                size = 2;
            _guest_io_write(port, size, data);
        }

        if ( size == 4 )
            return;

        port += size;
        bytes -= size;
        data >>= size * 8;
    }
}

static int cf_check write_io(
    unsigned int port, unsigned int bytes, unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    struct priv_op_ctxt *poc = container_of(ctxt, struct priv_op_ctxt, ctxt);
    struct vcpu *curr = current;
    struct domain *currd = current->domain;
    int rc;

    /* OUTS must not come here. */
    ASSERT((ctxt->opcode & ~9) == 0xe6);

    rc = guest_io_okay(port, bytes, ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    poc->bpmatch = check_guest_io_breakpoint(curr, port, bytes);

    if ( admin_io_okay(port, bytes, currd) )
    {
        io_emul_stub_t *io_emul =
            io_emul_stub_setup(poc, ctxt->opcode, port, bytes);

        io_emul(ctxt->regs);
        if ( (bytes == 1) && amd_acpi_c1e_quirk )
            amd_check_disable_c1e(port, val);
        return X86EMUL_DONE;
    }

    guest_io_write(port, bytes, val, currd);

    return X86EMUL_OKAY;
}

static int cf_check read_segment(
    enum x86_segment seg, struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    /* Check if this is an attempt to access the I/O bitmap. */
    if ( seg == x86_seg_tr )
    {
        switch ( ctxt->opcode )
        {
        case 0x6c ... 0x6f: /* ins / outs */
        case 0xe4 ... 0xe7: /* in / out (immediate port) */
        case 0xec ... 0xef: /* in / out (port in %dx) */
            /* Defer the check to priv_op_{read,write}_io(). */
            return X86EMUL_DONE;
        }
    }

    if ( ctxt->addr_size < 64 )
    {
        unsigned long limit;
        unsigned int sel, ar;

        switch ( seg )
        {
        case x86_seg_cs: sel = ctxt->regs->cs; break;
        case x86_seg_ds: sel = read_sreg(ds);  break;
        case x86_seg_es: sel = read_sreg(es);  break;
        case x86_seg_fs: sel = read_sreg(fs);  break;
        case x86_seg_gs: sel = read_sreg(gs);  break;
        case x86_seg_ss: sel = ctxt->regs->ss; break;
        default: return X86EMUL_UNHANDLEABLE;
        }

        if ( !pv_emul_read_descriptor(sel, current, &reg->base,
                                      &limit, &ar, 0) )
            return X86EMUL_UNHANDLEABLE;

        reg->limit = limit;
        reg->attr = ar >> 8;
    }
    else
    {
        switch ( seg )
        {
        default:
            if ( !is_x86_user_segment(seg) )
                return X86EMUL_UNHANDLEABLE;
            reg->base = 0;
            break;
        case x86_seg_fs:
            reg->base = read_fs_base();
            break;
        case x86_seg_gs:
            reg->base = read_gs_base();
            break;
        }

        reg->limit = ~0U;

        reg->attr = 0;
        reg->type = _SEGMENT_WR >> 8;
        if ( seg == x86_seg_cs )
        {
            reg->type |= _SEGMENT_CODE >> 8;
            reg->l = 1;
        }
        else
            reg->db = 1;
        reg->s   = 1;
        reg->dpl = 3;
        reg->p   = 1;
        reg->g   = 1;
    }

    /*
     * For x86_emulate.c's mode_ring0() to work, fake a DPL of zero.
     * Also do this for consistency for non-conforming code segments.
     */
    if ( (seg == x86_seg_ss ||
          (seg == x86_seg_cs &&
           !(reg->type & (_SEGMENT_EC >> 8)))) &&
         guest_kernel_mode(current, ctxt->regs) )
        reg->dpl = 0;

    return X86EMUL_OKAY;
}

static int pv_emul_virt_to_linear(unsigned long base, unsigned long offset,
                                  unsigned int bytes, unsigned long limit,
                                  enum x86_segment seg,
                                  struct x86_emulate_ctxt *ctxt,
                                  unsigned long *addr)
{
    int rc = X86EMUL_OKAY;

    *addr = base + offset;

    if ( ctxt->addr_size < 64 )
    {
        if ( limit < bytes - 1 || offset > limit - bytes + 1 )
            rc = X86EMUL_EXCEPTION;
        *addr = (uint32_t)*addr;
    }
    else if ( !__addr_ok(*addr) )
        rc = X86EMUL_EXCEPTION;

    if ( unlikely(rc == X86EMUL_EXCEPTION) )
        x86_emul_hw_exception(seg != x86_seg_ss ? X86_EXC_GP : X86_EXC_SS,
                              0, ctxt);

    return rc;
}

static int cf_check rep_ins(
    uint16_t port, enum x86_segment seg, unsigned long offset,
    unsigned int bytes_per_rep, unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct priv_op_ctxt *poc = container_of(ctxt, struct priv_op_ctxt, ctxt);
    struct vcpu *curr = current;
    struct domain *currd = current->domain;
    unsigned long goal = *reps;
    struct segment_register sreg;
    int rc;

    ASSERT(seg == x86_seg_es);

    *reps = 0;

    rc = guest_io_okay(port, bytes_per_rep, ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    rc = read_segment(x86_seg_es, &sreg, ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( !sreg.p )
        return X86EMUL_UNHANDLEABLE;
    if ( !sreg.s ||
         (sreg.type & (_SEGMENT_CODE >> 8)) ||
         !(sreg.type & (_SEGMENT_WR >> 8)) )
    {
        x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }

    poc->bpmatch = check_guest_io_breakpoint(curr, port, bytes_per_rep);

    while ( *reps < goal )
    {
        unsigned int data = guest_io_read(port, bytes_per_rep, currd);
        unsigned long addr;

        rc = pv_emul_virt_to_linear(sreg.base, offset, bytes_per_rep,
                                    sreg.limit, x86_seg_es, ctxt, &addr);
        if ( rc != X86EMUL_OKAY )
            return rc;

        if ( (rc = __copy_to_guest_pv((void __user *)addr, &data,
                                      bytes_per_rep)) != 0 )
        {
            x86_emul_pagefault(PFEC_write_access,
                               addr + bytes_per_rep - rc, ctxt);
            return X86EMUL_EXCEPTION;
        }

        ++*reps;

        if ( poc->bpmatch || hypercall_preempt_check() )
            break;

        /* x86_emulate() clips the repetition count to ensure we don't wrap. */
        if ( unlikely(ctxt->regs->eflags & X86_EFLAGS_DF) )
            offset -= bytes_per_rep;
        else
            offset += bytes_per_rep;
    }

    return X86EMUL_OKAY;
}

static int cf_check rep_outs(
    enum x86_segment seg, unsigned long offset, uint16_t port,
    unsigned int bytes_per_rep, unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct priv_op_ctxt *poc = container_of(ctxt, struct priv_op_ctxt, ctxt);
    struct vcpu *curr = current;
    struct domain *currd = current->domain;
    unsigned long goal = *reps;
    struct segment_register sreg;
    int rc;

    *reps = 0;

    rc = guest_io_okay(port, bytes_per_rep, ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    rc = read_segment(seg, &sreg, ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( !sreg.p )
        return X86EMUL_UNHANDLEABLE;
    if ( !sreg.s ||
         ((sreg.type & (_SEGMENT_CODE >> 8)) &&
          !(sreg.type & (_SEGMENT_WR >> 8))) )
    {
        x86_emul_hw_exception(seg != x86_seg_ss ? X86_EXC_GP : X86_EXC_SS,
                              0, ctxt);
        return X86EMUL_EXCEPTION;
    }

    poc->bpmatch = check_guest_io_breakpoint(curr, port, bytes_per_rep);

    while ( *reps < goal )
    {
        unsigned int data = 0;
        unsigned long addr;

        rc = pv_emul_virt_to_linear(sreg.base, offset, bytes_per_rep,
                                    sreg.limit, seg, ctxt, &addr);
        if ( rc != X86EMUL_OKAY )
            return rc;

        if ( (rc = __copy_from_guest_pv(&data, (void __user *)addr,
                                        bytes_per_rep)) != 0 )
        {
            x86_emul_pagefault(0, addr + bytes_per_rep - rc, ctxt);
            return X86EMUL_EXCEPTION;
        }

        guest_io_write(port, bytes_per_rep, data, currd);

        ++*reps;

        if ( poc->bpmatch || hypercall_preempt_check() )
            break;

        /* x86_emulate() clips the repetition count to ensure we don't wrap. */
        if ( unlikely(ctxt->regs->eflags & X86_EFLAGS_DF) )
            offset -= bytes_per_rep;
        else
            offset += bytes_per_rep;
    }

    return X86EMUL_OKAY;
}

static int cf_check read_cr(
    unsigned int reg, unsigned long *val, struct x86_emulate_ctxt *ctxt)
{
    const struct vcpu *curr = current;

    switch ( reg )
    {
    case 0: /* Read CR0 */
        *val = (read_cr0() & ~X86_CR0_TS) | curr->arch.pv.ctrlreg[0];
        return X86EMUL_OKAY;

    case 2: /* Read CR2 */
    case 4: /* Read CR4 */
        *val = curr->arch.pv.ctrlreg[reg];
        return X86EMUL_OKAY;

    case 3: /* Read CR3 */
    {
        const struct domain *currd = curr->domain;
        mfn_t mfn;

        if ( !is_pv_32bit_domain(currd) )
        {
            mfn = pagetable_get_mfn(curr->arch.guest_table);
            *val = xen_pfn_to_cr3(gfn_x(mfn_to_gfn(currd, mfn)));
        }
        else
        {
            l4_pgentry_t *pl4e =
                map_domain_page(pagetable_get_mfn(curr->arch.guest_table));

            mfn = l4e_get_mfn(*pl4e);
            unmap_domain_page(pl4e);
            *val = compat_pfn_to_cr3(gfn_x(mfn_to_gfn(currd, mfn)));
        }

        return X86EMUL_OKAY;
    }
    }

    return X86EMUL_UNHANDLEABLE;
}

static int cf_check write_cr(
    unsigned int reg, unsigned long val, struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0: /* Write CR0 */
        if ( (val ^ read_cr0()) & ~X86_CR0_TS )
        {
            gdprintk(XENLOG_WARNING,
                     "Attempt to change unmodifiable CR0 flags\n");
            break;
        }
        do_fpu_taskswitch(!!(val & X86_CR0_TS));
        return X86EMUL_OKAY;

    case 2: /* Write CR2 */
        curr->arch.pv.ctrlreg[2] = val;
        arch_set_cr2(curr, val);
        return X86EMUL_OKAY;

    case 3: /* Write CR3 */
    {
        struct domain *currd = curr->domain;
        unsigned long gfn;
        struct page_info *page;
        int rc;

        gfn = !is_pv_32bit_domain(currd)
              ? xen_cr3_to_pfn(val) : compat_cr3_to_pfn(val);
        page = get_page_from_gfn(currd, gfn, NULL, P2M_ALLOC);
        if ( !page )
            break;
        rc = new_guest_cr3(page_to_mfn(page));
        put_page(page);

        switch ( rc )
        {
        case 0:
            return X86EMUL_OKAY;
        case -ERESTART: /* retry after preemption */
            return X86EMUL_RETRY;
        }
        break;
    }

    case 4: /* Write CR4 */
        curr->arch.pv.ctrlreg[4] = pv_fixup_guest_cr4(curr, val);
        write_cr4(pv_make_cr4(curr));
        ctxt_switch_levelling(curr);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static inline uint64_t guest_misc_enable(uint64_t val)
{
    val &= ~(MSR_IA32_MISC_ENABLE_PERF_AVAIL |
             MSR_IA32_MISC_ENABLE_MONITOR_ENABLE);
    val |= MSR_IA32_MISC_ENABLE_BTS_UNAVAIL |
           MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL |
           MSR_IA32_MISC_ENABLE_XTPR_DISABLE;
    return val;
}

static uint64_t guest_efer(const struct domain *d)
{
    uint64_t val;

    /* Hide unknown bits, and unconditionally hide SVME and AIBRSE from guests. */
    val = read_efer() & EFER_KNOWN_MASK & ~(EFER_SVME | EFER_AIBRSE);
    /*
     * Hide the 64-bit features from 32-bit guests.  SCE has
     * vendor-dependent behaviour.
     */
    if ( is_pv_32bit_domain(d) )
        val &= ~(EFER_LME | EFER_LMA |
                 (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL
                  ? EFER_SCE : 0));
    return val;
}

static int cf_check read_msr(
    unsigned int reg, uint64_t *val, struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;
    const struct domain *currd = curr->domain;
    const struct cpu_policy *cp = currd->arch.cpu_policy;
    bool vpmu_msr = false, warn = false;
    uint64_t tmp;
    int ret;

    if ( (ret = guest_rdmsr(curr, reg, val)) != X86EMUL_UNHANDLEABLE )
    {
        if ( ret == X86EMUL_EXCEPTION )
            x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);

        goto done;
    }

    switch ( reg )
    {
    case MSR_APIC_BASE:
        /* Linux PV guests will attempt to read APIC_BASE. */
        *val = APIC_BASE_ENABLE | APIC_DEFAULT_PHYS_BASE;
        if ( !curr->vcpu_id )
            *val |= APIC_BASE_BSP;
        return X86EMUL_OKAY;

    case MSR_FS_BASE:
        if ( !cp->extd.lm )
            break;
        *val = read_fs_base();
        return X86EMUL_OKAY;

    case MSR_GS_BASE:
        if ( !cp->extd.lm )
            break;
        *val = read_gs_base();
        return X86EMUL_OKAY;

    case MSR_SHADOW_GS_BASE:
        if ( !cp->extd.lm )
            break;
        *val = curr->arch.pv.gs_base_user;
        return X86EMUL_OKAY;

    case MSR_IA32_TSC:
        *val = currd->arch.vtsc ? pv_soft_rdtsc(curr, ctxt->regs) : rdtsc();
        return X86EMUL_OKAY;

    case MSR_EFER:
        *val = guest_efer(currd);
        return X86EMUL_OKAY;

    case MSR_IA32_CR_PAT:
        *val = XEN_MSR_PAT;
        return X86EMUL_OKAY;

    case MSR_K7_FID_VID_CTL:
    case MSR_K7_FID_VID_STATUS:
    case MSR_K8_PSTATE_LIMIT:
    case MSR_K8_PSTATE_CTRL:
    case MSR_K8_PSTATE_STATUS:
    case MSR_K8_PSTATE0:
    case MSR_K8_PSTATE1:
    case MSR_K8_PSTATE2:
    case MSR_K8_PSTATE3:
    case MSR_K8_PSTATE4:
    case MSR_K8_PSTATE5:
    case MSR_K8_PSTATE6:
    case MSR_K8_PSTATE7:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
            break;
        if ( unlikely(is_cpufreq_controller(currd)) )
            goto normal;
        *val = 0;
        return X86EMUL_OKAY;

    case MSR_FAM10H_MMIO_CONF_BASE:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
             boot_cpu_data.x86 < 0x10 || boot_cpu_data.x86 >= 0x17 )
            break;
        /* fall through */
    case MSR_AMD64_NB_CFG:
        if ( is_hwdom_pinned_vcpu(curr) )
            goto normal;
        *val = 0;
        return X86EMUL_OKAY;

    case MSR_IA32_MISC_ENABLE:
        if ( rdmsr_safe(reg, *val) )
            break;
        *val = guest_misc_enable(*val);
        return X86EMUL_OKAY;

    case MSR_IA32_PERF_CAPABILITIES:
        /* No extra capabilities are supported. */
        *val = 0;
        return X86EMUL_OKAY;

    case MSR_P6_PERFCTR(0) ... MSR_P6_PERFCTR(7):
    case MSR_P6_EVNTSEL(0) ... MSR_P6_EVNTSEL(3):
    case MSR_CORE_PERF_FIXED_CTR0 ... MSR_CORE_PERF_FIXED_CTR2:
    case MSR_CORE_PERF_FIXED_CTR_CTRL ... MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        {
            vpmu_msr = true;
            /* fall through */
    case MSR_AMD_FAM15H_EVNTSEL0 ... MSR_AMD_FAM15H_PERFCTR5:
    case MSR_K7_EVNTSEL0 ... MSR_K7_PERFCTR3:
            if ( vpmu_msr || (boot_cpu_data.x86_vendor &
                              (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
            {
                if ( vpmu_do_rdmsr(reg, val) )
                    break;
                return X86EMUL_OKAY;
            }
        }
        /* fall through */
    default:
        if ( currd->arch.msr_relaxed && !rdmsr_safe(reg, tmp) )
        {
            *val = 0;
            return X86EMUL_OKAY;
        }

        warn = true;
        break;

    normal:
        if ( rdmsr_safe(reg, *val) )
            break;
        return X86EMUL_OKAY;
    }

 done:
    if ( ret != X86EMUL_OKAY && !curr->arch.pv.trap_ctxt[X86_EXC_GP].address &&
         (reg >> 16) != 0x4000 && !rdmsr_safe(reg, tmp) )
    {
        gprintk(XENLOG_WARNING, "faking RDMSR 0x%08x\n", reg);
        *val = 0;
        x86_emul_reset_event(ctxt);
        ret = X86EMUL_OKAY;
    }
    else if ( warn )
        gdprintk(XENLOG_WARNING, "RDMSR 0x%08x unimplemented\n", reg);

    return ret;
}

static int cf_check write_msr(
    unsigned int reg, uint64_t val, struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;
    const struct domain *currd = curr->domain;
    const struct cpu_policy *cp = currd->arch.cpu_policy;
    bool vpmu_msr = false;
    int ret;

    if ( (ret = guest_wrmsr(curr, reg, val)) != X86EMUL_UNHANDLEABLE )
    {
        if ( ret == X86EMUL_EXCEPTION )
            x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);

        return ret;
    }

    switch ( reg )
    {
        uint64_t temp;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !cp->extd.lm || !is_canonical_address(val) )
            break;

        if ( reg == MSR_FS_BASE )
            write_fs_base(val);
        else if ( reg == MSR_GS_BASE )
            write_gs_base(val);
        else if ( reg == MSR_SHADOW_GS_BASE )
        {
            write_gs_shadow(val);
            curr->arch.pv.gs_base_user = val;
        }
        else
            ASSERT_UNREACHABLE();
        return X86EMUL_OKAY;

    case MSR_EFER:
        /*
         * Reject writes which change the value, but Linux depends on being
         * able to write back the current value.
         */
        if ( val != guest_efer(currd) )
            break;
        return X86EMUL_OKAY;

    case MSR_K7_FID_VID_STATUS:
    case MSR_K7_FID_VID_CTL:
    case MSR_K8_PSTATE_LIMIT:
    case MSR_K8_PSTATE_CTRL:
    case MSR_K8_PSTATE_STATUS:
    case MSR_K8_PSTATE0:
    case MSR_K8_PSTATE1:
    case MSR_K8_PSTATE2:
    case MSR_K8_PSTATE3:
    case MSR_K8_PSTATE4:
    case MSR_K8_PSTATE5:
    case MSR_K8_PSTATE6:
    case MSR_K8_PSTATE7:
    case MSR_K8_HWCR:
        if ( !(boot_cpu_data.x86_vendor &
               (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
            break;
        if ( likely(!is_cpufreq_controller(currd)) ||
             wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_AMD64_NB_CFG:
        if ( !is_hwdom_pinned_vcpu(curr) )
            return X86EMUL_OKAY;
        if ( (rdmsr_safe(MSR_AMD64_NB_CFG, temp) != 0) ||
             ((val ^ temp) & ~(1ULL << AMD64_NB_CFG_CF8_EXT_ENABLE_BIT)) )
            goto invalid;
        if ( wrmsr_safe(MSR_AMD64_NB_CFG, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_FAM10H_MMIO_CONF_BASE:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
             boot_cpu_data.x86 < 0x10 || boot_cpu_data.x86 >= 0x17 )
            break;
        if ( !is_hwdom_pinned_vcpu(curr) )
            return X86EMUL_OKAY;
        if ( rdmsr_safe(MSR_FAM10H_MMIO_CONF_BASE, temp) != 0 )
            break;
        if ( (pci_probe & PCI_PROBE_MASK) == PCI_PROBE_MMCONF ?
             temp != val :
             ((temp ^ val) &
              ~(FAM10H_MMIO_CONF_ENABLE |
                (FAM10H_MMIO_CONF_BUSRANGE_MASK <<
                 FAM10H_MMIO_CONF_BUSRANGE_SHIFT) |
                ((u64)FAM10H_MMIO_CONF_BASE_MASK <<
                 FAM10H_MMIO_CONF_BASE_SHIFT))) )
            goto invalid;
        if ( wrmsr_safe(MSR_FAM10H_MMIO_CONF_BASE, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_IA32_MISC_ENABLE:
        if ( rdmsr_safe(reg, temp) )
            break;
        if ( val != guest_misc_enable(temp) )
            goto invalid;
        return X86EMUL_OKAY;

    case MSR_IA32_MPERF:
    case MSR_IA32_APERF:
        if ( !(boot_cpu_data.x86_vendor &
               (X86_VENDOR_INTEL | X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
            break;
        if ( likely(!is_cpufreq_controller(currd)) ||
             wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_IA32_THERM_CONTROL:
    case MSR_IA32_ENERGY_PERF_BIAS:
        if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
            break;
        if ( !is_hwdom_pinned_vcpu(curr) || wrmsr_safe(reg, val) == 0 )
            return X86EMUL_OKAY;
        break;

    case MSR_P6_PERFCTR(0) ... MSR_P6_PERFCTR(7):
    case MSR_P6_EVNTSEL(0) ... MSR_P6_EVNTSEL(3):
    case MSR_CORE_PERF_FIXED_CTR0 ... MSR_CORE_PERF_FIXED_CTR2:
    case MSR_CORE_PERF_FIXED_CTR_CTRL ... MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        {
            vpmu_msr = true;
    case MSR_AMD_FAM15H_EVNTSEL0 ... MSR_AMD_FAM15H_PERFCTR5:
    case MSR_K7_EVNTSEL0 ... MSR_K7_PERFCTR3:
            if ( vpmu_msr || (boot_cpu_data.x86_vendor &
                              (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
            {
                if ( (vpmu_mode & XENPMU_MODE_ALL) &&
                     !is_hardware_domain(currd) )
                    return X86EMUL_OKAY;

                if ( vpmu_do_wrmsr(reg, val) )
                    break;
                return X86EMUL_OKAY;
            }
        }
        /* fall through */
    default:
        if ( currd->arch.msr_relaxed && !rdmsr_safe(reg, val) )
            return X86EMUL_OKAY;

        gdprintk(XENLOG_WARNING,
                 "WRMSR 0x%08x val 0x%016"PRIx64" unimplemented\n",
                 reg, val);
        break;

    invalid:
        gdprintk(XENLOG_WARNING,
                 "Domain attempted WRMSR 0x%08x from 0x%016"PRIx64" to 0x%016"PRIx64"\n",
                 reg, temp, val);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static int cf_check cache_op(
    enum x86emul_cache_op op, enum x86_segment seg,
    unsigned long offset, struct x86_emulate_ctxt *ctxt)
{
    ASSERT(op == x86emul_wbinvd || op == x86emul_wbnoinvd);

    /* Ignore the instruction if unprivileged. */
    if ( !cache_flush_permitted(current->domain) )
        /*
         * Non-physdev domain attempted WBINVD; ignore for now since
         * newer linux uses this in some start-of-day timing loops.
         */
        ;
    else if ( op == x86emul_wbnoinvd /* && cpu_has_wbnoinvd */ )
        wbnoinvd();
    else
        wbinvd();

    return X86EMUL_OKAY;
}

static int cf_check validate(
    const struct x86_emulate_state *state, struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
    case 0x6c ... 0x6f: /* ins / outs */
    case 0xe4 ... 0xe7: /* in / out (immediate port) */
    case 0xec ... 0xef: /* in / out (port in %dx) */
    case X86EMUL_OPC(0x0f, 0x06): /* clts */
    case X86EMUL_OPC(0x0f, 0x09): /* wbinvd */
    case X86EMUL_OPC(0x0f, 0x20) ...
         X86EMUL_OPC(0x0f, 0x23): /* mov to/from cr/dr */
    case X86EMUL_OPC(0x0f, 0x30): /* wrmsr */
    case X86EMUL_OPC(0x0f, 0x31): /* rdtsc */
    case X86EMUL_OPC(0x0f, 0x32): /* rdmsr */
    case X86EMUL_OPC(0x0f, 0xa2): /* cpuid */
        return X86EMUL_OKAY;

    case 0xfa: case 0xfb: /* cli / sti */
        if ( !iopl_ok(current, ctxt->regs) )
            break;
        /*
         * This is just too dangerous to allow, in my opinion. Consider if the
         * caller then tries to reenable interrupts using POPF: we can't trap
         * that and we'll end up with hard-to-debug lockups. Fast & loose will
         * do for us. :-)
        vcpu_info(current, evtchn_upcall_mask) = (ctxt->opcode == 0xfa);
         */
        return X86EMUL_DONE;

    case X86EMUL_OPC(0x0f, 0x01):
    {
        unsigned int modrm_rm, modrm_reg;

        if ( x86_insn_modrm(state, &modrm_rm, &modrm_reg) != 3 ||
             (modrm_rm & 7) != 1 )
            break;
        switch ( modrm_reg & 7 )
        {
        case 2: /* xsetbv */
        case 7: /* rdtscp */
            return X86EMUL_OKAY;
        }
        break;
    }
    }

    return X86EMUL_UNHANDLEABLE;
}

static int cf_check insn_fetch(
    unsigned long offset, void *p_data, unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    const struct priv_op_ctxt *poc =
        container_of(ctxt, struct priv_op_ctxt, ctxt);
    unsigned int rc;
    unsigned long addr = poc->cs.base + offset;

    /* We don't mean to emulate any branches. */
    if ( !bytes )
        return X86EMUL_UNHANDLEABLE;

    rc = pv_emul_virt_to_linear(poc->cs.base, offset, bytes, poc->cs.limit,
                                x86_seg_cs, ctxt, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( (rc = __copy_from_guest_pv(p_data, (void __user *)addr, bytes)) != 0 )
    {
        /*
         * TODO: This should report PFEC_insn_fetch when goc->insn_fetch &&
         * cpu_has_nx, but we'd then need a "fetch" variant of
         * __copy_from_guest_pv() respecting NX, SMEP, and protection keys.
         */
        x86_emul_pagefault(0, addr + bytes - rc, ctxt);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}


static const struct x86_emulate_ops priv_op_ops = {
    .insn_fetch          = insn_fetch,
    .read                = x86emul_unhandleable_rw,
    .validate            = validate,
    .read_io             = read_io,
    .write_io            = write_io,
    .rep_ins             = rep_ins,
    .rep_outs            = rep_outs,
    .read_segment        = read_segment,
    .read_cr             = read_cr,
    .write_cr            = write_cr,
    .read_dr             = x86emul_read_dr,
    .write_dr            = x86emul_write_dr,
    .write_xcr           = x86emul_write_xcr,
    .read_msr            = read_msr,
    .write_msr           = write_msr,
    .cpuid               = x86emul_cpuid,
    .cache_op            = cache_op,
};

int pv_emulate_privileged_op(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct priv_op_ctxt ctxt = {
        .ctxt.regs = regs,
        .ctxt.lma = !is_pv_32bit_domain(currd),
    };
    int rc;
    unsigned int eflags, ar;

    /* Not part of the initializer, for old gcc to cope. */
    ctxt.ctxt.cpu_policy = currd->arch.cpu_policy;

    if ( !pv_emul_read_descriptor(regs->cs, curr, &ctxt.cs.base,
                                  &ctxt.cs.limit, &ar, 1) ||
         !(ar & _SEGMENT_S) ||
         !(ar & _SEGMENT_P) ||
         !(ar & _SEGMENT_CODE) )
        return 0;

    /* Mirror virtualized state into EFLAGS. */
    ASSERT(regs->eflags & X86_EFLAGS_IF);
    if ( vcpu_info(curr, evtchn_upcall_mask) )
        regs->eflags &= ~X86_EFLAGS_IF;
    else
        regs->eflags |= X86_EFLAGS_IF;
    ASSERT(!(regs->eflags & X86_EFLAGS_IOPL));
    regs->eflags |= curr->arch.pv.iopl;
    eflags = regs->eflags;

    ctxt.ctxt.addr_size = ar & _SEGMENT_L ? 64 : ar & _SEGMENT_DB ? 32 : 16;
    /* Leave zero in ctxt.ctxt.sp_size, as it's not needed. */
    rc = x86_emulate(&ctxt.ctxt, &priv_op_ops);

    if ( ctxt.io_emul_stub )
        unmap_domain_page(ctxt.io_emul_stub);

    /*
     * Un-mirror virtualized state from EFLAGS.
     * Nothing we allow to be emulated can change anything other than the
     * arithmetic bits, and the resume flag.
     */
    ASSERT(!((regs->eflags ^ eflags) &
             ~(X86_EFLAGS_RF | X86_EFLAGS_ARITH_MASK)));
    regs->eflags |= X86_EFLAGS_IF;
    regs->eflags &= ~X86_EFLAGS_IOPL;

    switch ( rc )
    {
    case X86EMUL_OKAY:
        ASSERT(!curr->arch.pv.trap_bounce.flags);

        if ( ctxt.ctxt.retire.singlestep )
            ctxt.bpmatch |= DR_STEP;

        if ( ctxt.bpmatch )
            pv_inject_DB(ctxt.bpmatch);

        /* fall through */
    case X86EMUL_RETRY:
        return EXCRET_fault_fixed;

    case X86EMUL_EXCEPTION:
        pv_inject_event(&ctxt.ctxt.event);
        return EXCRET_fault_fixed;
    }

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
