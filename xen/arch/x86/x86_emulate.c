/******************************************************************************
 * x86_emulate.c
 * 
 * Wrapper for generic x86 instruction decoder and emulator.
 * 
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/event.h>
#include <asm/x86_emulate.h>
#include <asm/processor.h> /* current_cpu_info */
#include <asm/xstate.h>
#include <asm/amd.h> /* cpu_has_amd_erratum() */
#include <asm/debugreg.h>

/* Avoid namespace pollution. */
#undef cmpxchg
#undef cpuid
#undef wbinvd

#define r(name) r ## name

#define cpu_has_amd_erratum(nr) \
        cpu_has_amd_erratum(&current_cpu_data, AMD_ERRATUM_##nr)

#define get_stub(stb) ({                                        \
    BUILD_BUG_ON(STUB_BUF_SIZE / 2 < MAX_INST_LEN + 1);         \
    ASSERT(!(stb).ptr);                                         \
    (stb).addr = this_cpu(stubs.addr) + STUB_BUF_SIZE / 2;      \
    memset(((stb).ptr = map_domain_page(_mfn(this_cpu(stubs.mfn)))) +  \
           ((stb).addr & ~PAGE_MASK), 0xcc, STUB_BUF_SIZE / 2);        \
})
#define put_stub(stb) ({                                   \
    if ( (stb).ptr )                                       \
    {                                                      \
        unmap_domain_page((stb).ptr);                      \
        (stb).ptr = NULL;                                  \
    }                                                      \
})

#define FXSAVE_AREA current->arch.fpu_ctxt

#ifndef CONFIG_HVM
# define X86EMUL_NO_FPU
# define X86EMUL_NO_MMX
# define X86EMUL_NO_SIMD
#endif

#include "x86_emulate/x86_emulate.c"

int x86emul_read_xcr(unsigned int reg, uint64_t *val,
                     struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
        *val = current->arch.xcr0;
        return X86EMUL_OKAY;

    case 1:
        if ( current->domain->arch.cpuid->xstate.xgetbv1 )
            break;
        /* fall through */
    default:
        x86_emul_hw_exception(TRAP_gp_fault, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }

    *val = xgetbv(reg);

    return X86EMUL_OKAY;
}

/* Note: May be called with ctxt=NULL. */
int x86emul_write_xcr(unsigned int reg, uint64_t val,
                      struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
        break;

    default:
    gp_fault:
        if ( ctxt )
            x86_emul_hw_exception(TRAP_gp_fault, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }

    if ( unlikely(handle_xsetbv(reg, val) != 0) )
        goto gp_fault;

    return X86EMUL_OKAY;
}

#ifdef CONFIG_PV
/* Called with NULL ctxt in hypercall context. */
int x86emul_read_dr(unsigned int reg, unsigned long *val,
                    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    /* HVM support requires a bit more plumbing before it will work. */
    ASSERT(is_pv_vcpu(curr));

    switch ( reg )
    {
    case 0 ... 3:
        *val = array_access_nospec(curr->arch.dr, reg);
        break;

    case 4:
        if ( curr->arch.pv.ctrlreg[4] & X86_CR4_DE )
            goto ud_fault;

        /* Fallthrough */
    case 6:
        *val = curr->arch.dr6;
        break;

    case 5:
        if ( curr->arch.pv.ctrlreg[4] & X86_CR4_DE )
            goto ud_fault;

        /* Fallthrough */
    case 7:
        *val = curr->arch.dr7 | curr->arch.pv.dr7_emul;
        break;

    ud_fault:
    default:
        if ( ctxt )
            x86_emul_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC, ctxt);

        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int x86emul_write_dr(unsigned int reg, unsigned long val,
                     struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    /* HVM support requires a bit more plumbing before it will work. */
    ASSERT(is_pv_vcpu(curr));

    switch ( set_debugreg(curr, reg, val) )
    {
    case 0:
        return X86EMUL_OKAY;

    case -ENODEV:
        x86_emul_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC, ctxt);
        return X86EMUL_EXCEPTION;

    default:
        x86_emul_hw_exception(TRAP_gp_fault, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }
}
#endif /* CONFIG_PV */

int x86emul_cpuid(uint32_t leaf, uint32_t subleaf,
                  struct cpuid_leaf *res, struct x86_emulate_ctxt *ctxt)
{
    guest_cpuid(current, leaf, subleaf, res);

    return X86EMUL_OKAY;
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
