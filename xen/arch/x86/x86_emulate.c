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
#include <asm/x86_emulate.h>
#include <asm/asm_defns.h> /* mark_regs_dirty() */
#include <asm/processor.h> /* current_cpu_info */
#include <asm/xstate.h>
#include <asm/amd.h> /* cpu_has_amd_erratum() */

/* Avoid namespace pollution. */
#undef cmpxchg
#undef cpuid
#undef wbinvd

#define cpu_has_amd_erratum(nr) \
        cpu_has_amd_erratum(&current_cpu_data, AMD_ERRATUM_##nr)

#define get_stub(stb) ({                                        \
    BUILD_BUG_ON(STUB_BUF_SIZE / 2 < MAX_INST_LEN + 1);         \
    (stb).addr = this_cpu(stubs.addr) + STUB_BUF_SIZE / 2;      \
    ((stb).ptr = map_domain_page(_mfn(this_cpu(stubs.mfn)))) +  \
        ((stb).addr & ~PAGE_MASK);                              \
})
#define put_stub(stb) ({                                   \
    if ( (stb).ptr )                                       \
    {                                                      \
        unmap_domain_page((stb).ptr);                      \
        (stb).ptr = NULL;                                  \
    }                                                      \
})

#include "x86_emulate/x86_emulate.c"
