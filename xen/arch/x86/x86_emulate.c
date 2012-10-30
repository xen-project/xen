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

#include <asm/x86_emulate.h>
#include <asm/asm_defns.h> /* mark_regs_dirty() */
#include <asm/processor.h> /* current_cpu_info */
#include <asm/amd.h> /* cpu_has_amd_erratum() */

/* Avoid namespace pollution. */
#undef cmpxchg
#undef cpuid

#define cpu_has_amd_erratum(nr) \
        cpu_has_amd_erratum(&current_cpu_data, AMD_ERRATUM_##nr)

#include "x86_emulate/x86_emulate.c"
