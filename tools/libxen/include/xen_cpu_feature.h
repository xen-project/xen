/*
 * Copyright (c) 2006, XenSource Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef XEN_CPU_FEATURE_H
#define XEN_CPU_FEATURE_H


#include "xen_common.h"


enum xen_cpu_feature
{
    /**
     *  Onboard FPU
     */
    XEN_CPU_FEATURE_FPU,

    /**
     *  Virtual Mode Extensions
     */
    XEN_CPU_FEATURE_VME,

    /**
     *  Debugging Extensions
     */
    XEN_CPU_FEATURE_DE,

    /**
     *  Page Size Extensions
     */
    XEN_CPU_FEATURE_PSE,

    /**
     *  Time Stamp Counter
     */
    XEN_CPU_FEATURE_TSC,

    /**
     *  Model-Specific Registers, RDMSR, WRMSR
     */
    XEN_CPU_FEATURE_MSR,

    /**
     *  Physical Address Extensions
     */
    XEN_CPU_FEATURE_PAE,

    /**
     *  Machine Check Architecture
     */
    XEN_CPU_FEATURE_MCE,

    /**
     *  CMPXCHG8 instruction
     */
    XEN_CPU_FEATURE_CX8,

    /**
     *  Onboard APIC
     */
    XEN_CPU_FEATURE_APIC,

    /**
     *  SYSENTER/SYSEXIT
     */
    XEN_CPU_FEATURE_SEP,

    /**
     *  Memory Type Range Registers
     */
    XEN_CPU_FEATURE_MTRR,

    /**
     *  Page Global Enable
     */
    XEN_CPU_FEATURE_PGE,

    /**
     *  Machine Check Architecture
     */
    XEN_CPU_FEATURE_MCA,

    /**
     *  CMOV instruction (FCMOVCC and FCOMI too if FPU present)
     */
    XEN_CPU_FEATURE_CMOV,

    /**
     *  Page Attribute Table
     */
    XEN_CPU_FEATURE_PAT,

    /**
     *  36-bit PSEs
     */
    XEN_CPU_FEATURE_PSE36,

    /**
     *  Processor serial number
     */
    XEN_CPU_FEATURE_PN,

    /**
     *  Supports the CLFLUSH instruction
     */
    XEN_CPU_FEATURE_CLFLSH,

    /**
     *  Debug Trace Store
     */
    XEN_CPU_FEATURE_DTES,

    /**
     *  ACPI via MSR
     */
    XEN_CPU_FEATURE_ACPI,

    /**
     *  Multimedia Extensions
     */
    XEN_CPU_FEATURE_MMX,

    /**
     *  FXSAVE and FXRSTOR instructions (fast save and restore
     */
    XEN_CPU_FEATURE_FXSR,

    /**
     *  Streaming SIMD Extensions
     */
    XEN_CPU_FEATURE_XMM,

    /**
     *  Streaming SIMD Extensions-2
     */
    XEN_CPU_FEATURE_XMM2,

    /**
     *  CPU self snoop
     */
    XEN_CPU_FEATURE_SELFSNOOP,

    /**
     *  Hyper-Threading
     */
    XEN_CPU_FEATURE_HT,

    /**
     *  Automatic clock control
     */
    XEN_CPU_FEATURE_ACC,

    /**
     *  IA-64 processor
     */
    XEN_CPU_FEATURE_IA64,

    /**
     *  SYSCALL/SYSRET
     */
    XEN_CPU_FEATURE_SYSCALL,

    /**
     *  MP Capable.
     */
    XEN_CPU_FEATURE_MP,

    /**
     *  Execute Disable
     */
    XEN_CPU_FEATURE_NX,

    /**
     *  AMD MMX extensions
     */
    XEN_CPU_FEATURE_MMXEXT,

    /**
     *  Long Mode (x86-64)
     */
    XEN_CPU_FEATURE_LM,

    /**
     *  AMD 3DNow! extensions
     */
    XEN_CPU_FEATURE_THREEDNOWEXT,

    /**
     *  3DNow!
     */
    XEN_CPU_FEATURE_THREEDNOW,

    /**
     *  CPU in recovery mode
     */
    XEN_CPU_FEATURE_RECOVERY,

    /**
     *  Longrun power control
     */
    XEN_CPU_FEATURE_LONGRUN,

    /**
     *  LongRun table interface
     */
    XEN_CPU_FEATURE_LRTI,

    /**
     *  Cyrix MMX extensions
     */
    XEN_CPU_FEATURE_CXMMX,

    /**
     *  AMD K6 nonstandard MTRRs
     */
    XEN_CPU_FEATURE_K6_MTRR,

    /**
     *  Cyrix ARRs (= MTRRs)
     */
    XEN_CPU_FEATURE_CYRIX_ARR,

    /**
     *  Centaur MCRs (= MTRRs)
     */
    XEN_CPU_FEATURE_CENTAUR_MCR,

    /**
     *  Opteron, Athlon64
     */
    XEN_CPU_FEATURE_K8,

    /**
     *  Athlon
     */
    XEN_CPU_FEATURE_K7,

    /**
     *  P3
     */
    XEN_CPU_FEATURE_P3,

    /**
     *  P4
     */
    XEN_CPU_FEATURE_P4,

    /**
     *  TSC ticks at a constant rate
     */
    XEN_CPU_FEATURE_CONSTANT_TSC,

    /**
     *  FXSAVE leaks FOP/FIP/FOP
     */
    XEN_CPU_FEATURE_FXSAVE_LEAK,

    /**
     *  Streaming SIMD Extensions-3
     */
    XEN_CPU_FEATURE_XMM3,

    /**
     *  Monitor/Mwait support
     */
    XEN_CPU_FEATURE_MWAIT,

    /**
     *  CPL Qualified Debug Store
     */
    XEN_CPU_FEATURE_DSCPL,

    /**
     *  Enhanced SpeedStep
     */
    XEN_CPU_FEATURE_EST,

    /**
     *  Thermal Monitor 2
     */
    XEN_CPU_FEATURE_TM2,

    /**
     *  Context ID
     */
    XEN_CPU_FEATURE_CID,

    /**
     *  CMPXCHG16B
     */
    XEN_CPU_FEATURE_CX16,

    /**
     *  Send Task Priority Messages
     */
    XEN_CPU_FEATURE_XTPR,

    /**
     *  on-CPU RNG present (xstore insn)
     */
    XEN_CPU_FEATURE_XSTORE,

    /**
     *  on-CPU RNG enabled
     */
    XEN_CPU_FEATURE_XSTORE_EN,

    /**
     *  on-CPU crypto (xcrypt insn)
     */
    XEN_CPU_FEATURE_XCRYPT,

    /**
     *  on-CPU crypto enabled
     */
    XEN_CPU_FEATURE_XCRYPT_EN,

    /**
     *  LAHF/SAHF in long mode
     */
    XEN_CPU_FEATURE_LAHF_LM,

    /**
     *  If yes HyperThreading not valid
     */
    XEN_CPU_FEATURE_CMP_LEGACY,

    /**
     *  VMX instruction set
     */
    XEN_CPU_FEATURE_VMX
};


typedef struct xen_cpu_feature_set
{
    size_t size;
    enum xen_cpu_feature contents[];
} xen_cpu_feature_set;

/**
 * Allocate a xen_cpu_feature_set of the given size.
 */
extern xen_cpu_feature_set *
xen_cpu_feature_set_alloc(size_t size);

/**
 * Free the given xen_cpu_feature_set.  The given set must have been
 * allocated by this library.
 */
extern void
xen_cpu_feature_set_free(xen_cpu_feature_set *set);


/**
 * Return the name corresponding to the given code.  This string must
 * not be modified or freed.
 */
extern const char *
xen_cpu_feature_to_string(enum xen_cpu_feature val);


/**
 * Return the correct code for the given string, or set the session
 * object to failure and return an undefined value if the given string does
 * not match a known code.
 */
extern enum xen_cpu_feature
xen_cpu_feature_from_string(xen_session *session, const char *str);


#endif
