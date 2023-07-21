/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) IBM Corp. 2005
 * Copyright Raptor Engineering, LLC
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Shawn Anastasio <sanastasio@raptorengineering.com>
 */

#ifndef _ASM_PPC_MSR_H
#define _ASM_PPC_MSR_H

#include <xen/const.h>

/* Flags in MSR: */
#define MSR_SF      _AC(0x8000000000000000, ULL)
#define MSR_TA      _AC(0x4000000000000000, ULL)
#define MSR_ISF     _AC(0x2000000000000000, ULL)
#define MSR_HV      _AC(0x1000000000000000, ULL)
#define MSR_VMX     _AC(0x0000000002000000, ULL)
#define MSR_MER     _AC(0x0000000000200000, ULL)
#define MSR_POW     _AC(0x0000000000040000, ULL)
#define MSR_ILE     _AC(0x0000000000010000, ULL)
#define MSR_EE      _AC(0x0000000000008000, ULL)
#define MSR_PR      _AC(0x0000000000004000, ULL)
#define MSR_FP      _AC(0x0000000000002000, ULL)
#define MSR_ME      _AC(0x0000000000001000, ULL)
#define MSR_FE0     _AC(0x0000000000000800, ULL)
#define MSR_SE      _AC(0x0000000000000400, ULL)
#define MSR_BE      _AC(0x0000000000000200, ULL)
#define MSR_FE1     _AC(0x0000000000000100, ULL)
#define MSR_IP      _AC(0x0000000000000040, ULL)
#define MSR_IR      _AC(0x0000000000000020, ULL)
#define MSR_DR      _AC(0x0000000000000010, ULL)
#define MSR_PMM     _AC(0x0000000000000004, ULL)
#define MSR_RI      _AC(0x0000000000000002, ULL)
#define MSR_LE      _AC(0x0000000000000001, ULL)

/* MSR bits set on the systemsim simulator */
#define MSR_SIM       _AC(0x0000000020000000, ULL)
#define MSR_SYSTEMSIM _AC(0x0000000010000000, ULL)

/* On a trap, srr1's copy of msr defines some bits as follows: */
#define MSR_TRAP_FE     _AC(0x0000000000100000, ULL) /* Floating Point Exception */
#define MSR_TRAP_IOP    _AC(0x0000000000080000, ULL) /* Illegal Instruction */
#define MSR_TRAP_PRIV   _AC(0x0000000000040000, ULL) /* Privileged Instruction */
#define MSR_TRAP        _AC(0x0000000000020000, ULL) /* Trap Instruction */
#define MSR_TRAP_NEXT   _AC(0x0000000000010000, ULL) /* PC is next instruction */
#define MSR_TRAP_BITS  (MSR_TRAP_FE|MSR_TRAP_IOP|MSR_TRAP_PRIV|MSR_TRAP)

#endif /* _ASM_PPC_MSR_H */
