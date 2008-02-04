/*
 * cpu.h: Virtual CPU state
 * Copyright (c) 2004, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#ifndef __ASM_X86_HVM_VMX_CPU_H__
#define __ASM_X86_HVM_VMX_CPU_H__

#define NUM_CORES_RESET_MASK                 0x00003FFF
#define NUM_THREADS_RESET_MASK               0xFF00FFFF

#define VMX_VCPU_CPUID_L1_ECX_RESERVED_18    0x00040000
#define VMX_VCPU_CPUID_L1_ECX_RESERVED_6     0x00000040

#define VMX_VCPU_CPUID_L1_ECX_RESERVED              \
            ( VMX_VCPU_CPUID_L1_ECX_RESERVED_18 |   \
              VMX_VCPU_CPUID_L1_ECX_RESERVED_6 )

#endif /* __ASM_X86_HVM_VMX_CPU_H__ */
