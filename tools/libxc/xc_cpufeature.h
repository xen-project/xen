/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LIBXC_CPUFEATURE_H
#define __LIBXC_CPUFEATURE_H

/* Intel-defined CPU features, CPUID level 0x00000001 (edx) */
#define X86_FEATURE_FPU          0 /* Onboard FPU */
#define X86_FEATURE_VME          1 /* Virtual Mode Extensions */
#define X86_FEATURE_DE           2 /* Debugging Extensions */
#define X86_FEATURE_PSE          3 /* Page Size Extensions */
#define X86_FEATURE_TSC          4 /* Time Stamp Counter */
#define X86_FEATURE_MSR          5 /* Model-Specific Registers, RDMSR, WRMSR */
#define X86_FEATURE_PAE          6 /* Physical Address Extensions */
#define X86_FEATURE_MCE          7 /* Machine Check Architecture */
#define X86_FEATURE_CX8          8 /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC         9 /* Onboard APIC */
#define X86_FEATURE_SEP         11 /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR        12 /* Memory Type Range Registers */
#define X86_FEATURE_PGE         13 /* Page Global Enable */
#define X86_FEATURE_MCA         14 /* Machine Check Architecture */
#define X86_FEATURE_CMOV        15 /* CMOV instruction */
#define X86_FEATURE_PAT         16 /* Page Attribute Table */
#define X86_FEATURE_PSE36       17 /* 36-bit PSEs */
#define X86_FEATURE_PN          18 /* Processor serial number */
#define X86_FEATURE_CLFLSH      19 /* Supports the CLFLUSH instruction */
#define X86_FEATURE_DS          21 /* Debug Store */
#define X86_FEATURE_ACPI        22 /* ACPI via MSR */
#define X86_FEATURE_MMX         23 /* Multimedia Extensions */
#define X86_FEATURE_FXSR        24 /* FXSAVE and FXRSTOR instructions */
#define X86_FEATURE_XMM         25 /* Streaming SIMD Extensions */
#define X86_FEATURE_XMM2        26 /* Streaming SIMD Extensions-2 */
#define X86_FEATURE_SELFSNOOP   27 /* CPU self snoop */
#define X86_FEATURE_HT          28 /* Hyper-Threading */
#define X86_FEATURE_ACC         29 /* Automatic clock control */
#define X86_FEATURE_IA64        30 /* IA-64 processor */
#define X86_FEATURE_PBE         31 /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL     11 /* SYSCALL/SYSRET */
#define X86_FEATURE_MP          19 /* MP Capable. */
#define X86_FEATURE_NX          20 /* Execute Disable */
#define X86_FEATURE_MMXEXT      22 /* AMD MMX extensions */
#define X86_FEATURE_FFXSR       25 /* FFXSR instruction optimizations */
#define X86_FEATURE_PAGE1GB     26 /* 1Gb large page support */
#define X86_FEATURE_RDTSCP      27 /* RDTSCP */
#define X86_FEATURE_LM          29 /* Long Mode (x86-64) */
#define X86_FEATURE_3DNOWEXT    30 /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW       31 /* 3DNow! */

/* Intel-defined CPU features, CPUID level 0x00000001 (ecx) */
#define X86_FEATURE_XMM3         0 /* Streaming SIMD Extensions-3 */
#define X86_FEATURE_PCLMULQDQ    1 /* Carry-less multiplication */
#define X86_FEATURE_DTES64       2 /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT        3 /* Monitor/Mwait support */
#define X86_FEATURE_DSCPL        4 /* CPL Qualified Debug Store */
#define X86_FEATURE_VMXE         5 /* Virtual Machine Extensions */
#define X86_FEATURE_SMXE         6 /* Safer Mode Extensions */
#define X86_FEATURE_EST          7 /* Enhanced SpeedStep */
#define X86_FEATURE_TM2          8 /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3        9 /* Supplemental Streaming SIMD Exts-3 */
#define X86_FEATURE_CID         10 /* Context ID */
#define X86_FEATURE_FMA         12 /* Fused Multiply Add */
#define X86_FEATURE_CX16        13 /* CMPXCHG16B */
#define X86_FEATURE_XTPR        14 /* Send Task Priority Messages */
#define X86_FEATURE_PDCM        15 /* Perf/Debug Capability MSR */
#define X86_FEATURE_PCID        17 /* Process Context ID */
#define X86_FEATURE_DCA         18 /* Direct Cache Access */
#define X86_FEATURE_SSE4_1      19 /* Streaming SIMD Extensions 4.1 */
#define X86_FEATURE_SSE4_2      20 /* Streaming SIMD Extensions 4.2 */
#define X86_FEATURE_X2APIC      21 /* x2APIC */
#define X86_FEATURE_MOVBE       22 /* movbe instruction */
#define X86_FEATURE_POPCNT      23 /* POPCNT instruction */
#define X86_FEATURE_TSC_DEADLINE 24 /* "tdt" TSC Deadline Timer */
#define X86_FEATURE_AES         25 /* AES acceleration instructions */
#define X86_FEATURE_XSAVE       26 /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_AVX         28 /* Advanced Vector Extensions */
#define X86_FEATURE_F16C        29 /* Half-precision convert instruction */
#define X86_FEATURE_RDRAND      30 /* Digital Random Number Generator */
#define X86_FEATURE_HYPERVISOR  31 /* Running under some hypervisor */

/* VIA/Cyrix/Centaur-defined CPU features, CPUID level 0xC0000001 */
#define X86_FEATURE_XSTORE       2 /* on-CPU RNG present (xstore insn) */
#define X86_FEATURE_XSTORE_EN    3 /* on-CPU RNG enabled */
#define X86_FEATURE_XCRYPT       6 /* on-CPU crypto (xcrypt insn) */
#define X86_FEATURE_XCRYPT_EN    7 /* on-CPU crypto enabled */
#define X86_FEATURE_ACE2         8 /* Advanced Cryptography Engine v2 */
#define X86_FEATURE_ACE2_EN      9 /* ACE v2 enabled */
#define X86_FEATURE_PHE         10 /* PadLock Hash Engine */
#define X86_FEATURE_PHE_EN      11 /* PHE enabled */
#define X86_FEATURE_PMM         12 /* PadLock Montgomery Multiplier */
#define X86_FEATURE_PMM_EN      13 /* PMM enabled */

/* More extended AMD flags: CPUID level 0x80000001, ecx */
#define X86_FEATURE_LAHF_LM      0 /* LAHF/SAHF in long mode */
#define X86_FEATURE_CMP_LEGACY   1 /* If yes HyperThreading not valid */
#define X86_FEATURE_SVM          2 /* Secure virtual machine */
#define X86_FEATURE_EXTAPIC      3 /* Extended APIC space */
#define X86_FEATURE_CR8_LEGACY   4 /* CR8 in 32-bit mode */
#define X86_FEATURE_ABM          5 /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A        6 /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE  7 /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH 8 /* 3DNow prefetch instructions */
#define X86_FEATURE_OSVW         9 /* OS Visible Workaround */
#define X86_FEATURE_IBS         10 /* Instruction Based Sampling */
#define X86_FEATURE_XOP         11 /* extended AVX instructions */
#define X86_FEATURE_SKINIT      12 /* SKINIT/STGI instructions */
#define X86_FEATURE_WDT         13 /* Watchdog timer */
#define X86_FEATURE_LWP         15 /* Light Weight Profiling */
#define X86_FEATURE_FMA4        16 /* 4 operands MAC instructions */
#define X86_FEATURE_NODEID_MSR  19 /* NodeId MSR */
#define X86_FEATURE_TBM         21 /* trailing bit manipulations */
#define X86_FEATURE_TOPOEXT     22 /* topology extensions CPUID leafs */
#define X86_FEATURE_DBEXT       26 /* data breakpoint extension */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (ebx) */
#define X86_FEATURE_FSGSBASE     0 /* {RD,WR}{FS,GS}BASE instructions */
#define X86_FEATURE_TSC_ADJUST   1 /* Tsc thread offset */
#define X86_FEATURE_BMI1         3 /* 1st group bit manipulation extensions */
#define X86_FEATURE_HLE          4 /* Hardware Lock Elision */
#define X86_FEATURE_AVX2         5 /* AVX2 instructions */
#define X86_FEATURE_SMEP         7 /* Supervisor Mode Execution Protection */
#define X86_FEATURE_BMI2         8 /* 2nd group bit manipulation extensions */
#define X86_FEATURE_ERMS         9 /* Enhanced REP MOVSB/STOSB */
#define X86_FEATURE_INVPCID     10 /* Invalidate Process Context ID */
#define X86_FEATURE_RTM         11 /* Restricted Transactional Memory */
#define X86_FEATURE_RDSEED      18 /* RDSEED instruction */
#define X86_FEATURE_ADX         19 /* ADCX, ADOX instructions */
#define X86_FEATURE_SMAP        20 /* Supervisor Mode Access Protection */


#endif /* __LIBXC_CPUFEATURE_H */
