#ifndef __ASM_MSR_H
#define __ASM_MSR_H

#define rdmsr(msr,val1,val2) \
     __asm__ __volatile__("rdmsr" \
			  : "=a" (val1), "=d" (val2) \
			  : "c" (msr))

#define rdmsrl(msr,val) do { unsigned long a__,b__; \
       __asm__ __volatile__("rdmsr" \
			    : "=a" (a__), "=d" (b__) \
			    : "c" (msr)); \
       val = a__ | (b__<<32); \
} while(0); 

#define wrmsr(msr,val1,val2) \
     __asm__ __volatile__("wrmsr" \
			  : /* no outputs */ \
			  : "c" (msr), "a" (val1), "d" (val2))

#define rdmsr_user(msr,val1,val2) ({\
    int _rc; \
    __asm__ __volatile__( \
        "1: rdmsr\n2:\n" \
        ".section .fixup,\"ax\"\n" \
        "3: movl $1,%2\n; jmp 2b\n" \
        ".previous\n" \
        ".section __ex_table,\"a\"\n" \
        "   "__FIXUP_ALIGN"\n" \
        "   "__FIXUP_WORD" 1b,3b\n" \
        ".previous\n" \
        : "=a" (val1), "=d" (val2), "=&r" (_rc) \
        : "c" (msr), "2" (0)); \
    _rc; })

#define wrmsr_user(msr,val1,val2) ({\
    int _rc; \
    __asm__ __volatile__( \
        "1: wrmsr\n2:\n" \
        ".section .fixup,\"ax\"\n" \
        "3: movl $1,%0\n; jmp 2b\n" \
        ".previous\n" \
        ".section __ex_table,\"a\"\n" \
        "   "__FIXUP_ALIGN"\n" \
        "   "__FIXUP_WORD" 1b,3b\n" \
        ".previous\n" \
        : "=&r" (_rc) \
        : "c" (msr), "a" (val1), "d" (val2), "0" (0)); \
    _rc; })

#define rdtsc(low,high) \
     __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))

#define rdtscl(low) \
     __asm__ __volatile__("rdtsc" : "=a" (low) : : "edx")

#if defined(__i386__)
#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))
#elif defined(__x86_64__)
#define rdtscll(val) do { \
     unsigned int a,d; \
     asm volatile("rdtsc" : "=a" (a), "=d" (d)); \
     (val) = ((unsigned long)a) | (((unsigned long)d)<<32); \
} while(0)
#endif

#define write_tsc(val1,val2) wrmsr(0x10, val1, val2)

#define rdpmc(counter,low,high) \
     __asm__ __volatile__("rdpmc" \
			  : "=a" (low), "=d" (high) \
			  : "c" (counter))

/* symbolic names for some interesting MSRs */
/* Intel defined MSRs. */
#define MSR_IA32_P5_MC_ADDR		0
#define MSR_IA32_P5_MC_TYPE		1
#define MSR_IA32_PLATFORM_ID		0x17
#define MSR_IA32_EBL_CR_POWERON		0x2a

/* AMD/K8 specific MSRs */ 
#define MSR_EFER 0xc0000080		/* extended feature register */
#define MSR_STAR 0xc0000081		/* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082 		/* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083		/* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084	/* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100		/* 64bit GS base */
#define MSR_GS_BASE 0xc0000101		/* 64bit FS base */
#define MSR_SHADOW_GS_BASE  0xc0000102	/* SwapGS GS shadow */ 
/* EFER bits: */ 
#define _EFER_SCE 0  /* SYSCALL/SYSRET */
#define _EFER_LME 8  /* Long mode enable */
#define _EFER_LMA 10 /* Long mode active (read-only) */
#define _EFER_NX 11  /* No execute enable */

#define EFER_SCE (1<<_EFER_SCE)
#define EFER_LME (1<<_EFER_LME)
#define EFER_LMA (1<<_EFER_LMA)
#define EFER_NX (1<<_EFER_NX)

/* Intel MSRs. Some also available on other CPUs */
#define MSR_IA32_PLATFORM_ID	0x17

#define MSR_IA32_PERFCTR0      0xc1
#define MSR_IA32_PERFCTR1      0xc2

#define MSR_MTRRcap		0x0fe
#define MSR_IA32_BBL_CR_CTL        0x119

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176

#define MSR_IA32_MCG_CAP       0x179
#define MSR_IA32_MCG_STATUS        0x17a
#define MSR_IA32_MCG_CTL       0x17b

#define MSR_IA32_EVNTSEL0      0x186
#define MSR_IA32_EVNTSEL1      0x187

#define MSR_MTRRfix64K_00000	0x250
#define MSR_MTRRfix16K_80000	0x258
#define MSR_MTRRfix16K_A0000	0x259
#define MSR_MTRRfix4K_C0000	0x268
#define MSR_MTRRfix4K_C8000	0x269
#define MSR_MTRRfix4K_D0000	0x26a
#define MSR_MTRRfix4K_D8000	0x26b
#define MSR_MTRRfix4K_E0000	0x26c
#define MSR_MTRRfix4K_E8000	0x26d
#define MSR_MTRRfix4K_F0000	0x26e
#define MSR_MTRRfix4K_F8000	0x26f
#define MSR_MTRRdefType		0x2ff

#define MSR_IA32_MC0_CTL       0x400
#define MSR_IA32_MC0_STATUS        0x401
#define MSR_IA32_MC0_ADDR      0x402
#define MSR_IA32_MC0_MISC      0x403

#define MSR_IA32_DS_AREA	0x600

#define MSR_IA32_APICBASE		0x1b
#define MSR_IA32_APICBASE_BSP		(1<<8)
#define MSR_IA32_APICBASE_ENABLE	(1<<11)
#define MSR_IA32_APICBASE_BASE		(0xfffff<<12)

#define MSR_IA32_UCODE_WRITE		0x79
#define MSR_IA32_UCODE_REV		0x8b

#define MSR_IA32_BBL_CR_CTL		0x119

#define MSR_IA32_MCG_CAP		0x179
#define MSR_IA32_MCG_STATUS		0x17a
#define MSR_IA32_MCG_CTL		0x17b

#define MSR_IA32_THERM_CONTROL		0x19a
#define MSR_IA32_THERM_INTERRUPT	0x19b
#define MSR_IA32_THERM_STATUS		0x19c
#define MSR_IA32_MISC_ENABLE		0x1a0

#define MSR_IA32_MISC_ENABLE_PERF_AVAIL   (1<<7)
#define MSR_IA32_MISC_ENABLE_BTS_UNAVAIL  (1<<11)
#define MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL (1<<12)

#define MSR_IA32_DEBUGCTLMSR		0x1d9
#define MSR_IA32_DEBUGCTLMSR_LBR        (1<<0)
#define MSR_IA32_DEBUGCTLMSR_BTF        (1<<1)
#define MSR_IA32_DEBUGCTLMSR_TR		(1<<2)
#define MSR_IA32_DEBUGCTLMSR_BTS        (1<<3)
#define MSR_IA32_DEBUGCTLMSR_BTINT      (1<<4)

#define MSR_IA32_LASTBRANCH_TOS         0x1da
#define MSR_IA32_LASTBRANCH_0		0x1db
#define MSR_IA32_LASTBRANCH_1		0x1dc
#define MSR_IA32_LASTBRANCH_2		0x1dd
#define MSR_IA32_LASTBRANCH_3		0x1de

#define MSR_IA32_MC0_CTL		0x400
#define MSR_IA32_MC0_STATUS		0x401
#define MSR_IA32_MC0_ADDR		0x402
#define MSR_IA32_MC0_MISC		0x403

#define MSR_P6_PERFCTR0			0xc1
#define MSR_P6_PERFCTR1			0xc2
#define MSR_P6_EVNTSEL0			0x186
#define MSR_P6_EVNTSEL1			0x187


/* K7/K8 MSRs. Not complete. See the architecture manual for a more complete list. */
#define MSR_K7_EVNTSEL0            0xC0010000
#define MSR_K7_PERFCTR0            0xC0010004
#define MSR_K7_EVNTSEL1            0xC0010001
#define MSR_K7_PERFCTR1            0xC0010005
#define MSR_K7_EVNTSEL2            0xC0010002
#define MSR_K7_PERFCTR2            0xC0010006
#define MSR_K7_EVNTSEL3            0xC0010003
#define MSR_K7_PERFCTR3            0xC0010007
#define MSR_K8_TOP_MEM1		   0xC001001A
#define MSR_K8_TOP_MEM2		   0xC001001D
#define MSR_K8_SYSCFG		   0xC0000010	
#define MSR_K7_HWCR			0xC0010015
#define MSR_K7_CLK_CTL			0xC001001b
#define MSR_K7_FID_VID_CTL		0xC0010041
#define MSR_K7_VID_STATUS		0xC0010042

/* K6 MSRs */
#define MSR_K6_EFER			0xC0000080
#define MSR_K6_STAR			0xC0000081
#define MSR_K6_WHCR			0xC0000082
#define MSR_K6_UWCCR			0xC0000085
#define MSR_K6_EPMR			0xC0000086
#define MSR_K6_PSOR			0xC0000087
#define MSR_K6_PFIR			0xC0000088

/* Centaur-Hauls/IDT defined MSRs. */
#define MSR_IDT_FCR1			0x107
#define MSR_IDT_FCR2			0x108
#define MSR_IDT_FCR3			0x109
#define MSR_IDT_FCR4			0x10a

#define MSR_IDT_MCR0			0x110
#define MSR_IDT_MCR1			0x111
#define MSR_IDT_MCR2			0x112
#define MSR_IDT_MCR3			0x113
#define MSR_IDT_MCR4			0x114
#define MSR_IDT_MCR5			0x115
#define MSR_IDT_MCR6			0x116
#define MSR_IDT_MCR7			0x117
#define MSR_IDT_MCR_CTRL		0x120

/* VIA Cyrix defined MSRs*/
#define MSR_VIA_FCR			0x1107
#define MSR_VIA_LONGHAUL		0x110a
#define MSR_VIA_BCR2			0x1147

/* Transmeta defined MSRs */
#define MSR_TMTA_LONGRUN_CTRL		0x80868010
#define MSR_TMTA_LONGRUN_FLAGS		0x80868011
#define MSR_TMTA_LRTI_READOUT		0x80868018
#define MSR_TMTA_LRTI_VOLT_MHZ		0x8086801a

#endif /* __ASM_MSR_H */
