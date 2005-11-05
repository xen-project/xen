#ifndef IA64_INTRINSIC_H
#define IA64_INTRINSIC_H

/*
 * Compiler-dependent Intrinsics
 *
 * Copyright (C) 2002,2003 Jun Nakajima <jun.nakajima@intel.com>
 * Copyright (C) 2002,2003 Suresh Siddha <suresh.b.siddha@intel.com>
 *
 */
extern long ia64_cmpxchg_called_with_bad_pointer (void);
extern void ia64_bad_param_for_getreg (void);
#define ia64_cmpxchg(sem,ptr,o,n,s) ({					\
	uint64_t _o, _r;						\
	switch(s) {							\
		case 1: _o = (uint8_t)(long)(o); break;			\
		case 2: _o = (uint16_t)(long)(o); break;		\
		case 4: _o = (uint32_t)(long)(o); break;		\
		case 8: _o = (uint64_t)(long)(o); break;		\
		default: break;						\
	}								\
	switch(s) {							\
		case 1:							\
		_r = ia64_cmpxchg1_##sem((uint8_t*)ptr,n,_o); break;	\
		case 2:							\
		_r = ia64_cmpxchg2_##sem((uint16_t*)ptr,n,_o); break;	\
		case 4:							\
		_r = ia64_cmpxchg4_##sem((uint32_t*)ptr,n,_o); break;	\
		case 8:							\
		_r = ia64_cmpxchg8_##sem((uint64_t*)ptr,n,_o); break;	\
		default:						\
		_r = ia64_cmpxchg_called_with_bad_pointer(); break;	\
	}								\
	(__typeof__(o)) _r;						\
})

#define cmpxchg_acq(ptr,o,n) ia64_cmpxchg(acq,ptr,o,n,sizeof(*ptr))
#define cmpxchg_rel(ptr,o,n) ia64_cmpxchg(rel,ptr,o,n,sizeof(*ptr))

/*
 * Register Names for getreg() and setreg().
 *
 * The "magic" numbers happen to match the values used by the Intel compiler's
 * getreg()/setreg() intrinsics.
 */

/* Special Registers */

#define _IA64_REG_IP		1016	/* getreg only */
#define _IA64_REG_PSR		1019
#define _IA64_REG_PSR_L		1019

/* General Integer Registers */

#define _IA64_REG_GP		1025	/* R1 */
#define _IA64_REG_R8		1032	/* R8 */
#define _IA64_REG_R9		1033	/* R9 */
#define _IA64_REG_SP		1036	/* R12 */
#define _IA64_REG_TP		1037	/* R13 */

/* Application Registers */

#define _IA64_REG_AR_KR0	3072
#define _IA64_REG_AR_KR1	3073
#define _IA64_REG_AR_KR2	3074
#define _IA64_REG_AR_KR3	3075
#define _IA64_REG_AR_KR4	3076
#define _IA64_REG_AR_KR5	3077
#define _IA64_REG_AR_KR6	3078
#define _IA64_REG_AR_KR7	3079
#define _IA64_REG_AR_RSC	3088
#define _IA64_REG_AR_BSP	3089
#define _IA64_REG_AR_BSPSTORE	3090
#define _IA64_REG_AR_RNAT	3091
#define _IA64_REG_AR_FCR	3093
#define _IA64_REG_AR_EFLAG	3096
#define _IA64_REG_AR_CSD	3097
#define _IA64_REG_AR_SSD	3098
#define _IA64_REG_AR_CFLAG	3099
#define _IA64_REG_AR_FSR	3100
#define _IA64_REG_AR_FIR	3101
#define _IA64_REG_AR_FDR	3102
#define _IA64_REG_AR_CCV	3104
#define _IA64_REG_AR_UNAT	3108
#define _IA64_REG_AR_FPSR	3112
#define _IA64_REG_AR_ITC	3116
#define _IA64_REG_AR_PFS	3136
#define _IA64_REG_AR_LC		3137
#define _IA64_REG_AR_EC		3138

/* Control Registers */

#define _IA64_REG_CR_DCR	4096
#define _IA64_REG_CR_ITM	4097
#define _IA64_REG_CR_IVA	4098
#define _IA64_REG_CR_PTA	4104
#define _IA64_REG_CR_IPSR	4112
#define _IA64_REG_CR_ISR	4113
#define _IA64_REG_CR_IIP	4115
#define _IA64_REG_CR_IFA	4116
#define _IA64_REG_CR_ITIR	4117
#define _IA64_REG_CR_IIPA	4118
#define _IA64_REG_CR_IFS	4119
#define _IA64_REG_CR_IIM	4120
#define _IA64_REG_CR_IHA	4121
#define _IA64_REG_CR_LID	4160
#define _IA64_REG_CR_IVR	4161	/* getreg only */
#define _IA64_REG_CR_TPR	4162
#define _IA64_REG_CR_EOI	4163
#define _IA64_REG_CR_IRR0	4164	/* getreg only */
#define _IA64_REG_CR_IRR1	4165	/* getreg only */
#define _IA64_REG_CR_IRR2	4166	/* getreg only */
#define _IA64_REG_CR_IRR3	4167	/* getreg only */
#define _IA64_REG_CR_ITV	4168
#define _IA64_REG_CR_PMV	4169
#define _IA64_REG_CR_CMCV	4170
#define _IA64_REG_CR_LRR0	4176
#define _IA64_REG_CR_LRR1	4177

/* Indirect Registers for getindreg() and setindreg() */

#define _IA64_REG_INDR_CPUID	9000	/* getindreg only */
#define _IA64_REG_INDR_DBR	9001
#define _IA64_REG_INDR_IBR	9002
#define _IA64_REG_INDR_PKR	9003
#define _IA64_REG_INDR_PMC	9004
#define _IA64_REG_INDR_PMD	9005
#define _IA64_REG_INDR_RR	9006

#ifdef __INTEL_COMPILER
void  __fc(uint64_t *addr);
void  __synci(void);
void __isrlz(void);
void __dsrlz(void);
uint64_t __getReg(const int whichReg);
uint64_t _InterlockedCompareExchange8_rel(volatile uint8_t *dest, uint64_t xchg, uint64_t comp);
uint64_t _InterlockedCompareExchange8_acq(volatile uint8_t *dest, uint64_t xchg, uint64_t comp);
uint64_t _InterlockedCompareExchange16_rel(volatile uint16_t *dest, uint64_t xchg, uint64_t comp);
uint64_t _InterlockedCompareExchange16_acq(volatile uint16_t *dest, uint64_t xchg, uint64_t comp);
uint64_t _InterlockedCompareExchange_rel(volatile uint32_t *dest, uint64_t xchg, uint64_t comp);
uint64_t _InterlockedCompareExchange_acq(volatile uint32_t *dest, uint64_t xchg, uint64_t comp);
uint64_t _InterlockedCompareExchange64_rel(volatile uint64_t *dest, uint64_t xchg, uint64_t comp);
u64_t _InterlockedCompareExchange64_acq(volatile uint64_t *dest, uint64_t xchg, uint64_t comp);

#define ia64_cmpxchg1_rel	_InterlockedCompareExchange8_rel
#define ia64_cmpxchg1_acq	_InterlockedCompareExchange8_acq
#define ia64_cmpxchg2_rel	_InterlockedCompareExchange16_rel
#define ia64_cmpxchg2_acq	_InterlockedCompareExchange16_acq
#define ia64_cmpxchg4_rel	_InterlockedCompareExchange_rel
#define ia64_cmpxchg4_acq	_InterlockedCompareExchange_acq
#define ia64_cmpxchg8_rel	_InterlockedCompareExchange64_rel
#define ia64_cmpxchg8_acq	_InterlockedCompareExchange64_acq

#define ia64_srlz_d		__dsrlz
#define ia64_srlz_i		__isrlz
#define __ia64_fc 		__fc
#define ia64_sync_i		__synci
#define __ia64_getreg		__getReg
#else /* __INTEL_COMPILER */
#define ia64_cmpxchg1_acq(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
	asm volatile ("cmpxchg1.acq %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg1_rel(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
	asm volatile ("cmpxchg1.rel %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg2_acq(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
	asm volatile ("cmpxchg2.acq %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg2_rel(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
											\
	asm volatile ("cmpxchg2.rel %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg4_acq(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
	asm volatile ("cmpxchg4.acq %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg4_rel(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
	asm volatile ("cmpxchg4.rel %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg8_acq(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
	asm volatile ("cmpxchg8.acq %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_cmpxchg8_rel(ptr, new, old)						\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));					\
											\
	asm volatile ("cmpxchg8.rel %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

#define ia64_srlz_i()	asm volatile (";; srlz.i ;;" ::: "memory")
#define ia64_srlz_d()	asm volatile (";; srlz.d" ::: "memory");
#define __ia64_fc(addr)	asm volatile ("fc %0" :: "r"(addr) : "memory")
#define ia64_sync_i()	asm volatile (";; sync.i" ::: "memory")

#define __ia64_getreg(regnum)							\
({										\
	uint64_t ia64_intri_res;							\
										\
	switch (regnum) {							\
	case _IA64_REG_GP:							\
		asm volatile ("mov %0=gp" : "=r"(ia64_intri_res));		\
		break;								\
	case _IA64_REG_IP:							\
		asm volatile ("mov %0=ip" : "=r"(ia64_intri_res));		\
		break;								\
	case _IA64_REG_PSR:							\
		asm volatile ("mov %0=psr" : "=r"(ia64_intri_res));		\
		break;								\
	case _IA64_REG_TP:	/* for current() */				\
		ia64_intri_res = ia64_r13;					\
		break;								\
	case _IA64_REG_AR_KR0 ... _IA64_REG_AR_EC:				\
		asm volatile ("mov %0=ar%1" : "=r" (ia64_intri_res)		\
				      : "i"(regnum - _IA64_REG_AR_KR0));	\
		break;								\
	case _IA64_REG_CR_DCR ... _IA64_REG_CR_LRR1:				\
		asm volatile ("mov %0=cr%1" : "=r" (ia64_intri_res)		\
				      : "i" (regnum - _IA64_REG_CR_DCR));	\
		break;								\
	case _IA64_REG_SP:							\
		asm volatile ("mov %0=sp" : "=r" (ia64_intri_res));		\
		break;								\
	default:								\
		ia64_bad_param_for_getreg();					\
		break;								\
	}									\
	ia64_intri_res;								\
})

#endif /* __INTEL_COMPILER */
#endif /* IA64_INTRINSIC_H */
