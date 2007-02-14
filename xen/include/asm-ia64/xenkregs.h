#ifndef _ASM_IA64_XENKREGS_H
#define _ASM_IA64_XENKREGS_H

/*
 * Translation registers:
 */
#define IA64_TR_SHARED_INFO	3	/* dtr3: page shared with domain */
#define	IA64_TR_VHPT		4	/* dtr4: vhpt */
#define IA64_TR_MAPPED_REGS	5	/* dtr5: vcpu mapped regs */
#define IA64_DTR_GUEST_KERNEL   6
#define IA64_ITR_GUEST_KERNEL   2
/* Processor status register bits: */
#define IA64_PSR_VM_BIT		46
#define IA64_PSR_VM	(__IA64_UL(1) << IA64_PSR_VM_BIT)

#define IA64_DEFAULT_DCR_BITS	(IA64_DCR_PP | IA64_DCR_LC | IA64_DCR_DM | \
				 IA64_DCR_DP | IA64_DCR_DK | IA64_DCR_DX | \
				 IA64_DCR_DR | IA64_DCR_DA | IA64_DCR_DD)

/* Interruption Function State */
#define IA64_IFS_V_BIT		63
#define IA64_IFS_V	(__IA64_UL(1) << IA64_IFS_V_BIT)

/* Page Table Address */
#define IA64_PTA_VE_BIT 0
#define IA64_PTA_SIZE_BIT 2
#define IA64_PTA_VF_BIT 8
#define IA64_PTA_BASE_BIT 15

#define IA64_PTA_VE     (__IA64_UL(1) << IA64_PTA_VE_BIT)
#define IA64_PTA_SIZE   (__IA64_UL(0x3f) << IA64_PTA_SIZE_BIT)
#define IA64_PTA_VF     (__IA64_UL(1) << IA64_PTA_VF_BIT)
#define IA64_PTA_BASE   (__IA64_UL(0) - ((__IA64_UL(1) << IA64_PTA_BASE_BIT)))

#endif /* _ASM_IA64_XENKREGS_H */
