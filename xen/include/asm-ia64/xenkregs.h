#ifndef _ASM_IA64_XENKREGS_H
#define _ASM_IA64_XENKREGS_H

/*
 * Translation registers:
 */
#define IA64_TR_SHARED_INFO	3	/* dtr3: page shared with domain */
#define	IA64_TR_VHPT		4	/* dtr4: vhpt */
#define IA64_TR_ARCH_INFO      5

#ifdef CONFIG_VTI
#define IA64_TR_VHPT_IN_DOM	5	/* dtr5: Double mapping for vhpt table in domain space */
#define IA64_TR_XEN_IN_DOM	6	/* itr6, dtr6: Double mapping for xen image in domain space */
#define IA64_TR_RR7_SWITCH_STUB	7	/* dtr7: mapping for rr7 switch stub */
#define IA64_TEMP_PHYSICAL	8	/* itr8, dtr8: temp mapping for guest physical memory 256M */
#endif // CONFIG_VTI

/* Processor status register bits: */
#define IA64_PSR_VM_BIT		46
#define IA64_PSR_VM	(__IA64_UL(1) << IA64_PSR_VM_BIT)

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
