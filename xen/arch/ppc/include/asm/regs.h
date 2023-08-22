/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 */

#ifndef _ASM_REG_DEFS_H_
#define _ASM_REG_DEFS_H_

/* Special Purpose Registers */
#define SPRN_VRSAVE 256
#define SPRN_DSISR  18
#define SPRN_DAR    19
#define SPRN_DEC    22
#define SPRN_SRR0   26
#define SPRN_SRR1   27
#define SPRN_TBRL   268
#define SPRN_TBRU   269
#define SPRN_SPRG0  272
#define SPRN_SPRG1  273
#define SPRN_SPRG2  274
#define SPRN_SPRG3  275
#define SPRN_TBWL   284
#define SPRN_TBWU   285

#define SPRN_HSPRG0 304
#define SPRN_HSPRG1 305
#define SPRN_HDEC   310
#define SPRN_HIOR   311
#define SPRN_RMOR   312
#define SPRN_HRMOR  313
#define SPRN_HSRR0  314
#define SPRN_HSRR1  315
#define SPRN_LPIDR  319

#define SPRN_PTCR	0x1D0	/* Partition table control Register */
#define SPRN_PID	0x030	/* Process ID */

/* Performance monitor spr encodings */
#define SPRN_MMCRA  786
#define   MMCRA_SAMPHV    _AC(0x10000000, UL) /* state of MSR HV when SIAR set */
#define   MMCRA_SAMPPR    _AC(0x08000000, UL) /* state of MSR PR when SIAR set */
#define   MMCRA_SAMPLE_ENABLE _AC(0x00000001, UL) /* enable sampling */
#define NUM_PMCS 8
#define SPRN_PMC1   787
#define SPRN_PMC2   788
#define SPRN_PMC3   789
#define SPRN_PMC4   790
#define SPRN_PMC5   791
#define SPRN_PMC6   792
#define SPRN_PMC7   793
#define SPRN_PMC8   794
#define SPRN_MMCR0  795
#define   MMCR0_FC      _AC(0x80000000, UL) /* freeze counters */
#define   MMCR0_FCS     _AC(0x40000000, UL) /* freeze in supervisor state */
#define   MMCR0_FCP     _AC(0x20000000, UL) /* freeze in problem state */
#define   MMCR0_FCM1    _AC(0x10000000, UL) /* freeze counters while MSR mark = 1 */
#define   MMCR0_FCM0    _AC(0x08000000, UL) /* freeze counters while MSR mark = 0 */
#define   MMCR0_PMAE    _AC(0x04000000, UL) /* performance monitor alert enabled */
#define   MMCR0_PMAO    _AC(0x00000080, UL) /* performance monitor alert occurred */
#define   MMCR0_FCH     _AC(0x00000001, UL) /* freeze conditions in hypervisor */
#define SPRN_SIAR   796
#define SPRN_SDAR   797
#define SPRN_MMCR1  798

/* As defined for PU G4 */
#define SPRN_HID0   1008
#define SPRN_HID1   1009
#define SPRN_HID4   1012

#define SPRN_DABR   1013
#define SPRN_HID5   1014
#define SPRN_DABRX  1015
#define SPRN_HID6   1017
#define SPRN_HID7   1018
#define SPRN_HID8   1019
#define SPRN_PIR    1023

#define SPRN_LPCR	0x13E	/* LPAR Control Register */
#define   LPCR_VPM0		_AC(0x8000000000000000, UL)
#define   LPCR_VPM1		_AC(0x4000000000000000, UL)
#define   LPCR_ISL		_AC(0x2000000000000000, UL)
#define   LPCR_VC_SH		61
#define   LPCR_DPFD_SH		52
#define   LPCR_DPFD		(_AC(7, UL) << LPCR_DPFD_SH)
#define   LPCR_VRMASD_SH	47
#define   LPCR_VRMASD		(_AC(0x1f, UL) << LPCR_VRMASD_SH)
#define   LPCR_VRMA_L		_AC(0x0008000000000000, UL)
#define   LPCR_VRMA_LP0		_AC(0x0001000000000000, UL)
#define   LPCR_VRMA_LP1		_AC(0x0000800000000000, UL)
#define   LPCR_RMLS		0x1C000000	/* Implementation dependent RMO limit sel */
#define   LPCR_RMLS_SH		26
#define   LPCR_HAIL		_AC(0x0000000004000000, UL)   /* HV AIL (ISAv3.1) */
#define   LPCR_ILE		_AC(0x0000000002000000, UL)   /* !HV irqs set MSR:LE */
#define   LPCR_AIL		_AC(0x0000000001800000, UL)	/* Alternate interrupt location */
#define   LPCR_AIL_0		_AC(0x0000000000000000, UL)	/* MMU off exception offset 0x0 */
#define   LPCR_AIL_3		_AC(0x0000000001800000, UL)   /* MMU on exception offset 0xc00...4xxx */
#define   LPCR_ONL		_AC(0x0000000000040000, UL)	/* online - PURR/SPURR count */
#define   LPCR_LD		_AC(0x0000000000020000, UL)	/* large decremeter */
#define   LPCR_PECE		_AC(0x000000000001f000, UL)	/* powersave exit cause enable */
#define     LPCR_PECEDP	_AC(0x0000000000010000, UL)	/* directed priv dbells cause exit */
#define     LPCR_PECEDH	_AC(0x0000000000008000, UL)	/* directed hyp dbells cause exit */
#define     LPCR_PECE0		_AC(0x0000000000004000, UL)	/* ext. exceptions can cause exit */
#define     LPCR_PECE1		_AC(0x0000000000002000, UL)	/* decrementer can cause exit */
#define     LPCR_PECE2		_AC(0x0000000000001000, UL)	/* machine check etc can cause exit */
#define     LPCR_PECE_HVEE	_AC(0x0000400000000000, UL)	/* P9 Wakeup on HV interrupts */
#define   LPCR_MER		_AC(0x0000000000000800, UL)	/* Mediated External Exception */
#define   LPCR_MER_SH		11
#define	  LPCR_GTSE		_AC(0x0000000000000400, UL)  	/* Guest Translation Shootdown Enable */
#define   LPCR_TC		_AC(0x0000000000000200, UL)	/* Translation control */
#define   LPCR_HEIC		_AC(0x0000000000000010, UL)   /* Hypervisor External Interrupt Control */
#define   LPCR_LPES		0x0000000c
#define   LPCR_LPES0		_AC(0x0000000000000008, UL)      /* LPAR Env selector 0 */
#define   LPCR_LPES1		_AC(0x0000000000000004, UL)      /* LPAR Env selector 1 */
#define   LPCR_LPES_SH		2
#define   LPCR_RMI		_AC(0x0000000000000002, UL)      /* real mode is cache inhibit */
#define   LPCR_HVICE		_AC(0x0000000000000002, UL)      /* P9: HV interrupt enable */
#define   LPCR_HDICE		_AC(0x0000000000000001, UL)      /* Hyp Decr enable (HV,PR,EE) */
#define   LPCR_UPRT		_AC(0x0000000000400000, UL)      /* Use Process Table (ISA 3) */
#define   LPCR_HR		_AC(0x0000000000100000, UL)

#endif /* _ASM_REG_DEFS_H_ */
