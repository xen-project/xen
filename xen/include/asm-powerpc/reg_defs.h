/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 */

#ifndef _ASM_REG_DEFS_H_
#define _ASM_REG_DEFS_H_

#ifdef __ASSEMBLY__
/* Condition Register Bit Fields */

#define cr0 0
#define cr1 1
#define cr2 2
#define cr3 3
#define cr4 4
#define cr5 5
#define cr6 6
#define cr7 7


/* General Purpose Registers (GPRs) */

#define r0  0
#define r1  1
#define r2  2
#define r3  3
#define r4  4
#define r5  5
#define r6  6
#define r7  7
#define r8  8
#define r9  9
#define r10 10
#define r11 11
#define r12 12
#define r13 13
#define r14 14
#define r15 15
#define r16 16
#define r17 17
#define r18 18
#define r19 19
#define r20 20
#define r21 21
#define r22 22
#define r23 23
#define r24 24
#define r25 25
#define r26 26
#define r27 27
#define r28 28
#define r29 29
#define r30 30
#define r31 31

/* Floating Point Registers (FPRs) */
#define fr0     0
#define fr1     1
#define fr2     2
#define fr3     3
#define fr4     4
#define fr5     5
#define fr6     6
#define fr7     7
#define fr8     8
#define fr9     9
#define fr10    10
#define fr11    11
#define fr12    12
#define fr13    13
#define fr14    14
#define fr15    15
#define fr16    16
#define fr17    17
#define fr18    18
#define fr19    19
#define fr20    20
#define fr21    21
#define fr22    22
#define fr23    23
#define fr24    24
#define fr25    25
#define fr26    26
#define fr27    27
#define fr28    28
#define fr29    29
#define fr30    30
#define fr31    31

/* Vector Registers (FPRs) */
#define vr0     0
#define vr1     1
#define vr2     2
#define vr3     3
#define vr4     4
#define vr5     5
#define vr6     6
#define vr7     7
#define vr8     8
#define vr9     9
#define vr10    10
#define vr11    11
#define vr12    12
#define vr13    13
#define vr14    14
#define vr15    15
#define vr16    16
#define vr17    17
#define vr18    18
#define vr19    19
#define vr20    20
#define vr21    21
#define vr22    22
#define vr23    23
#define vr24    24
#define vr25    25
#define vr26    26
#define vr27    27
#define vr28    28
#define vr29    29
#define vr30    30
#define vr31    31

#endif

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
#define SPRN_LPCR   318
#define SPRN_LPIDR  319

/* Performance monitor spr encodings */
#define SPRN_MMCRA  786
#define   MMCRA_SAMPHV    UL(0x10000000) /* state of MSR HV when SIAR set */
#define   MMCRA_SAMPPR    UL(0x08000000) /* state of MSR PR when SIAR set */
#define   MMCRA_SAMPLE_ENABLE UL(0x00000001) /* enable sampling */
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
#define   MMCR0_FC      UL(0x80000000) /* freeze counters */
#define   MMCR0_FCS     UL(0x40000000) /* freeze in supervisor state */
#define   MMCR0_FCP     UL(0x20000000) /* freeze in problem state */
#define   MMCR0_FCM1    UL(0x10000000) /* freeze counters while MSR mark = 1 */
#define   MMCR0_FCM0    UL(0x08000000) /* freeze counters while MSR mark = 0 */
#define   MMCR0_PMAE    UL(0x04000000) /* performance monitor alert enabled */
#define   MMCR0_PMAO    UL(0x00000080) /* performance monitor alert occurred */
#define   MMCR0_FCH     UL(0x00000001) /* freeze conditions in hypervisor */
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

#endif /* _ASM_REG_DEFS_H_ */
