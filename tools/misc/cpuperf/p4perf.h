/*
 * P4 Performance counter stuff.
 *
 * P4 Xeon with Hyperthreading has counters per physical package which can
 * count events from either logical CPU. However, in many cases more than
 * ECSR and CCCR/counter can be used to count the same event. For instr or
 * uops retired, use either ESCR0/IQ_CCCR0 ESCR1/IQ_CCCR2.
 *
 * $Id: p4perf.h,v 1.2 2003/10/13 16:51:41 jrb44 Exp $
 *
 * $Log: p4perf.h,v $
 * Revision 1.2  2003/10/13 16:51:41  jrb44
 * *** empty log message ***
 *
 */

#ifndef P4PERF_H
#define P4PERF_H

#ifdef __KERNEL__
#include <asm/msr.h>
#endif

/*****************************************************************************
 * Performance counter configuration.                                        *
 *****************************************************************************/

#ifndef P6_EVNTSEL_OS
# define P6_EVNTSEL_OS     (1 << 17)
# define P6_EVNTSEL_USR    (1 << 16)
# define P6_EVNTSEL_E      (1 << 18)
# define P6_EVNTSEL_EN     (1 << 22)
#endif
#define P6_PERF_INST_RETIRED 0xc0
#define P6_PERF_UOPS_RETIRED 0xc2

#define P4_ESCR_USR                    (1 << 2)
#define P4_ESCR_OS                     (1 << 3)
#define P4_ESCR_T0_USR                 (1 << 2) /* First logical CPU  */
#define P4_ESCR_T0_OS                  (1 << 3)
#define P4_ESCR_T1_USR                 (1 << 0) /* Second logical CPU */
#define P4_ESCR_T1_OS                  (1 << 1)
#define P4_ESCR_TE                     (1 << 4)
#define P4_ESCR_THREADS(t)             (t)
#define P4_ESCR_TV(tag)                (tag << 5)
#define P4_ESCR_EVNTSEL(e)             (e << 25)
#define P4_ESCR_EVNTMASK(e)            (e << 9)

#define P4_ESCR_EVNTSEL_FRONT_END      0x08
#define P4_ESCR_EVNTSEL_EXECUTION      0x0c
#define P4_ESCR_EVNTSEL_REPLAY         0x09
#define P4_ESCR_EVNTSEL_INSTR_RETIRED  0x02
#define P4_ESCR_EVNTSEL_UOPS_RETIRED   0x01
#define P4_ESCR_EVNTSEL_UOP_TYPE       0x02
#define P4_ESCR_EVNTSEL_RET_MBR_TYPE   0x05
//#define P4_ESCR_EVNTSEL_RET_MBR_TYPE   0x04

#define P4_ESCR_EVNTMASK_FE_NBOGUS     0x01
#define P4_ESCR_EVNTMASK_FE_BOGUS      0x02

#define P4_ESCR_EVNTMASK_EXEC_NBOGUS0  0x01
#define P4_ESCR_EVNTMASK_EXEC_NBOGUS1  0x02
#define P4_ESCR_EVNTMASK_EXEC_NBOGUS2  0x04
#define P4_ESCR_EVNTMASK_EXEC_NBOGUS3  0x08
#define P4_ESCR_EVNTMASK_EXEC_BOGUS0   0x10
#define P4_ESCR_EVNTMASK_EXEC_BOGUS1   0x20
#define P4_ESCR_EVNTMASK_EXEC_BOGUS2   0x40
#define P4_ESCR_EVNTMASK_EXEC_BOGUS3   0x80

#define P4_ESCR_EVNTMASK_REPLAY_NBOGUS 0x01
#define P4_ESCR_EVNTMASK_REPLAY_BOGUS  0x02

#define P4_ESCR_EVNTMASK_IRET_NB_NTAG  0x01
#define P4_ESCR_EVNTMASK_IRET_NB_TAG   0x02
#define P4_ESCR_EVNTMASK_IRET_B_NTAG   0x04
#define P4_ESCR_EVNTMASK_IRET_B_TAG    0x08

#define P4_ESCR_EVNTMASK_URET_NBOGUS   0x01
#define P4_ESCR_EVNTMASK_URET_BOGUS    0x02

#define P4_ESCR_EVNTMASK_UOP_LOADS     0x02
#define P4_ESCR_EVNTMASK_UOP_STORES    0x04

#define P4_ESCR_EVNTMASK_RMBRT_COND    0x02
#define P4_ESCR_EVNTMASK_RMBRT_CALL    0x04
#define P4_ESCR_EVNTMASK_RMBRT_RETURN  0x08
#define P4_ESCR_EVNTMASK_RMBRT_INDIR   0x10

#define P4_ESCR_EVNTMASK_RBRT_COND     0x02
#define P4_ESCR_EVNTMASK_RBRT_CALL     0x04
#define P4_ESCR_EVNTMASK_RBRT_RETURN   0x08
#define P4_ESCR_EVNTMASK_RBRT_INDIR    0x10

//#define P4_ESCR_EVNTMASK_INSTR_RETIRED 0x01  /* Non bogus, not tagged */
//#define P4_ESCR_EVNTMASK_UOPS_RETIRED  0x01  /* Non bogus             */

#define P4_CCCR_OVF                    (1 << 31)
#define P4_CCCR_CASCADE                (1 << 30)
#define P4_CCCR_FORCE_OVF              (1 << 25)
#define P4_CCCR_EDGE                   (1 << 24)
#define P4_CCCR_COMPLEMENT             (1 << 19)
#define P4_CCCR_COMPARE                (1 << 18)
#define P4_CCCR_THRESHOLD(t)           (t << 20)
#define P4_CCCR_ENABLE                 (1 << 12)
#define P4_CCCR_ESCR(escr)             (escr << 13)
#define P4_CCCR_ACTIVE_THREAD(t)       (t << 16)   /* Set to 11 */
#define P4_CCCR_OVF_PMI_T0             (1 << 26)
#define P4_CCCR_OVF_PMI_T1             (1 << 27)
#define P4_CCCR_RESERVED               (3 << 16)
#define P4_CCCR_OVF_PMI                (1 << 26)

// BPU
#define MSR_P4_BPU_COUNTER0            0x300
#define MSR_P4_BPU_COUNTER1            0x301
#define MSR_P4_BPU_CCCR0               0x360
#define MSR_P4_BPU_CCCR1               0x361

#define MSR_P4_BPU_COUNTER2            0x302
#define MSR_P4_BPU_COUNTER3            0x303
#define MSR_P4_BPU_CCCR2               0x362
#define MSR_P4_BPU_CCCR3               0x363

#define MSR_P4_BSU_ESCR0               0x3a0
#define MSR_P4_FSB_ESCR0               0x3a2
#define MSR_P4_MOB_ESCR0               0x3aa
#define MSR_P4_PMH_ESCR0               0x3ac
#define MSR_P4_BPU_ESCR0               0x3b2
#define MSR_P4_IS_ESCR0                0x3b4
#define MSR_P4_ITLB_ESCR0              0x3b6
#define MSR_P4_IX_ESCR0                0x3c8

#define P4_BSU_ESCR0_NUMBER            7
#define P4_FSB_ESCR0_NUMBER            6
#define P4_MOB_ESCR0_NUMBER            2
#define P4_PMH_ESCR0_NUMBER            4
#define P4_BPU_ESCR0_NUMBER            0
#define P4_IS_ESCR0_NUMBER             1
#define P4_ITLB_ESCR0_NUMBER           3
#define P4_IX_ESCR0_NUMBER             5

#define MSR_P4_BSU_ESCR1               0x3a1
#define MSR_P4_FSB_ESCR1               0x3a3
#define MSR_P4_MOB_ESCR1               0x3ab
#define MSR_P4_PMH_ESCR1               0x3ad
#define MSR_P4_BPU_ESCR1               0x3b3
#define MSR_P4_IS_ESCR1                0x3b5
#define MSR_P4_ITLB_ESCR1              0x3b7
#define MSR_P4_IX_ESCR1                0x3c9

#define P4_BSU_ESCR1_NUMBER            7
#define P4_FSB_ESCR1_NUMBER            6
#define P4_MOB_ESCR1_NUMBER            2
#define P4_PMH_ESCR1_NUMBER            4
#define P4_BPU_ESCR1_NUMBER            0
#define P4_IS_ESCR1_NUMBER             1
#define P4_ITLB_ESCR1_NUMBER           3
#define P4_IX_ESCR1_NUMBER             5

// MS
#define MSR_P4_MS_COUNTER0             0x304
#define MSR_P4_MS_COUNTER1             0x305
#define MSR_P4_MS_CCCR0                0x364
#define MSR_P4_MS_CCCR1                0x365

#define MSR_P4_MS_COUNTER2             0x306
#define MSR_P4_MS_COUNTER3             0x307
#define MSR_P4_MS_CCCR2                0x366
#define MSR_P4_MS_CCCR3                0x367

#define MSR_P4_MS_ESCR0                0x3c0
#define MSR_P4_TBPU_ESCR0              0x3c2
#define MSR_P4_TC_ESCR0                0x3c4

#define P4_MS_ESCR0_NUMBER             0
#define P4_TBPU_ESCR0_NUMBER           2
#define P4_TC_ESCR0_NUMBER             1

#define MSR_P4_MS_ESCR1                0x3c1
#define MSR_P4_TBPU_ESCR1              0x3c3
#define MSR_P4_TC_ESCR1                0x3c5

#define P4_MS_ESCR1_NUMBER             0
#define P4_TBPU_ESCR1_NUMBER           2
#define P4_TC_ESCR1_NUMBER             1

// FLAME
#define MSR_P4_FLAME_COUNTER0          0x308
#define MSR_P4_FLAME_COUNTER1          0x309
#define MSR_P4_FLAME_CCCR0             0x368
#define MSR_P4_FLAME_CCCR1             0x369

#define MSR_P4_FLAME_COUNTER2          0x30a
#define MSR_P4_FLAME_COUNTER3          0x30b
#define MSR_P4_FLAME_CCCR2             0x36a
#define MSR_P4_FLAME_CCCR3             0x36b

#define MSR_P4_FIRM_ESCR0              0x3a4
#define MSR_P4_FLAME_ESCR0             0x3a6
#define MSR_P4_DAC_ESCR0               0x3a8
#define MSR_P4_SAAT_ESCR0              0x3ae
#define MSR_P4_U2L_ESCR0               0x3b0

#define P4_FIRM_ESCR0_NUMBER           1
#define P4_FLAME_ESCR0_NUMBER          0
#define P4_DAC_ESCR0_NUMBER            5
#define P4_SAAT_ESCR0_NUMBER           2
#define P4_U2L_ESCR0_NUMBER            3

#define MSR_P4_FIRM_ESCR1              0x3a5
#define MSR_P4_FLAME_ESCR1             0x3a7
#define MSR_P4_DAC_ESCR1               0x3a9
#define MSR_P4_SAAT_ESCR1              0x3af
#define MSR_P4_U2L_ESCR1               0x3b1

#define P4_FIRM_ESCR1_NUMBER           1
#define P4_FLAME_ESCR1_NUMBER          0
#define P4_DAC_ESCR1_NUMBER            5
#define P4_SAAT_ESCR1_NUMBER           2
#define P4_U2L_ESCR1_NUMBER            3

// IQ
#define MSR_P4_IQ_COUNTER0             0x30c
#define MSR_P4_IQ_COUNTER1             0x30d
#define MSR_P4_IQ_CCCR0                0x36c
#define MSR_P4_IQ_CCCR1                0x36d

#define MSR_P4_IQ_COUNTER2             0x30e
#define MSR_P4_IQ_COUNTER3             0x30f
#define MSR_P4_IQ_CCCR2                0x36e
#define MSR_P4_IQ_CCCR3                0x36f

#define MSR_P4_IQ_COUNTER4             0x310
#define MSR_P4_IQ_COUNTER5             0x311
#define MSR_P4_IQ_CCCR4                0x370
#define MSR_P4_IQ_CCCR5                0x371

#define MSR_P4_CRU_ESCR0               0x3b8
#define MSR_P4_CRU_ESCR2               0x3cc
#define MSR_P4_CRU_ESCR4               0x3e0
#define MSR_P4_IQ_ESCR0                0x3ba
#define MSR_P4_RAT_ESCR0               0x3bc
#define MSR_P4_SSU_ESCR0               0x3be
#define MSR_P4_ALF_ESCR0               0x3ca

#define P4_CRU_ESCR0_NUMBER            4
#define P4_CRU_ESCR2_NUMBER            5
#define P4_CRU_ESCR4_NUMBER            6
#define P4_IQ_ESCR0_NUMBER             0
#define P4_RAT_ESCR0_NUMBER            2
#define P4_SSU_ESCR0_NUMBER            3
#define P4_ALF_ESCR0_NUMBER            1

#define MSR_P4_CRU_ESCR1               0x3b9
#define MSR_P4_CRU_ESCR3               0x3cd
#define MSR_P4_CRU_ESCR5               0x3e1
#define MSR_P4_IQ_ESCR1                0x3bb
#define MSR_P4_RAT_ESCR1               0x3bd
#define MSR_P4_ALF_ESCR1               0x3cb

#define P4_CRU_ESCR1_NUMBER            4
#define P4_CRU_ESCR3_NUMBER            5
#define P4_CRU_ESCR5_NUMBER            6
#define P4_IQ_ESCR1_NUMBER             0
#define P4_RAT_ESCR1_NUMBER            2
#define P4_ALF_ESCR1_NUMBER            1

#define P4_BPU_COUNTER0_NUMBER         0
#define P4_BPU_COUNTER1_NUMBER         1
#define P4_BPU_COUNTER2_NUMBER         2
#define P4_BPU_COUNTER3_NUMBER         3

#define P4_MS_COUNTER0_NUMBER          4
#define P4_MS_COUNTER1_NUMBER          5
#define P4_MS_COUNTER2_NUMBER          6
#define P4_MS_COUNTER3_NUMBER          7

#define P4_FLAME_COUNTER0_NUMBER       8
#define P4_FLAME_COUNTER1_NUMBER       9
#define P4_FLAME_COUNTER2_NUMBER       10
#define P4_FLAME_COUNTER3_NUMBER       11

#define P4_IQ_COUNTER0_NUMBER          12
#define P4_IQ_COUNTER1_NUMBER          13
#define P4_IQ_COUNTER2_NUMBER          14
#define P4_IQ_COUNTER3_NUMBER          15
#define P4_IQ_COUNTER4_NUMBER          16
#define P4_IQ_COUNTER5_NUMBER          17

/* PEBS
 */
#define MSR_P4_PEBS_ENABLE             0x3F1
#define MSR_P4_PEBS_MATRIX_VERT        0x3F2

#define P4_PEBS_ENABLE_MY_THR          (1 << 25)
#define P4_PEBS_ENABLE_OTH_THR         (1 << 26)
#define P4_PEBS_ENABLE                 (1 << 24)
#define P4_PEBS_BIT0                   (1 << 0)
#define P4_PEBS_BIT1                   (1 << 1)
#define P4_PEBS_BIT2                   (1 << 2)

#define P4_PEBS_MATRIX_VERT_BIT0       (1 << 0)
#define P4_PEBS_MATRIX_VERT_BIT1       (1 << 1)
#define P4_PEBS_MATRIX_VERT_BIT2       (1 << 2)

/* Replay tagging.
 */
#define P4_REPLAY_TAGGING_PEBS_L1LMR   P4_PEBS_BIT0
#define P4_REPLAY_TAGGING_PEBS_L2LMR   P4_PEBS_BIT1
#define P4_REPLAY_TAGGING_PEBS_DTLMR   P4_PEBS_BIT2
#define P4_REPLAY_TAGGING_PEBS_DTSMR   P4_PEBS_BIT2
#define P4_REPLAY_TAGGING_PEBS_DTAMR   P4_PEBS_BIT2

#define P4_REPLAY_TAGGING_VERT_L1LMR   P4_PEBS_MATRIX_VERT_BIT0
#define P4_REPLAY_TAGGING_VERT_L2LMR   P4_PEBS_MATRIX_VERT_BIT0
#define P4_REPLAY_TAGGING_VERT_DTLMR   P4_PEBS_MATRIX_VERT_BIT0
#define P4_REPLAY_TAGGING_VERT_DTSMR   P4_PEBS_MATRIX_VERT_BIT1
#define P4_REPLAY_TAGGING_VERT_DTAMR   P4_PEBS_MATRIX_VERT_BIT0 | P4_PEBS_MATRIX_VERT_BIT1




/*****************************************************************************
 *                                                                           *
 *****************************************************************************/

// x87_FP_uop
#define EVENT_SEL_x87_FP_uop                0x04
#define EVENT_MASK_x87_FP_uop_ALL           (1 << 15)

// execution event (at retirement)
#define EVENT_SEL_execution_event           0x0C

// scalar_SP_uop
#define EVENT_SEL_scalar_SP_uop             0x0a
#define EVENT_MASK_scalar_SP_uop_ALL        (1 << 15)

// scalar_DP_uop
#define EVENT_SEL_scalar_DP_uop             0x0e
#define EVENT_MASK_scalar_DP_uop_ALL        (1 << 15)

// Instruction retired
#define EVENT_SEL_instr_retired             0x02
#define EVENT_MASK_instr_retired_ALL        0x0f

// uOps retired
#define EVENT_SEL_uops_retired              0x01
#define EVENT_MASK_uops_retired_ALL         0x03

// L1 misses retired
#define EVENT_SEL_replay_event              0x09
#define EVENT_MASK_replay_event_ALL         0x03

// Trace cache
#define EVENT_SEL_BPU_fetch_request         0x03
#define EVENT_MASK_BPU_fetch_request_TCMISS 0x01

// Bus activity
#define EVENT_SEL_FSB_data_activity               0x17
#define EVENT_MASK_FSB_data_activity_DRDY_DRV     0x01
#define EVENT_MASK_FSB_data_activity_DRDY_OWN     0x02
#define EVENT_MASK_FSB_data_activity_DRDY_OOTHER  0x04
#define EVENT_MASK_FSB_data_activity_DBSY_DRV     0x08
#define EVENT_MASK_FSB_data_activity_DBSY_OWN     0x10
#define EVENT_MASK_FSB_data_activity_DBSY_OOTHER  0x20

// Cache L2
#define EVENT_SEL_BSQ_cache_reference             0x0c
#define EVENT_MASK_BSQ_cache_reference_RD_L2_HITS 0x001
#define EVENT_MASK_BSQ_cache_reference_RD_L2_HITE 0x002
#define EVENT_MASK_BSQ_cache_reference_RD_L2_HITM 0x004

#define EVENT_MASK_BSQ_cache_reference_RD_L3_HITS 0x008
#define EVENT_MASK_BSQ_cache_reference_RD_L3_HITE 0x010
#define EVENT_MASK_BSQ_cache_reference_RD_L3_HITM 0x020

#define EVENT_MASK_BSQ_cache_reference_RD_L2_MISS 0x100
#define EVENT_MASK_BSQ_cache_reference_RD_L3_MISS 0x200
#define EVENT_MASK_BSQ_cache_reference_WR_L2_MISS 0x400

#endif

/* End of $RCSfile: p4perf.h,v $ */
