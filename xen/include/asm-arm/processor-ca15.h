#ifndef __ASM_ARM_PROCESSOR_CA15_H
#define __ASM_ARM_PROCESSOR_CA15_H

/* ACTLR Auxiliary Control Register, Cortex A15 */
#define ACTLR_CA15_SNOOP_DELAYED      (1<<31)
#define ACTLR_CA15_MAIN_CLOCK         (1<<30)
#define ACTLR_CA15_NEON_CLOCK         (1<<29)
#define ACTLR_CA15_NONCACHE           (1<<24)
#define ACTLR_CA15_INORDER_REQ        (1<<23)
#define ACTLR_CA15_INORDER_LOAD       (1<<22)
#define ACTLR_CA15_L2_TLB_PREFETCH    (1<<21)
#define ACTLR_CA15_L2_IPA_PA_CACHE    (1<<20)
#define ACTLR_CA15_L2_CACHE           (1<<19)
#define ACTLR_CA15_L2_PA_CACHE        (1<<18)
#define ACTLR_CA15_TLB                (1<<17)
#define ACTLR_CA15_STRONGY_ORDERED    (1<<16)
#define ACTLR_CA15_INORDER            (1<<15)
#define ACTLR_CA15_FORCE_LIM          (1<<14)
#define ACTLR_CA15_CP_FLUSH           (1<<13)
#define ACTLR_CA15_CP_PUSH            (1<<12)
#define ACTLR_CA15_LIM                (1<<11)
#define ACTLR_CA15_SER                (1<<10)
#define ACTLR_CA15_OPT                (1<<9)
#define ACTLR_CA15_WFI                (1<<8)
#define ACTLR_CA15_WFE                (1<<7)
#define ACTLR_CA15_SMP                (1<<6)
#define ACTLR_CA15_PLD                (1<<5)
#define ACTLR_CA15_IP                 (1<<4)
#define ACTLR_CA15_MICRO_BTB          (1<<3)
#define ACTLR_CA15_LOOP_ONE           (1<<2)
#define ACTLR_CA15_LOOP_DISABLE       (1<<1)
#define ACTLR_CA15_BTB                (1<<0)

#endif /* __ASM_ARM_PROCESSOR_CA15_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
