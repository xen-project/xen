#include <xen/sched.h>
#include <xen/init.h>
#include <asm/processor.h>
#include <asm/vfp.h>

void vfp_save_state(struct vcpu *v)
{
    v->arch.vfp.fpexc = READ_CP32(FPEXC);

    WRITE_CP32(v->arch.vfp.fpexc | FPEXC_EN, FPEXC);

    v->arch.vfp.fpscr = READ_CP32(FPSCR);

    if ( v->arch.vfp.fpexc & FPEXC_EX ) /* Check for sub-architecture */
    {
        v->arch.vfp.fpinst = READ_CP32(FPINST);

        if ( v->arch.vfp.fpexc & FPEXC_FP2V )
            v->arch.vfp.fpinst2 = READ_CP32(FPINST2);
        /* Disable FPEXC_EX */
        WRITE_CP32((v->arch.vfp.fpexc | FPEXC_EN) & ~FPEXC_EX, FPEXC);
    }

    /* Save {d0-d15} */
    asm volatile("stc p11, cr0, [%1], #32*4"
                 : "=Q" (*v->arch.vfp.fpregs1) : "r" (v->arch.vfp.fpregs1));

    /* 32 x 64 bits registers? */
    if ( (READ_CP32(MVFR0) & MVFR0_A_SIMD_MASK) == 2 )
    {
        /* Save {d16-d31} */
        asm volatile("stcl p11, cr0, [%1], #32*4"
                     : "=Q" (*v->arch.vfp.fpregs2) : "r" (v->arch.vfp.fpregs2));
    }

    WRITE_CP32(v->arch.vfp.fpexc & ~(FPEXC_EN), FPEXC);
}

void vfp_restore_state(struct vcpu *v)
{
    //uint64_t test[16];
    WRITE_CP32(READ_CP32(FPEXC) | FPEXC_EN, FPEXC);

    /* Restore {d0-d15} */
    asm volatile("ldc p11, cr0, [%1], #32*4"
                 : : "Q" (*v->arch.vfp.fpregs1), "r" (v->arch.vfp.fpregs1));

    /* 32 x 64 bits registers? */
    if ( (READ_CP32(MVFR0) & MVFR0_A_SIMD_MASK) == 2 ) /* 32 x 64 bits registers */
        /* Restore {d16-d31} */
        asm volatile("ldcl p11, cr0, [%1], #32*4"
                     : : "Q" (*v->arch.vfp.fpregs2), "r" (v->arch.vfp.fpregs2));

    if ( v->arch.vfp.fpexc & FPEXC_EX )
    {
        WRITE_CP32(v->arch.vfp.fpinst, FPINST);
        if ( v->arch.vfp.fpexc & FPEXC_FP2V )
            WRITE_CP32(v->arch.vfp.fpinst2, FPINST2);
    }

    WRITE_CP32(v->arch.vfp.fpscr, FPSCR);

    WRITE_CP32(v->arch.vfp.fpexc, FPEXC);
}

static __init int vfp_init(void)
{
    unsigned int vfpsid;
    unsigned int vfparch;

    vfpsid = READ_CP32(FPSID);

    printk("VFP implementer 0x%02x architecture %d part 0x%02x variant 0x%x "
           "rev 0x%x\n",
           (vfpsid & FPSID_IMPLEMENTER_MASK) >> FPSID_IMPLEMENTER_BIT,
           (vfpsid & FPSID_ARCH_MASK) >> FPSID_ARCH_BIT,
           (vfpsid & FPSID_PART_MASK) >> FPSID_PART_BIT,
           (vfpsid & FPSID_VARIANT_MASK) >> FPSID_VARIANT_BIT,
           (vfpsid & FPSID_REV_MASK) >> FPSID_REV_BIT);

    vfparch = (vfpsid & FPSID_ARCH_MASK) >> FPSID_ARCH_BIT;
    if ( vfparch < 2 )
        panic("Xen only support VFP 3");

    return 0;
}
presmp_initcall(vfp_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
