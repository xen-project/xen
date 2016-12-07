/*
 * Helpers to emulate co-processor and system registers
 */
#ifndef __ASM_ARM_VREG__
#define __ASM_ARM_VREG__

#ifdef CONFIG_ARM_64
typedef bool (*vreg_sysreg32_fn_t)(struct cpu_user_regs *regs, uint32_t *r,
                                   bool read);
typedef bool (*vreg_sysreg64_fn_t)(struct cpu_user_regs *regs, uint64_t *r,
                                   bool read);

static inline bool vreg_emulate_sysreg32(struct cpu_user_regs *regs, union hsr hsr,
                                         vreg_sysreg32_fn_t fn)
{
    struct hsr_sysreg sysreg = hsr.sysreg;
    uint32_t r = 0;
    bool ret;

    if ( !sysreg.read )
        r = get_user_reg(regs, sysreg.reg);

    ret = fn(regs, &r, sysreg.read);

    if ( ret && sysreg.read )
        set_user_reg(regs, sysreg.reg, r);

    return ret;
}

static inline bool vreg_emulate_sysreg64(struct cpu_user_regs *regs, union hsr hsr,
                                         vreg_sysreg64_fn_t fn)
{
    struct hsr_sysreg sysreg = hsr.sysreg;
    /*
     * Initialize to zero to avoid leaking data if there is an
     * implementation error in the emulation (such as not correctly
     * setting x).
     */
    uint64_t x = 0;
    bool ret;

    if ( !sysreg.read )
        x = get_user_reg(regs, sysreg.reg);

    ret = fn(regs, &x, sysreg.read);

    if ( ret && sysreg.read )
        set_user_reg(regs, sysreg.reg, x);

    return ret;
}

#endif

#endif /* __ASM_ARM_VREG__ */
