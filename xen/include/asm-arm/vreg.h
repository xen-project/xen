/*
 * Helpers to emulate co-processor and system registers
 */
#ifndef __ASM_ARM_VREG__
#define __ASM_ARM_VREG__

typedef bool (*vreg_reg32_fn_t)(struct cpu_user_regs *regs, uint32_t *r,
                                   bool read);
typedef bool (*vreg_reg64_fn_t)(struct cpu_user_regs *regs, uint64_t *r,
                                   bool read);

static inline bool vreg_emulate_cp32(struct cpu_user_regs *regs, union hsr hsr,
                                     vreg_reg32_fn_t fn)
{
    struct hsr_cp32 cp32 = hsr.cp32;
    /*
     * Initialize to zero to avoid leaking data if there is an
     * implementation error in the emulation (such as not correctly
     * setting r).
     */
    uint32_t r = 0;
    bool ret;

    if ( !cp32.read )
        r = get_user_reg(regs, cp32.reg);

    ret = fn(regs, &r, cp32.read);

    if ( ret && cp32.read )
        set_user_reg(regs, cp32.reg, r);

    return ret;
}

static inline bool vreg_emulate_cp64(struct cpu_user_regs *regs, union hsr hsr,
                                     vreg_reg64_fn_t fn)
{
    struct hsr_cp64 cp64 = hsr.cp64;
    /*
     * Initialize to zero to avoid leaking data if there is an
     * implementation error in the emulation (such as not correctly
     * setting x).
     */
    uint64_t x = 0;
    bool ret;

    if ( !cp64.read )
    {
        uint32_t r1 = get_user_reg(regs, cp64.reg1);
        uint32_t r2 = get_user_reg(regs, cp64.reg2);

        x = (uint64_t)r1 | ((uint64_t)r2 << 32);
    }

    ret = fn(regs, &x, cp64.read);

    if ( ret && cp64.read )
    {
        set_user_reg(regs, cp64.reg1, x & 0xffffffff);
        set_user_reg(regs, cp64.reg2, x >> 32);
    }

    return ret;
}

#ifdef CONFIG_ARM_64
static inline bool vreg_emulate_sysreg32(struct cpu_user_regs *regs, union hsr hsr,
                                         vreg_reg32_fn_t fn)
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
                                         vreg_reg64_fn_t fn)
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
