/*
 * Helpers to emulate co-processor and system registers
 */
#ifndef __ASM_ARM_VREG__
#define __ASM_ARM_VREG__

typedef bool (*vreg_reg64_fn_t)(struct cpu_user_regs *regs, uint64_t *r,
                                   bool read);
typedef bool (*vreg_reg_fn_t)(struct cpu_user_regs *regs, register_t *r,
                                   bool read);

static inline bool vreg_emulate_cp32(struct cpu_user_regs *regs, union hsr hsr,
                                     vreg_reg_fn_t fn)
{
    struct hsr_cp32 cp32 = hsr.cp32;
    /*
     * Initialize to zero to avoid leaking data if there is an
     * implementation error in the emulation (such as not correctly
     * setting r).
     */
    register_t r = 0;
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
        set_user_reg(regs, cp64.reg1, x & 0xffffffffU);
        set_user_reg(regs, cp64.reg2, x >> 32);
    }

    return ret;
}

#ifdef CONFIG_ARM_64
static inline bool vreg_emulate_sysreg(struct cpu_user_regs *regs, union hsr hsr,
                                         vreg_reg_fn_t fn)
{
    struct hsr_sysreg sysreg = hsr.sysreg;
    register_t r = 0;
    bool ret;

    if ( !sysreg.read )
        r = get_user_reg(regs, sysreg.reg);

    ret = fn(regs, &r, sysreg.read);

    if ( ret && sysreg.read )
        set_user_reg(regs, sysreg.reg, r);

    return ret;
}
#endif

#define VREG_REG_MASK(size) ((~0UL) >> (BITS_PER_LONG - ((1 << (size)) * 8)))

/*
 * The check on the size supported by the register has to be done by
 * the caller of vreg_regN_*.
 *
 * Note that the alignment fault will always be taken in the guest
 * (see B3.12.7 DDI0406.b).
 */

/* N-bit register helpers */
#define VREG_REG_HELPERS(sz, offmask)                                   \
static inline register_t vreg_reg##sz##_extract(uint##sz##_t reg,       \
                                                const mmio_info_t *info)\
{                                                                       \
    unsigned int offset = info->gpa & (offmask);                        \
                                                                        \
    reg >>= 8 * offset;                                                 \
    reg &= VREG_REG_MASK(info->dabt.size);                              \
                                                                        \
    return reg;                                                         \
}                                                                       \
                                                                        \
static inline void vreg_reg##sz##_update(uint##sz##_t *reg,             \
                                         register_t val,                \
                                         const mmio_info_t *info)       \
{                                                                       \
    unsigned int offset = info->gpa & (offmask);                        \
    uint##sz##_t mask = VREG_REG_MASK(info->dabt.size);                 \
    unsigned int shift = offset * 8;                                    \
                                                                        \
    *reg &= ~(mask << shift);                                           \
    *reg |= ((uint##sz##_t)val & mask) << shift;                        \
}                                                                       \
                                                                        \
static inline void vreg_reg##sz##_setbits(uint##sz##_t *reg,            \
                                          register_t bits,              \
                                          const mmio_info_t *info)      \
{                                                                       \
    unsigned int offset = info->gpa & (offmask);                        \
    uint##sz##_t mask = VREG_REG_MASK(info->dabt.size);                 \
    unsigned int shift = offset * 8;                                    \
                                                                        \
    *reg |= ((uint##sz##_t)bits & mask) << shift;                       \
}                                                                       \
                                                                        \
static inline void vreg_reg##sz##_clearbits(uint##sz##_t *reg,          \
                                            register_t bits,            \
                                            const mmio_info_t *info)    \
{                                                                       \
    unsigned int offset = info->gpa & (offmask);                        \
    uint##sz##_t mask = VREG_REG_MASK(info->dabt.size);                 \
    unsigned int shift = offset * 8;                                    \
                                                                        \
    *reg &= ~(((uint##sz##_t)bits & mask) << shift);                    \
}

VREG_REG_HELPERS(64, 0x7)
VREG_REG_HELPERS(32, 0x3)

#undef VREG_REG_HELPERS

#endif /* __ASM_ARM_VREG__ */
