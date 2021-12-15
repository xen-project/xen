#ifndef __ASM_ARM_VGIC_EMUL_H__
#define __ASM_ARM_VGIC_EMUL_H__

/*
 * Helpers to create easily a case to match emulate a single register or
 * a range of registers
 */

#define VREG32(reg) reg ... reg + 3
#define VREG64(reg) reg ... reg + 7

#define VRANGE32(start, end) start ... end + 3
#define VRANGE64(start, end) start ... end + 7

/*
 * 64 bits registers can be accessible using 32-bit and 64-bit unless
 * stated otherwise (See 8.1.3 ARM IHI 0069A).
 */
static inline bool vgic_reg64_check_access(struct hsr_dabt dabt)
{
    return ( dabt.size == DABT_DOUBLE_WORD || dabt.size == DABT_WORD );
}

#endif /* __ASM_ARM_VGIC_EMUL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
