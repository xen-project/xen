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

#endif /* __ASM_ARM_VGIC_EMUL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
