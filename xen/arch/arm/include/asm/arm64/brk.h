/*
 * Copyright (C) 2016 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ASM_ARM_ARM64_BRK
#define __ASM_ARM_ARM64_BRK

/*
 * #imm16 values used for BRK instruction generation
 * 0x001: xen-mode BUG() and WARN() traps
 * 0x002: for triggering a fault on purpose (reserved)
 */
#define BRK_BUG_FRAME_IMM   1
#define BRK_FAULT_IMM       2

/*
 * BRK instruction encoding
 * The #imm16 value should be placed at bits[20:5] within BRK ins
 */
#define AARCH64_BREAK_MON 0xd4200000

/*
 * BRK instruction for provoking a fault on purpose
 */
#define AARCH64_BREAK_FAULT (AARCH64_BREAK_MON | (BRK_FAULT_IMM << 5))

#endif /* !__ASM_ARM_ARM64_BRK */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
