/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arm SVE assembly routines
 *
 * Copyright (C) 2022 ARM Ltd.
 *
 * Some macros and instruction encoding in this file are taken from linux 6.1.1,
 * file arch/arm64/include/asm/fpsimdmacros.h, some of them are a modified
 * version.
 */

/* Sanity-check macros to help avoid encoding garbage instructions */

.macro _check_general_reg nr
    .if (\nr) < 0 || (\nr) > 30
        .error "Bad register number \nr."
    .endif
.endm

.macro _check_num n, min, max
    .if (\n) < (\min) || (\n) > (\max)
        .error "Number \n out of range [\min,\max]"
    .endif
.endm

/* SVE instruction encodings for non-SVE-capable assemblers */
/* (pre binutils 2.28, all kernel capable clang versions support SVE) */

/* RDVL X\nx, #\imm */
.macro _sve_rdvl nx, imm
    _check_general_reg \nx
    _check_num (\imm), -0x20, 0x1f
    .inst 0x04bf5000                \
        | (\nx)                     \
        | (((\imm) & 0x3f) << 5)
.endm

/* Gets the current vector register size in bytes */
GLOBAL(sve_get_hw_vl)
    _sve_rdvl 0, 1
    ret

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
