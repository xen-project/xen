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

.macro _sve_check_zreg znr
    .if (\znr) < 0 || (\znr) > 31
        .error "Bad Scalable Vector Extension vector register number \znr."
    .endif
.endm

.macro _sve_check_preg pnr
    .if (\pnr) < 0 || (\pnr) > 15
        .error "Bad Scalable Vector Extension predicate register number \pnr."
    .endif
.endm

.macro _check_num n, min, max
    .if (\n) < (\min) || (\n) > (\max)
        .error "Number \n out of range [\min,\max]"
    .endif
.endm

/* SVE instruction encodings for non-SVE-capable assemblers */
/* (pre binutils 2.28, all kernel capable clang versions support SVE) */

/* STR (vector): STR Z\nz, [X\nxbase, #\offset, MUL VL] */
.macro _sve_str_v nz, nxbase, offset=0
    _sve_check_zreg \nz
    _check_general_reg \nxbase
    _check_num (\offset), -0x100, 0xff
    .inst 0xe5804000                \
        | (\nz)                     \
        | ((\nxbase) << 5)          \
        | (((\offset) & 7) << 10)   \
        | (((\offset) & 0x1f8) << 13)
.endm

/* LDR (vector): LDR Z\nz, [X\nxbase, #\offset, MUL VL] */
.macro _sve_ldr_v nz, nxbase, offset=0
    _sve_check_zreg \nz
    _check_general_reg \nxbase
    _check_num (\offset), -0x100, 0xff
    .inst 0x85804000                \
        | (\nz)                     \
        | ((\nxbase) << 5)          \
        | (((\offset) & 7) << 10)   \
        | (((\offset) & 0x1f8) << 13)
.endm

/* STR (predicate): STR P\np, [X\nxbase, #\offset, MUL VL] */
.macro _sve_str_p np, nxbase, offset=0
    _sve_check_preg \np
    _check_general_reg \nxbase
    _check_num (\offset), -0x100, 0xff
    .inst 0xe5800000                \
        | (\np)                     \
        | ((\nxbase) << 5)          \
        | (((\offset) & 7) << 10)   \
        | (((\offset) & 0x1f8) << 13)
.endm

/* LDR (predicate): LDR P\np, [X\nxbase, #\offset, MUL VL] */
.macro _sve_ldr_p np, nxbase, offset=0
    _sve_check_preg \np
    _check_general_reg \nxbase
    _check_num (\offset), -0x100, 0xff
    .inst 0x85800000                \
        | (\np)                     \
        | ((\nxbase) << 5)          \
        | (((\offset) & 7) << 10)   \
        | (((\offset) & 0x1f8) << 13)
.endm

/* RDVL X\nx, #\imm */
.macro _sve_rdvl nx, imm
    _check_general_reg \nx
    _check_num (\imm), -0x20, 0x1f
    .inst 0x04bf5000                \
        | (\nx)                     \
        | (((\imm) & 0x3f) << 5)
.endm

/* RDFFR (unpredicated): RDFFR P\np.B */
.macro _sve_rdffr np
    _sve_check_preg \np
    .inst 0x2519f000                \
        | (\np)
.endm

/* WRFFR P\np.B */
.macro _sve_wrffr np
    _sve_check_preg \np
    .inst 0x25289000                \
        | ((\np) << 5)
.endm

.macro __for from:req, to:req
    .if (\from) == (\to)
        _for__body %\from
    .else
        __for %\from, %((\from) + ((\to) - (\from)) / 2)
        __for %((\from) + ((\to) - (\from)) / 2 + 1), %\to
    .endif
.endm

.macro _for var:req, from:req, to:req, insn:vararg
    .macro _for__body \var:req
        .noaltmacro
        \insn
        .altmacro
    .endm

    .altmacro
    __for \from, \to
    .noaltmacro

    .purgem _for__body
.endm

/*
 * sve_save and sve_load are different from the Linux version because the
 * buffers to save the context are different from Xen and for example Linux
 * is using this macro to save/restore also fpsr and fpcr while we do it in C
 */

.macro sve_save nxzffrctx, nxpctx, save_ffr
    _for n, 0, 31, _sve_str_v \n, \nxzffrctx, \n - 32
    _for n, 0, 15, _sve_str_p \n, \nxpctx, \n
        cbz \save_ffr, 1f
        _sve_rdffr 0
        _sve_str_p 0, \nxzffrctx
        _sve_ldr_p 0, \nxpctx
        b 2f
1:
        str xzr, [x\nxzffrctx]      // Zero out FFR
2:
.endm

.macro sve_load nxzffrctx, nxpctx, restore_ffr
    _for n, 0, 31, _sve_ldr_v \n, \nxzffrctx, \n - 32
        cbz \restore_ffr, 1f
        _sve_ldr_p 0, \nxzffrctx
        _sve_wrffr 0
1:
    _for n, 0, 15, _sve_ldr_p \n, \nxpctx, \n
.endm

/* Gets the current vector register size in bytes */
FUNC(sve_get_hw_vl)
    _sve_rdvl 0, 1
    ret
END(sve_get_hw_vl)

/*
 * Save the SVE context
 *
 * x0 - pointer to buffer for Z0-31 + FFR
 * x1 - pointer to buffer for P0-15
 * x2 - Save FFR if non-zero
 */
FUNC(sve_save_ctx)
    sve_save 0, 1, x2
    ret
END(sve_save_ctx)

/*
 * Load the SVE context
 *
 * x0 - pointer to buffer for Z0-31 + FFR
 * x1 - pointer to buffer for P0-15
 * x2 - Restore FFR if non-zero
 */
FUNC(sve_load_ctx)
    sve_load 0, 1, x2
    ret
END(sve_load_ctx)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
