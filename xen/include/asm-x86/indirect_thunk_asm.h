/*
 * Warning!  This file is included at an assembler level for .c files, causing
 * usual #ifdef'ary to turn into comments.
 */

.macro INDIRECT_BRANCH insn:req arg:req
/*
 * Create an indirect branch.  insn is one of call/jmp, arg is a single
 * register.
 *
 * With no compiler support, this degrades into a plain indirect call/jmp.
 * With compiler support, dispatch to the correct __x86_indirect_thunk_*
 */
    .if CONFIG_INDIRECT_THUNK == 1

        $done = 0
        .irp reg, ax, cx, dx, bx, bp, si, di, 8, 9, 10, 11, 12, 13, 14, 15
        .ifeqs "\arg", "%r\reg"
            \insn __x86_indirect_thunk_r\reg
            $done = 1
           .exitm
        .endif
        .endr

        .if $done != 1
            .error "Bad register arg \arg"
        .endif

    .else
        \insn *\arg
    .endif
.endm

/* Convenience wrappers. */
.macro INDIRECT_CALL arg:req
    INDIRECT_BRANCH call \arg
.endm

.macro INDIRECT_JMP arg:req
    INDIRECT_BRANCH jmp \arg
.endm
