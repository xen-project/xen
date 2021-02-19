#ifndef HAVE_AS_CLAC_STAC
.macro clac
    .byte 0x0f, 0x01, 0xca
.endm

.macro stac
    .byte 0x0f, 0x01, 0xcb
.endm
#endif

.macro vmrun
    .byte 0x0f, 0x01, 0xd8
.endm

.macro stgi
    .byte 0x0f, 0x01, 0xdc
.endm

.macro clgi
    .byte 0x0f, 0x01, 0xdd
.endm

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

.macro guest_access_mask_ptr ptr:req, scratch1:req, scratch2:req
#if defined(CONFIG_SPECULATIVE_HARDEN_GUEST_ACCESS)
    /*
     * Here we want
     *
     * ptr &= ~0ull >> (ptr < HYPERVISOR_VIRT_END);
     *
     * but guaranteed without any conditional branches (hence in assembly).
     */
    mov $(HYPERVISOR_VIRT_END - 1), \scratch1
    mov $~0, \scratch2
    cmp \ptr, \scratch1
    rcr $1, \scratch2
    and \scratch2, \ptr
#elif defined(CONFIG_DEBUG) && defined(CONFIG_PV)
    xor $~\@, \scratch1
    xor $~\@, \scratch2
#endif
.endm
