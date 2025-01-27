#include <asm/page-bits.h>

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

/*
 * Call a noreturn function.  This could be JMP, but CALL results in a more
 * helpful backtrace.  BUG is to catch functions which do decide to return...
 */
.macro tailcall fn:req
    call  \fn
    BUG   /* Shouldn't return */
.endm

.macro INDIRECT_CALL arg:req
/*
 * Create an indirect call.  arg is a single register.
 *
 * With no compiler support, this degrades into a plain indirect call/jmp.
 * With compiler support, dispatch to the correct __x86_indirect_thunk_*
 */
    .if CONFIG_INDIRECT_THUNK == 1

        $done = 0
        .irp reg, ax, cx, dx, bx, bp, si, di, 8, 9, 10, 11, 12, 13, 14, 15
        .ifeqs "\arg", "%r\reg"
            call __x86_indirect_thunk_r\reg
            $done = 1
           .exitm
        .endif
        .endr

        .if $done != 1
            .error "Bad register arg \arg"
        .endif

    .else
        call *\arg
    .endif
.endm

#ifdef CONFIG_XEN_IBT
# define ENDBR64 endbr64
#else
# define ENDBR64
#endif

.macro guest_access_mask_ptr ptr:req, scratch1:req, scratch2:req
#if defined(CONFIG_SPECULATIVE_HARDEN_GUEST_ACCESS)
    /*
     * Here we want to adjust \ptr such that
     * - if it's within Xen range, it becomes non-canonical,
     * - otherwise if it's (non-)canonical on input, it retains that property,
     * - if the result is non-canonical, bit 47 is clear (to avoid
     *   potentially populating the cache with Xen data on AMD-like hardware),
     * but guaranteed without any conditional branches (hence in assembly).
     *
     * To achieve this we determine which bit to forcibly clear: Either bit 47
     * (in case the address is below HYPERVISOR_VIRT_END) or bit 63.  Further
     * we determine whether for forcably set bit 63: In case we first cleared
     * it, we'll merely restore the original address.  In case we ended up
     * clearing bit 47 (i.e. the address was either non-canonical or within Xen
     * range), setting the bit will yield a guaranteed non-canonical address.
     * If we didn't clear a bit, we also won't set one: The address was in the
     * low half of address space in that case with bit 47 already clear.  The
     * address can thus be left unchanged, whether canonical or not.
     */
    mov $(HYPERVISOR_VIRT_END - 1), \scratch1
    mov $(VADDR_BITS - 1), \scratch2
    cmp \ptr, \scratch1
    /*
     * Not needed: The value we have in \scratch1 will be truncated to 6 bits,
     * thus yielding the value we need.
    mov $63, \scratch1
     */
    cmovnb \scratch2, \scratch1
    xor \scratch2, \scratch2
    btr \scratch1, \ptr
    rcr $1, \scratch2
    or \scratch2, \ptr
#elif defined(CONFIG_DEBUG) && defined(CONFIG_PV)
    xor $~\@, \scratch1
    xor $~\@, \scratch2
#endif
.endm
