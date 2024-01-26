#ifndef __X86_BUG_H__
#define __X86_BUG_H__

/*
 * Please do not include in the header any header that might
 * use BUG/ASSERT/etc maros asthey will be defined later after
 * the return to <xen/bug.h> from the current header:
 * 
 * <xen/bug.h>:
 *  ...
 *   <asm/bug.h>:
 *     ...
 *     <any_header_which_uses_BUG/ASSERT/etc macros.h>
 *     ...
 *  ...
 *  #define BUG() ...
 *  ...
 *  #define ASSERT() ...
 *  ...
 */

#ifndef __ASSEMBLY__

#define BUG_INSTR       "ud2"
#define BUG_ASM_CONST   "c"

#else  /* !__ASSEMBLY__ */

/*
 * Construct a bugframe, suitable for using in assembly code.  Should always
 * match the C version above.  One complication is having to stash the strings
 * in .rodata
 */
    .macro BUG_FRAME type, line, file_str, second_frame, msg

    .if \type >= BUGFRAME_NR
        .error "Invalid BUGFRAME index"
    .endif

    .L\@ud: ud2a

    .pushsection .rodata.str1, "aMS", @progbits, 1
         .L\@s1: .asciz "\file_str"
    .popsection

    .pushsection .bug_frames.\type, "a", @progbits
        .p2align 2
        .L\@bf:
        .long (.L\@ud - .L\@bf) + \
               ((\line >> BUG_LINE_LO_WIDTH) << BUG_DISP_WIDTH)
        .long (.L\@s1 - .L\@bf) + \
               ((\line & ((1 << BUG_LINE_LO_WIDTH) - 1)) << BUG_DISP_WIDTH)

        .if \second_frame
            .pushsection .rodata.str1, "aMS", @progbits, 1
                .L\@s2: .asciz "\msg"
            .popsection
            .long 0, (.L\@s2 - .L\@bf)
        .endif
    .popsection
    .endm

#define WARN BUG_FRAME BUGFRAME_warn, __LINE__, __FILE__, 0, 0
#define BUG  BUG_FRAME BUGFRAME_bug,  __LINE__, __FILE__, 0, 0

#define ASSERT_FAILED(msg)                                      \
     BUG_FRAME BUGFRAME_assert, __LINE__, __FILE__, 1, msg

#endif /* !__ASSEMBLY__ */

#endif /* __X86_BUG_H__ */
