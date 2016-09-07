#ifndef __X86_BUG_H__
#define __X86_BUG_H__

#define BUG_DISP_WIDTH    24
#define BUG_LINE_LO_WIDTH (31 - BUG_DISP_WIDTH)
#define BUG_LINE_HI_WIDTH (31 - BUG_DISP_WIDTH)

#define BUGFRAME_run_fn 0
#define BUGFRAME_warn   1
#define BUGFRAME_bug    2
#define BUGFRAME_assert 3

#define BUGFRAME_NR     4

#ifndef __ASSEMBLY__

struct bug_frame {
    signed int loc_disp:BUG_DISP_WIDTH;
    unsigned int line_hi:BUG_LINE_HI_WIDTH;
    signed int ptr_disp:BUG_DISP_WIDTH;
    unsigned int line_lo:BUG_LINE_LO_WIDTH;
    signed int msg_disp[];
};

#define bug_loc(b) ((const void *)(b) + (b)->loc_disp)
#define bug_ptr(b) ((const void *)(b) + (b)->ptr_disp)
#define bug_line(b) (((((b)->line_hi + ((b)->loc_disp < 0)) &                \
                       ((1 << BUG_LINE_HI_WIDTH) - 1)) <<                    \
                      BUG_LINE_LO_WIDTH) +                                   \
                     (((b)->line_lo + ((b)->ptr_disp < 0)) &                 \
                      ((1 << BUG_LINE_LO_WIDTH) - 1)))
#define bug_msg(b) ((const char *)(b) + (b)->msg_disp[1])

#define _ASM_BUGFRAME_TEXT(second_frame)                                     \
    ".Lbug%=: ud2\n"                                                         \
    ".pushsection .bug_frames.%c[bf_type], \"a\", @progbits\n"               \
    ".p2align 2\n"                                                           \
    ".Lfrm%=:\n"                                                             \
    ".long (.Lbug%= - .Lfrm%=) + %c[bf_line_hi]\n"                           \
    ".long (%c[bf_ptr] - .Lfrm%=) + %c[bf_line_lo]\n"                        \
    ".if " #second_frame "\n"                                                \
    ".long 0, %c[bf_msg] - .Lfrm%=\n"                                        \
    ".endif\n"                                                               \
    ".popsection\n"                                                          \

#define _ASM_BUGFRAME_INFO(type, line, ptr, msg)                             \
    [bf_type]    "i" (type),                                                 \
    [bf_ptr]     "i" (ptr),                                                  \
    [bf_msg]     "i" (msg),                                                  \
    [bf_line_lo] "i" ((line & ((1 << BUG_LINE_LO_WIDTH) - 1))                \
                      << BUG_DISP_WIDTH),                                    \
    [bf_line_hi] "i" (((line) >> BUG_LINE_LO_WIDTH) << BUG_DISP_WIDTH)

#define BUG_FRAME(type, line, ptr, second_frame, msg) do {                   \
    BUILD_BUG_ON((line) >> (BUG_LINE_LO_WIDTH + BUG_LINE_HI_WIDTH));         \
    BUILD_BUG_ON((type) >= BUGFRAME_NR);                                     \
    asm volatile ( _ASM_BUGFRAME_TEXT(second_frame)                          \
                   :: _ASM_BUGFRAME_INFO(type, line, ptr, msg) );            \
} while (0)


#define WARN() BUG_FRAME(BUGFRAME_warn, __LINE__, __FILE__, 0, NULL)
#define BUG() do {                                              \
    BUG_FRAME(BUGFRAME_bug,  __LINE__, __FILE__, 0, NULL);      \
    unreachable();                                              \
} while (0)

#define run_in_exception_handler(fn) BUG_FRAME(BUGFRAME_run_fn, 0, fn, 0, NULL)

#define assert_failed(msg) do {                                 \
    BUG_FRAME(BUGFRAME_assert, __LINE__, __FILE__, 1, msg);     \
    unreachable();                                              \
} while (0)

extern const struct bug_frame __start_bug_frames[],
                              __stop_bug_frames_0[],
                              __stop_bug_frames_1[],
                              __stop_bug_frames_2[],
                              __stop_bug_frames_3[];

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
