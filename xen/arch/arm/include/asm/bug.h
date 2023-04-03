#ifndef __ARM_BUG_H__
#define __ARM_BUG_H__

#include <xen/types.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/bug.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/bug.h>
#else
# error "unknown ARM variant"
#endif

#define BUG_FRAME_STRUCT

struct bug_frame {
    signed int loc_disp;    /* Relative address to the bug address */
    signed int file_disp;   /* Relative address to the filename */
    signed int msg_disp;    /* Relative address to the predicate (for ASSERT) */
    uint16_t line;          /* Line number */
    uint32_t pad0:16;       /* Padding for 8-bytes align */
};

#define bug_loc(b) ((const void *)(b) + (b)->loc_disp)
#define bug_file(b) ((const void *)(b) + (b)->file_disp);
#define bug_line(b) ((b)->line)
#define bug_msg(b) ((const char *)(b) + (b)->msg_disp)

/* Many versions of GCC doesn't support the asm %c parameter which would
 * be preferable to this unpleasantness. We use mergeable string
 * sections to avoid multiple copies of the string appearing in the
 * Xen image. BUGFRAME_run_fn needs to be handled separately.
 */
#define BUG_FRAME(type, line, file, has_msg, msg) do {                      \
    BUILD_BUG_ON((line) >> 16);                                             \
    BUILD_BUG_ON((type) >= BUGFRAME_NR);                                    \
    asm ("1:"BUG_INSTR"\n"                                                  \
         ".pushsection .rodata.str, \"aMS\", %progbits, 1\n"                \
         "2:\t.asciz " __stringify(file) "\n"                               \
         "3:\n"                                                             \
         ".if " #has_msg "\n"                                               \
         "\t.asciz " #msg "\n"                                              \
         ".endif\n"                                                         \
         ".popsection\n"                                                    \
         ".pushsection .bug_frames." __stringify(type) ", \"a\", %progbits\n"\
         "4:\n"                                                             \
         ".p2align 2\n"                                                     \
         ".long (1b - 4b)\n"                                                \
         ".long (2b - 4b)\n"                                                \
         ".long (3b - 4b)\n"                                                \
         ".hword " __stringify(line) ", 0\n"                                \
         ".popsection");                                                    \
} while (0)

/*
 * GCC will not allow to use "i"  when PIE is enabled (Xen doesn't set the
 * flag but instead rely on the default value from the compiler). So the
 * easiest way to implement run_in_exception_handler() is to pass the to
 * be called function in a fixed register.
 */
#define  run_in_exception_handler(fn) do {                                  \
    asm ("mov " __stringify(BUG_FN_REG) ", %0\n"                            \
         "1:"BUG_INSTR"\n"                                                  \
         ".pushsection .bug_frames." __stringify(BUGFRAME_run_fn) ","       \
         "             \"a\", %%progbits\n"                                 \
         "2:\n"                                                             \
         ".p2align 2\n"                                                     \
         ".long (1b - 2b)\n"                                                \
         ".long 0, 0, 0\n"                                                  \
         ".popsection" :: "r" (fn) : __stringify(BUG_FN_REG) );             \
} while (0)

#define WARN() BUG_FRAME(BUGFRAME_warn, __LINE__, __FILE__, 0, "")

#define BUG() do {                                              \
    BUG_FRAME(BUGFRAME_bug,  __LINE__, __FILE__, 0, "");        \
    unreachable();                                              \
} while (0)

#define assert_failed(msg) do {                                 \
    BUG_FRAME(BUGFRAME_assert, __LINE__, __FILE__, 1, msg);     \
    unreachable();                                              \
} while (0)

#endif /* __ARM_BUG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
