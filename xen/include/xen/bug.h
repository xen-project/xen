#ifndef __XEN_BUG_H__
#define __XEN_BUG_H__

#define BUGFRAME_run_fn 0
#define BUGFRAME_warn   1
#define BUGFRAME_bug    2
#define BUGFRAME_assert 3

#define BUGFRAME_NR     4

#define BUG_DISP_WIDTH    24
#define BUG_LINE_LO_WIDTH (31 - BUG_DISP_WIDTH)
#define BUG_LINE_HI_WIDTH (31 - BUG_DISP_WIDTH)

#include <asm/bug.h>

#ifndef __ASSEMBLY__

#include <xen/compiler.h>
#include <xen/macros.h>
#include <xen/types.h>

#ifndef BUG_FRAME_STRUCT

struct bug_frame {
    signed int loc_disp:BUG_DISP_WIDTH;
    unsigned int line_hi:BUG_LINE_HI_WIDTH;
    signed int ptr_disp:BUG_DISP_WIDTH;
    unsigned int line_lo:BUG_LINE_LO_WIDTH;
    signed int msg_disp[];
};

#define bug_loc(b) ((unsigned long)(b) + (b)->loc_disp)

#define bug_ptr(b) ((const void *)(b) + (b)->ptr_disp)

#define bug_line(b) (((((b)->line_hi + ((b)->loc_disp < 0)) &                \
                       ((1 << BUG_LINE_HI_WIDTH) - 1)) <<                    \
                      BUG_LINE_LO_WIDTH) +                                   \
                     (((b)->line_lo + ((b)->ptr_disp < 0)) &                 \
                      ((1 << BUG_LINE_LO_WIDTH) - 1)))

#define bug_msg(b) ((const char *)(b) + (b)->msg_disp[1])

#define BUG_CHECK_LINE_WIDTH(line) \
    BUILD_BUG_ON((line) >> (BUG_LINE_LO_WIDTH + BUG_LINE_HI_WIDTH))

#elif !defined(BUG_CHECK_LINE_WIDTH)

#define BUG_CHECK_LINE_WIDTH(line) ((void)(line))

#endif /* BUG_FRAME_STRUCT */


/*
 * Some architectures mark immediate instruction operands in a special way.
 * In such cases the special marking may need omitting when specifying
 * directive operands. Allow architectures to specify a suitable
 * modifier.
 */
#ifndef BUG_ASM_CONST
#define BUG_ASM_CONST ""
#endif

#ifndef _ASM_BUGFRAME_TEXT

#define _ASM_BUGFRAME_TEXT(second_frame)                                            \
    ".Lbug%=:"BUG_INSTR"\n"                                                         \
    "   .pushsection .bug_frames.%"BUG_ASM_CONST"[bf_type], \"a\", %%progbits\n"    \
    "   .p2align 2\n"                                                               \
    ".Lfrm%=:\n"                                                                    \
    "   .long (.Lbug%= - .Lfrm%=) + %"BUG_ASM_CONST"[bf_line_hi]\n"                 \
    "   .long (%"BUG_ASM_CONST"[bf_ptr] - .Lfrm%=) + %"BUG_ASM_CONST"[bf_line_lo]\n"\
    "   .if " #second_frame "\n"                                                    \
    "   .long 0, %"BUG_ASM_CONST"[bf_msg] - .Lfrm%=\n"                              \
    "   .endif\n"                                                                   \
    "   .popsection\n"

#define _ASM_BUGFRAME_INFO(type, line, ptr, msg)                             \
    [bf_type]    "i" (type),                                                 \
    [bf_ptr]     "i" (ptr),                                                  \
    [bf_msg]     "i" (msg),                                                  \
    [bf_line_lo] "i" (((line) & ((1 << BUG_LINE_LO_WIDTH) - 1))              \
                      << BUG_DISP_WIDTH),                                    \
    [bf_line_hi] "i" (((line) >> BUG_LINE_LO_WIDTH) << BUG_DISP_WIDTH)

#endif /* _ASM_BUGFRAME_TEXT */

#ifndef BUG_FRAME

#define BUG_FRAME(type, line, ptr, second_frame, msg) do {                   \
    BUG_CHECK_LINE_WIDTH(line);                                           \
    BUILD_BUG_ON((type) >= BUGFRAME_NR);                                     \
    asm volatile ( _ASM_BUGFRAME_TEXT(second_frame)                          \
                   :: _ASM_BUGFRAME_INFO(type, line, ptr, msg) );            \
} while ( false )

#endif

struct cpu_user_regs;
typedef void bug_fn_t(const struct cpu_user_regs *regs);

#ifndef run_in_exception_handler

static void always_inline run_in_exception_handler(bug_fn_t *fn)
{
    BUG_FRAME(BUGFRAME_run_fn, 0, fn, 0, NULL);
}

#endif /* run_in_exception_handler */

#ifndef WARN
#define WARN() BUG_FRAME(BUGFRAME_warn, __LINE__, __FILE__, 0, NULL)
#endif

#ifndef BUG
#define BUG() do {                                              \
    BUG_FRAME(BUGFRAME_bug,  __LINE__, __FILE__, 0, NULL);      \
    unreachable();                                              \
} while ( false )
#endif

#ifndef assert_failed
#define assert_failed(msg) do {                                 \
    BUG_FRAME(BUGFRAME_assert, __LINE__, __FILE__, 1, msg);     \
    unreachable();                                              \
} while ( false )
#endif

#define BUG_ON(p)  do { if (unlikely(p)) BUG();  } while (0)
#define WARN_ON(p)  ({                  \
    bool ret_warn_on_ = (p);            \
                                        \
    if ( unlikely(ret_warn_on_) )       \
        WARN();                         \
    unlikely(ret_warn_on_);             \
})

#ifndef NDEBUG
#define ASSERT(p) \
    do { if ( unlikely(!(p)) ) assert_failed(#p); } while (0)
#define ASSERT_UNREACHABLE() assert_failed("unreachable")
#else
#define ASSERT(p) do { if ( 0 && (p) ) {} } while (0)
#define ASSERT_UNREACHABLE() do { } while (0)
#endif

#ifdef CONFIG_GENERIC_BUG_FRAME

/*
 * Returns a negative value in case of an error otherwise
 * BUGFRAME_{run_fn, warn, bug, assert}
 */
int do_bug_frame(const struct cpu_user_regs *regs, unsigned long pc);

#endif /* CONFIG_GENERIC_BUG_FRAME */

#endif /* !__ASSEMBLY__ */

#endif /* __XEN_BUG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
