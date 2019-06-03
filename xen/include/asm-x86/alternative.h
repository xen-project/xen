#ifndef __X86_ALTERNATIVE_H__
#define __X86_ALTERNATIVE_H__

#ifdef __ASSEMBLY__
#include <asm/alternative-asm.h>
#else
#include <xen/lib.h>
#include <xen/stringify.h>
#include <asm/asm-macros.h>

struct __packed alt_instr {
    int32_t  orig_offset;   /* original instruction */
    int32_t  repl_offset;   /* offset to replacement instruction */
    uint16_t cpuid;         /* cpuid bit set for replacement */
    uint8_t  orig_len;      /* length of original instruction */
    uint8_t  repl_len;      /* length of new instruction */
    uint8_t  pad_len;       /* length of build-time padding */
    uint8_t  priv;          /* Private, for use by apply_alternatives() */
};

#define __ALT_PTR(a,f)      ((uint8_t *)((void *)&(a)->f + (a)->f))
#define ALT_ORIG_PTR(a)     __ALT_PTR(a, orig_offset)
#define ALT_REPL_PTR(a)     __ALT_PTR(a, repl_offset)

extern void add_nops(void *insns, unsigned int len);
/* Similar to alternative_instructions except it can be run with IRQs enabled. */
extern void apply_alternatives(struct alt_instr *start, struct alt_instr *end);
extern void alternative_instructions(void);
extern void alternative_branches(void);

#define alt_orig_len       "(.LXEN%=_orig_e - .LXEN%=_orig_s)"
#define alt_pad_len        "(.LXEN%=_orig_p - .LXEN%=_orig_e)"
#define alt_total_len      "(.LXEN%=_orig_p - .LXEN%=_orig_s)"
#define alt_repl_s(num)    ".LXEN%=_repl_s"#num
#define alt_repl_e(num)    ".LXEN%=_repl_e"#num
#define alt_repl_len(num)  "(" alt_repl_e(num) " - " alt_repl_s(num) ")"

/* GAS's idea of true is -1, while Clang's idea is 1. */
#ifdef HAVE_AS_NEGATIVE_TRUE
# define AS_TRUE "-"
#else
# define AS_TRUE ""
#endif

#define as_max(a, b) "(("a") ^ ((("a") ^ ("b")) & -("AS_TRUE"(("a") < ("b")))))"

#define OLDINSTR(oldinstr, padding)                              \
    ".LXEN%=_orig_s:\n\t" oldinstr "\n .LXEN%=_orig_e:\n\t"      \
    ".LXEN%=_diff = " padding "\n\t"                             \
    "mknops ("AS_TRUE"(.LXEN%=_diff > 0) * .LXEN%=_diff)\n\t"    \
    ".LXEN%=_orig_p:\n\t"

#define OLDINSTR_1(oldinstr, n1)                                 \
    OLDINSTR(oldinstr, alt_repl_len(n1) "-" alt_orig_len)

#define OLDINSTR_2(oldinstr, n1, n2)                             \
    OLDINSTR(oldinstr,                                           \
             as_max(alt_repl_len(n1),                            \
                    alt_repl_len(n2)) "-" alt_orig_len)

#define ALTINSTR_ENTRY(feature, num)                                    \
        " .long .LXEN%=_orig_s - .\n"             /* label           */ \
        " .long " alt_repl_s(num)" - .\n"         /* new instruction */ \
        " .word " __stringify(feature) "\n"       /* feature bit     */ \
        " .byte " alt_orig_len "\n"               /* source len      */ \
        " .byte " alt_repl_len(num) "\n"          /* replacement len */ \
        " .byte " alt_pad_len "\n"                /* padding len     */ \
        " .byte 0\n"                              /* priv            */

#define DISCARD_ENTRY(num)                        /* repl <= total */   \
        " .byte 0xff + (" alt_repl_len(num) ") - (" alt_total_len ")\n"

#define ALTINSTR_REPLACEMENT(newinstr, num)       /* replacement */     \
        alt_repl_s(num)":\n\t" newinstr "\n" alt_repl_e(num) ":\n\t"

/* alternative assembly primitive: */
#define ALTERNATIVE(oldinstr, newinstr, feature)                        \
        OLDINSTR_1(oldinstr, 1)                                         \
        ".pushsection .altinstructions, \"a\", @progbits\n"             \
        ALTINSTR_ENTRY(feature, 1)                                      \
        ".section .discard, \"a\", @progbits\n"                         \
        ".byte " alt_total_len "\n" /* total_len <= 255 */              \
        DISCARD_ENTRY(1)                                                \
        ".section .altinstr_replacement, \"ax\", @progbits\n"           \
        ALTINSTR_REPLACEMENT(newinstr, 1)                               \
        ".popsection\n"

#define ALTERNATIVE_2(oldinstr, newinstr1, feature1, newinstr2, feature2) \
        OLDINSTR_2(oldinstr, 1, 2)                                      \
        ".pushsection .altinstructions, \"a\", @progbits\n"             \
        ALTINSTR_ENTRY(feature1, 1)                                     \
        ALTINSTR_ENTRY(feature2, 2)                                     \
        ".section .discard, \"a\", @progbits\n"                         \
        ".byte " alt_total_len "\n" /* total_len <= 255 */              \
        DISCARD_ENTRY(1)                                                \
        DISCARD_ENTRY(2)                                                \
        ".section .altinstr_replacement, \"ax\", @progbits\n"           \
        ALTINSTR_REPLACEMENT(newinstr1, 1)                              \
        ALTINSTR_REPLACEMENT(newinstr2, 2)                              \
        ".popsection\n"

/*
 * Alternative instructions for different CPU types or capabilities.
 *
 * This allows to use optimized instructions even on generic binary
 * kernels.
 *
 * length of oldinstr must be longer or equal the length of newinstr
 * It can be padded with nops as needed.
 *
 * For non barrier like inlines please define new variants
 * without volatile and memory clobber.
 */
#define alternative(oldinstr, newinstr, feature)                        \
        asm volatile (ALTERNATIVE(oldinstr, newinstr, feature) : : : "memory")

/*
 * Alternative inline assembly with input.
 *
 * Pecularities:
 * No memory clobber here.
 * Argument numbers start with 1.
 * Best is to use constraints that are fixed size (like (%1) ... "r")
 * If you use variable sized constraints like "m" or "g" in the
 * replacement make sure to pad to the worst case length.
 */
#define alternative_input(oldinstr, newinstr, feature, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		      : : input)

/* Like alternative_input, but with a single output argument */
#define alternative_io(oldinstr, newinstr, feature, output, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		      : output : input)

/*
 * This is similar to alternative_io. But it has two features and
 * respective instructions.
 *
 * If CPU has feature2, newinstr2 is used.
 * Otherwise, if CPU has feature1, newinstr1 is used.
 * Otherwise, oldinstr is used.
 */
#define alternative_io_2(oldinstr, newinstr1, feature1, newinstr2,	\
			 feature2, output, input...)			\
	asm volatile(ALTERNATIVE_2(oldinstr, newinstr1, feature1,	\
				   newinstr2, feature2)			\
		     : output : input)

/* Use this macro(s) if you need more than one output parameter. */
#define ASM_OUTPUT2(a...) a

/*
 * Machinery to allow converting indirect to direct calls, when the called
 * function is determined once at boot and later never changed.
 */

#define ALT_CALL_arg1 "rdi"
#define ALT_CALL_arg2 "rsi"
#define ALT_CALL_arg3 "rdx"
#define ALT_CALL_arg4 "rcx"
#define ALT_CALL_arg5 "r8"
#define ALT_CALL_arg6 "r9"

#define ALT_CALL_ARG(arg, n) \
    register typeof((arg) ? (arg) : 0) a ## n ## _ \
    asm ( ALT_CALL_arg ## n ) = (arg)
#define ALT_CALL_NO_ARG(n) \
    register unsigned long a ## n ## _ asm ( ALT_CALL_arg ## n )

#define ALT_CALL_NO_ARG6 ALT_CALL_NO_ARG(6)
#define ALT_CALL_NO_ARG5 ALT_CALL_NO_ARG(5); ALT_CALL_NO_ARG6
#define ALT_CALL_NO_ARG4 ALT_CALL_NO_ARG(4); ALT_CALL_NO_ARG5
#define ALT_CALL_NO_ARG3 ALT_CALL_NO_ARG(3); ALT_CALL_NO_ARG4
#define ALT_CALL_NO_ARG2 ALT_CALL_NO_ARG(2); ALT_CALL_NO_ARG3
#define ALT_CALL_NO_ARG1 ALT_CALL_NO_ARG(1); ALT_CALL_NO_ARG2

/*
 * Unfortunately ALT_CALL_NO_ARG() above can't use a fake initializer (to
 * suppress "uninitialized variable" warnings), as various versions of gcc
 * older than 8.1 fall on the nose in various ways with that (always because
 * of some other construct elsewhere in the same function needing to use the
 * same hard register). Otherwise the asm() below could uniformly use "+r"
 * output constraints, making unnecessary all these ALT_CALL<n>_OUT macros.
 */
#define ALT_CALL0_OUT "=r" (a1_), "=r" (a2_), "=r" (a3_), \
                      "=r" (a4_), "=r" (a5_), "=r" (a6_)
#define ALT_CALL1_OUT "+r" (a1_), "=r" (a2_), "=r" (a3_), \
                      "=r" (a4_), "=r" (a5_), "=r" (a6_)
#define ALT_CALL2_OUT "+r" (a1_), "+r" (a2_), "=r" (a3_), \
                      "=r" (a4_), "=r" (a5_), "=r" (a6_)
#define ALT_CALL3_OUT "+r" (a1_), "+r" (a2_), "+r" (a3_), \
                      "=r" (a4_), "=r" (a5_), "=r" (a6_)
#define ALT_CALL4_OUT "+r" (a1_), "+r" (a2_), "+r" (a3_), \
                      "+r" (a4_), "=r" (a5_), "=r" (a6_)
#define ALT_CALL5_OUT "+r" (a1_), "+r" (a2_), "+r" (a3_), \
                      "+r" (a4_), "+r" (a5_), "=r" (a6_)
#define ALT_CALL6_OUT "+r" (a1_), "+r" (a2_), "+r" (a3_), \
                      "+r" (a4_), "+r" (a5_), "+r" (a6_)

#define alternative_callN(n, rettype, func) ({                     \
    rettype ret_;                                                  \
    register unsigned long r10_ asm("r10");                        \
    register unsigned long r11_ asm("r11");                        \
    asm volatile (ALTERNATIVE("call *%c[addr](%%rip)", "call .",   \
                              X86_FEATURE_ALWAYS)                  \
                  : ALT_CALL ## n ## _OUT, "=a" (ret_),            \
                    "=r" (r10_), "=r" (r11_) ASM_CALL_CONSTRAINT   \
                  : [addr] "i" (&(func)), "g" (func)               \
                  : "memory" );                                    \
    ret_;                                                          \
})

#define alternative_vcall0(func) ({             \
    ALT_CALL_NO_ARG1;                           \
    ((void)alternative_callN(0, int, func));    \
})

#define alternative_call0(func) ({              \
    ALT_CALL_NO_ARG1;                           \
    alternative_callN(0, typeof(func()), func); \
})

#define alternative_vcall1(func, arg) ({           \
    ALT_CALL_ARG(arg, 1);                          \
    ALT_CALL_NO_ARG2;                              \
    (void)sizeof(func(arg));                       \
    (void)alternative_callN(1, int, func);         \
})

#define alternative_call1(func, arg) ({            \
    ALT_CALL_ARG(arg, 1);                          \
    ALT_CALL_NO_ARG2;                              \
    alternative_callN(1, typeof(func(arg)), func); \
})

#define alternative_vcall2(func, arg1, arg2) ({           \
    typeof(arg2) v2_ = (arg2);                            \
    ALT_CALL_ARG(arg1, 1);                                \
    ALT_CALL_ARG(v2_, 2);                                 \
    ALT_CALL_NO_ARG3;                                     \
    (void)sizeof(func(arg1, arg2));                       \
    (void)alternative_callN(2, int, func);                \
})

#define alternative_call2(func, arg1, arg2) ({            \
    typeof(arg2) v2_ = (arg2);                            \
    ALT_CALL_ARG(arg1, 1);                                \
    ALT_CALL_ARG(v2_, 2);                                 \
    ALT_CALL_NO_ARG3;                                     \
    alternative_callN(2, typeof(func(arg1, arg2)), func); \
})

#define alternative_vcall3(func, arg1, arg2, arg3) ({    \
    typeof(arg2) v2_ = (arg2);                           \
    typeof(arg3) v3_ = (arg3);                           \
    ALT_CALL_ARG(arg1, 1);                               \
    ALT_CALL_ARG(v2_, 2);                                \
    ALT_CALL_ARG(v3_, 3);                                \
    ALT_CALL_NO_ARG4;                                    \
    (void)sizeof(func(arg1, arg2, arg3));                \
    (void)alternative_callN(3, int, func);               \
})

#define alternative_call3(func, arg1, arg2, arg3) ({     \
    typeof(arg2) v2_ = (arg2);                           \
    typeof(arg3) v3_ = (arg3);                           \
    ALT_CALL_ARG(arg1, 1);                               \
    ALT_CALL_ARG(v2_, 2);                                \
    ALT_CALL_ARG(v3_, 3);                                \
    ALT_CALL_NO_ARG4;                                    \
    alternative_callN(3, typeof(func(arg1, arg2, arg3)), \
                      func);                             \
})

#define alternative_vcall4(func, arg1, arg2, arg3, arg4) ({ \
    typeof(arg2) v2_ = (arg2);                              \
    typeof(arg3) v3_ = (arg3);                              \
    typeof(arg4) v4_ = (arg4);                              \
    ALT_CALL_ARG(arg1, 1);                                  \
    ALT_CALL_ARG(v2_, 2);                                   \
    ALT_CALL_ARG(v3_, 3);                                   \
    ALT_CALL_ARG(v4_, 4);                                   \
    ALT_CALL_NO_ARG5;                                       \
    (void)sizeof(func(arg1, arg2, arg3, arg4));             \
    (void)alternative_callN(4, int, func);                  \
})

#define alternative_call4(func, arg1, arg2, arg3, arg4) ({  \
    typeof(arg2) v2_ = (arg2);                              \
    typeof(arg3) v3_ = (arg3);                              \
    typeof(arg4) v4_ = (arg4);                              \
    ALT_CALL_ARG(arg1, 1);                                  \
    ALT_CALL_ARG(v2_, 2);                                   \
    ALT_CALL_ARG(v3_, 3);                                   \
    ALT_CALL_ARG(v4_, 4);                                   \
    ALT_CALL_NO_ARG5;                                       \
    alternative_callN(4, typeof(func(arg1, arg2,            \
                                     arg3, arg4)),          \
                      func);                                \
})

#define alternative_vcall5(func, arg1, arg2, arg3, arg4, arg5) ({ \
    typeof(arg2) v2_ = (arg2);                                    \
    typeof(arg3) v3_ = (arg3);                                    \
    typeof(arg4) v4_ = (arg4);                                    \
    typeof(arg5) v5_ = (arg5);                                    \
    ALT_CALL_ARG(arg1, 1);                                        \
    ALT_CALL_ARG(v2_, 2);                                         \
    ALT_CALL_ARG(v3_, 3);                                         \
    ALT_CALL_ARG(v4_, 4);                                         \
    ALT_CALL_ARG(v5_, 5);                                         \
    ALT_CALL_NO_ARG6;                                             \
    (void)sizeof(func(arg1, arg2, arg3, arg4, arg5));             \
    (void)alternative_callN(5, int, func);                        \
})

#define alternative_call5(func, arg1, arg2, arg3, arg4, arg5) ({  \
    typeof(arg2) v2_ = (arg2);                                    \
    typeof(arg3) v3_ = (arg3);                                    \
    typeof(arg4) v4_ = (arg4);                                    \
    typeof(arg5) v5_ = (arg5);                                    \
    ALT_CALL_ARG(arg1, 1);                                        \
    ALT_CALL_ARG(v2_, 2);                                         \
    ALT_CALL_ARG(v3_, 3);                                         \
    ALT_CALL_ARG(v4_, 4);                                         \
    ALT_CALL_ARG(v5_, 5);                                         \
    ALT_CALL_NO_ARG6;                                             \
    alternative_callN(5, typeof(func(arg1, arg2, arg3,            \
                                     arg4, arg5)),                \
                      func);                                      \
})

#define alternative_vcall6(func, arg1, arg2, arg3, arg4, arg5, arg6) ({ \
    typeof(arg2) v2_ = (arg2);                                          \
    typeof(arg3) v3_ = (arg3);                                          \
    typeof(arg4) v4_ = (arg4);                                          \
    typeof(arg5) v5_ = (arg5);                                          \
    typeof(arg6) v6_ = (arg6);                                          \
    ALT_CALL_ARG(arg1, 1);                                              \
    ALT_CALL_ARG(v2_, 2);                                               \
    ALT_CALL_ARG(v3_, 3);                                               \
    ALT_CALL_ARG(v4_, 4);                                               \
    ALT_CALL_ARG(v5_, 5);                                               \
    ALT_CALL_ARG(v6_, 6);                                               \
    (void)sizeof(func(arg1, arg2, arg3, arg4, arg5, arg6));             \
    (void)alternative_callN(6, int, func);                              \
})

#define alternative_call6(func, arg1, arg2, arg3, arg4, arg5, arg6) ({  \
    typeof(arg2) v2_ = (arg2);                                          \
    typeof(arg3) v3_ = (arg3);                                          \
    typeof(arg4) v4_ = (arg4);                                          \
    typeof(arg5) v5_ = (arg5);                                          \
    typeof(arg6) v6_ = (arg6);                                          \
    ALT_CALL_ARG(arg1, 1);                                              \
    ALT_CALL_ARG(v2_, 2);                                               \
    ALT_CALL_ARG(v3_, 3);                                               \
    ALT_CALL_ARG(v4_, 4);                                               \
    ALT_CALL_ARG(v5_, 5);                                               \
    ALT_CALL_ARG(v6_, 6);                                               \
    alternative_callN(6, typeof(func(arg1, arg2, arg3,                  \
                                     arg4, arg5, arg6)),                \
                      func);                                            \
})

#define alternative_vcall__(nr) alternative_vcall ## nr
#define alternative_call__(nr)  alternative_call ## nr

#define alternative_vcall_(nr) alternative_vcall__(nr)
#define alternative_call_(nr)  alternative_call__(nr)

#define alternative_vcall(func, args...) \
    alternative_vcall_(count_args(args))(func, ## args)

#define alternative_call(func, args...) \
    alternative_call_(count_args(args))(func, ## args)

#endif /*  !__ASSEMBLY__  */

#endif /* __X86_ALTERNATIVE_H__ */
