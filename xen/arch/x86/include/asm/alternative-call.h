/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_ALTERNATIVE_CALL_H
#define X86_ALTERNATIVE_CALL_H

#include <xen/macros.h>
#include <xen/stdint.h>

/* Simply the relative position of the source call. */
struct alt_call {
    int32_t offset;
};
#define ALT_CALL_PTR(a) ((void *)&(a)->offset + (a)->offset)
#define ALT_CALL_LEN(a) (6)

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

#ifdef CONFIG_CC_IS_CLANG
/*
 * Clang doesn't follow the psABI and doesn't truncate parameter values at the
 * callee.  This can lead to bad code being generated when using alternative
 * calls.
 *
 * Workaround it by using a temporary intermediate variable that's zeroed
 * before being assigned the parameter value, as that forces clang to zero the
 * register at the caller.
 *
 * This has been reported upstream:
 * https://github.com/llvm/llvm-project/issues/12579
 * https://github.com/llvm/llvm-project/issues/82598
 */
#define ALT_CALL_ARG(arg, n)                                            \
    register unsigned long a ## n ## _ asm ( ALT_CALL_arg ## n ) = ({   \
        unsigned long tmp = 0;                                          \
        BUILD_BUG_ON(sizeof(arg) > sizeof(unsigned long));              \
        *(typeof(arg) *)&tmp = (arg);                                   \
        tmp;                                                            \
    })
#else
#define ALT_CALL_ARG(arg, n) \
    register typeof(arg) a ## n ## _ asm ( ALT_CALL_arg ## n ) = \
        ({ BUILD_BUG_ON(sizeof(arg) > sizeof(void *)); (arg); })
#endif
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
    asm_inline volatile (                                          \
                  "1: call *%c[addr](%%rip)\n\t"                   \
                  ".pushsection .alt_call_sites, \"a\", @progbits\n\t"  \
                  ".long 1b - .\n\t"                               \
                  ".popsection"                                    \
                  : ALT_CALL ## n ## _OUT, "=a" (ret_),            \
                    "=r" (r10_), "=r" (r11_) ASM_CALL_CONSTRAINT   \
                  : [addr] "i" (&(func)), "g" (func)               \
                  : "memory" );                                    \
    ret_;                                                          \
})

#define alternative_vcall0(func) ({             \
    ALT_CALL_NO_ARG1;                           \
    (void)sizeof(func());                       \
    (void)alternative_callN(0, int, func);      \
})

#define alternative_call0(func) ({              \
    ALT_CALL_NO_ARG1;                           \
    alternative_callN(0, typeof(func()), func); \
})

#define alternative_vcall1(func, arg) ({           \
    typeof(arg) v1_ = (arg);                       \
    ALT_CALL_ARG(v1_, 1);                          \
    ALT_CALL_NO_ARG2;                              \
    (void)sizeof(func(arg));                       \
    (void)alternative_callN(1, int, func);         \
})

#define alternative_call1(func, arg) ({            \
    typeof(arg) v1_ = (arg);                       \
    ALT_CALL_ARG(v1_, 1);                          \
    ALT_CALL_NO_ARG2;                              \
    alternative_callN(1, typeof(func(arg)), func); \
})

#define alternative_vcall2(func, arg1, arg2) ({           \
    typeof(arg1) v1_ = (arg1);                            \
    typeof(arg2) v2_ = (arg2);                            \
    ALT_CALL_ARG(v1_, 1);                                 \
    ALT_CALL_ARG(v2_, 2);                                 \
    ALT_CALL_NO_ARG3;                                     \
    (void)sizeof(func(arg1, arg2));                       \
    (void)alternative_callN(2, int, func);                \
})

#define alternative_call2(func, arg1, arg2) ({            \
    typeof(arg1) v1_ = (arg1);                            \
    typeof(arg2) v2_ = (arg2);                            \
    ALT_CALL_ARG(v1_, 1);                                 \
    ALT_CALL_ARG(v2_, 2);                                 \
    ALT_CALL_NO_ARG3;                                     \
    alternative_callN(2, typeof(func(arg1, arg2)), func); \
})

#define alternative_vcall3(func, arg1, arg2, arg3) ({    \
    typeof(arg1) v1_ = (arg1);                           \
    typeof(arg2) v2_ = (arg2);                           \
    typeof(arg3) v3_ = (arg3);                           \
    ALT_CALL_ARG(v1_, 1);                                \
    ALT_CALL_ARG(v2_, 2);                                \
    ALT_CALL_ARG(v3_, 3);                                \
    ALT_CALL_NO_ARG4;                                    \
    (void)sizeof(func(arg1, arg2, arg3));                \
    (void)alternative_callN(3, int, func);               \
})

#define alternative_call3(func, arg1, arg2, arg3) ({     \
    typeof(arg1) v1_ = (arg1);                           \
    typeof(arg2) v2_ = (arg2);                           \
    typeof(arg3) v3_ = (arg3);                           \
    ALT_CALL_ARG(v1_, 1);                                \
    ALT_CALL_ARG(v2_, 2);                                \
    ALT_CALL_ARG(v3_, 3);                                \
    ALT_CALL_NO_ARG4;                                    \
    alternative_callN(3, typeof(func(arg1, arg2, arg3)), \
                      func);                             \
})

#define alternative_vcall4(func, arg1, arg2, arg3, arg4) ({ \
    typeof(arg1) v1_ = (arg1);                              \
    typeof(arg2) v2_ = (arg2);                              \
    typeof(arg3) v3_ = (arg3);                              \
    typeof(arg4) v4_ = (arg4);                              \
    ALT_CALL_ARG(v1_, 1);                                   \
    ALT_CALL_ARG(v2_, 2);                                   \
    ALT_CALL_ARG(v3_, 3);                                   \
    ALT_CALL_ARG(v4_, 4);                                   \
    ALT_CALL_NO_ARG5;                                       \
    (void)sizeof(func(arg1, arg2, arg3, arg4));             \
    (void)alternative_callN(4, int, func);                  \
})

#define alternative_call4(func, arg1, arg2, arg3, arg4) ({  \
    typeof(arg1) v1_ = (arg1);                              \
    typeof(arg2) v2_ = (arg2);                              \
    typeof(arg3) v3_ = (arg3);                              \
    typeof(arg4) v4_ = (arg4);                              \
    ALT_CALL_ARG(v1_, 1);                                   \
    ALT_CALL_ARG(v2_, 2);                                   \
    ALT_CALL_ARG(v3_, 3);                                   \
    ALT_CALL_ARG(v4_, 4);                                   \
    ALT_CALL_NO_ARG5;                                       \
    alternative_callN(4, typeof(func(arg1, arg2,            \
                                     arg3, arg4)),          \
                      func);                                \
})

#define alternative_vcall5(func, arg1, arg2, arg3, arg4, arg5) ({ \
    typeof(arg1) v1_ = (arg1);                                    \
    typeof(arg2) v2_ = (arg2);                                    \
    typeof(arg3) v3_ = (arg3);                                    \
    typeof(arg4) v4_ = (arg4);                                    \
    typeof(arg5) v5_ = (arg5);                                    \
    ALT_CALL_ARG(v1_, 1);                                         \
    ALT_CALL_ARG(v2_, 2);                                         \
    ALT_CALL_ARG(v3_, 3);                                         \
    ALT_CALL_ARG(v4_, 4);                                         \
    ALT_CALL_ARG(v5_, 5);                                         \
    ALT_CALL_NO_ARG6;                                             \
    (void)sizeof(func(arg1, arg2, arg3, arg4, arg5));             \
    (void)alternative_callN(5, int, func);                        \
})

#define alternative_call5(func, arg1, arg2, arg3, arg4, arg5) ({  \
    typeof(arg1) v1_ = (arg1);                                    \
    typeof(arg2) v2_ = (arg2);                                    \
    typeof(arg3) v3_ = (arg3);                                    \
    typeof(arg4) v4_ = (arg4);                                    \
    typeof(arg5) v5_ = (arg5);                                    \
    ALT_CALL_ARG(v1_, 1);                                         \
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
    typeof(arg1) v1_ = (arg1);                                          \
    typeof(arg2) v2_ = (arg2);                                          \
    typeof(arg3) v3_ = (arg3);                                          \
    typeof(arg4) v4_ = (arg4);                                          \
    typeof(arg5) v5_ = (arg5);                                          \
    typeof(arg6) v6_ = (arg6);                                          \
    ALT_CALL_ARG(v1_, 1);                                               \
    ALT_CALL_ARG(v2_, 2);                                               \
    ALT_CALL_ARG(v3_, 3);                                               \
    ALT_CALL_ARG(v4_, 4);                                               \
    ALT_CALL_ARG(v5_, 5);                                               \
    ALT_CALL_ARG(v6_, 6);                                               \
    (void)sizeof(func(arg1, arg2, arg3, arg4, arg5, arg6));             \
    (void)alternative_callN(6, int, func);                              \
})

#define alternative_call6(func, arg1, arg2, arg3, arg4, arg5, arg6) ({  \
    typeof(arg1) v1_ = (arg1);                                          \
    typeof(arg2) v2_ = (arg2);                                          \
    typeof(arg3) v3_ = (arg3);                                          \
    typeof(arg4) v4_ = (arg4);                                          \
    typeof(arg5) v5_ = (arg5);                                          \
    typeof(arg6) v6_ = (arg6);                                          \
    ALT_CALL_ARG(v1_, 1);                                               \
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

#endif /* X86_ALTERNATIVE_CALL_H */
