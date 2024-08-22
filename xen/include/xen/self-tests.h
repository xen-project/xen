/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Helpers for Xen self-tests of basic logic, including confirming that
 * examples which should be calculated by the compiler are.
 */
#ifndef XEN_SELF_TESTS_H
#define XEN_SELF_TESTS_H

#include <xen/lib.h>

/*
 * Check that fn(val) can be calcuated by the compiler, and that it gives the
 * expected answer.
 *
 * Clang < 8 can't fold constants through static inlines, causing this to
 * fail.  Simply skip it for incredibly old compilers.
 *
 * N.B. fn is intentionally not bracketed to allow us to test function-like
 * macros too.
 */
#if !defined(CONFIG_CC_IS_CLANG) || CONFIG_CLANG_VERSION >= 80000
#define COMPILE_CHECK(fn, val, res)                                     \
    do {                                                                \
        typeof(fn(val)) real = fn(val);                                 \
                                                                        \
        if ( !__builtin_constant_p(real) )                              \
            BUILD_ERROR("'" STR(fn(val)) "' not compile-time constant"); \
        else if ( real != (res) )                                       \
            BUILD_ERROR("Compile time check '" STR(fn(val) == res) "' failed"); \
    } while ( 0 )
#else
#define COMPILE_CHECK(fn, val, res)
#endif

/*
 * Check that Xen's runtime logic for fn(val) gives the expected answer.  This
 * requires using HIDE() to prevent the optimiser from collapsing the logic
 * into a constant.
 *
 * N.B. fn is intentionally not bracketed to allow us to test function-like
 * macros too.
 */
#define RUNTIME_CHECK(fn, val, res)                     \
    do {                                                \
        typeof(fn(val)) real = fn(HIDE(val));           \
                                                        \
        if ( real != (res) )                            \
            panic("%s: %s(%s) expected %u, got %u\n",   \
                  __func__, #fn, #val, real, res);      \
    } while ( 0 )

/*
 * Perform compile-time and runtime checks for fn(val) == res.
 */
#define CHECK(fn, val, res)                     \
    do {                                        \
        COMPILE_CHECK(fn, val, res);            \
        RUNTIME_CHECK(fn, val, res);            \
    } while ( 0 )

#endif /* XEN_SELF_TESTS_H */
