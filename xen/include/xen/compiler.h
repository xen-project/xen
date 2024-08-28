#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#if !defined(__GNUC__) || (__GNUC__ < 4)
#error Sorry, your compiler is too old/not recognized.
#elif CONFIG_CC_IS_GCC
# if defined(CONFIG_ARM_32) && CONFIG_GCC_VERSION < 40900
#  error Sorry, your version of GCC is too old - please use 4.9 or newer.
# elif defined(CONFIG_ARM_64) && CONFIG_GCC_VERSION < 50100
/*
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63293
 * https://lore.kernel.org/r/20210107111841.GN1551@shell.armlinux.org.uk
 */
#  error Sorry, your version of GCC is too old - please use 5.1 or newer.
# endif
#endif

#define barrier()     __asm__ __volatile__("": : :"memory")

#define likely(x)     __builtin_expect(!!(x),1)
#define unlikely(x)   __builtin_expect(!!(x),0)

#define always_inline inline __attribute__((__always_inline__))
#define gnu_inline    inline __attribute__((__gnu_inline__))
#define noinline      __attribute__((__noinline__))

#define noreturn      __attribute__((__noreturn__))

#define __packed      __attribute__((__packed__))

#define __weak        __attribute__((__weak__))

#if !defined(CONFIG_CC_IS_CLANG) || CONFIG_CLANG_VERSION >= 140000
# define nocall       __attribute__((__error__("Nonstandard ABI")))
#else
# define nocall
#endif

#ifdef CONFIG_XEN_IBT
# define cf_check     __attribute__((__cf_check__))
#else
# define cf_check
#endif

#if (!defined(__clang__) && (__GNUC__ == 4) && (__GNUC_MINOR__ < 5))
#define unreachable() do {} while (1)
#else
#define unreachable() __builtin_unreachable()
#endif

/*
 * Add the pseudo keyword 'fallthrough' so case statement blocks
 * must end with any of these keywords:
 *   break;
 *   fallthrough;
 *   goto <label>;
 *   return [expression];
 *
 *  gcc: https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if (!defined(__clang__) && (__GNUC__ >= 7))
# define fallthrough        __attribute__((__fallthrough__))
#else
# define fallthrough        do {} while (0)  /* fallthrough */
#endif

#ifdef __clang__
/* Clang can replace some vars with new automatic ones that go in .data;
 * mark all explicit-segment vars 'used' to prevent that. */
#define __section(s)      __used __attribute__((__section__(s)))
#else
#define __section(s)      __attribute__((__section__(s)))
#endif
#define __used_section(s) __used __attribute__((__section__(s)))
#define __text_section(s) __attribute__((__section__(s)))

#define __aligned(a) __attribute__((__aligned__(a)))

#ifdef INIT_SECTIONS_ONLY
/*
 * For sources indicated to have only init code, make sure even
 * inline functions not expanded inline get placed in .init.text.
 */
#include <xen/init.h>
/* SAF-3-safe MISRA C Rule 20.4: allow section checks to pass when not inlined */
#define inline inline __init
#endif

#define __constructor       __attribute__((__constructor__)) cf_check
#define __pure              __attribute__((__pure__))
#define attr_const          __attribute__((__const__))
#define __transparent__     __attribute__((__transparent_union__))

/*
 * The difference between the following two attributes is that __used is
 * intended to be used in cases where a reference to an identifier may be
 * invisible to the compiler (e.g. an inline assembly operand not listed
 * in the asm()'s operands), preventing the compiler from eliminating the
 * variable or function.
 * __maybe_unused otoh is to be used to merely prevent warnings (e.g. when
 * an identifier is used only inside a preprocessor conditional, yet putting
 * its declaration/definition inside another conditional would harm code
 * readability).
 */
#define __used         __attribute__((__used__))
#define __maybe_unused __attribute__((__unused__))

#define __must_check __attribute__((__warn_unused_result__))
#define __nonnull(...) __attribute__((__nonnull__(__VA_ARGS__)))

#define offsetof(a,b) __builtin_offsetof(a,b)

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#define alignof __alignof__
#endif

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a) \
  BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&(a)[0])))

#ifdef CONFIG_CC_HAS_VISIBILITY_ATTRIBUTE
/* Results in more efficient PIC code (no indirections through GOT or PLT). */
#pragma GCC visibility push(hidden)
#endif

/* Make the optimizer believe the variable can be manipulated arbitrarily. */
#define OPTIMIZER_HIDE_VAR(var) __asm__ ( "" : "+g" (var) )

/* This macro obfuscates arithmetic on a variable address so that gcc
   shouldn't recognize the original var, and make assumptions about it */
/*
 * Versions of the ppc64 compiler before 4.1 had a bug where use of
 * RELOC_HIDE could trash r30. The bug can be worked around by changing
 * the inline assembly constraint from =g to =r, in this particular
 * case either is valid.
 */
#define RELOC_HIDE(ptr, off)                    \
  ({ unsigned long __ptr;                       \
    __asm__ ("" : "=r"(__ptr) : "0"(ptr));      \
    (typeof(ptr)) (__ptr + (off)); })

/* See gcc bug 100680. */
#if CONFIG_GCC_VERSION >= 110000 && CONFIG_GCC_VERSION < 110300
# define gcc11_wrap(x) RELOC_HIDE(x, 0)
#else
# define gcc11_wrap(x) (x)
#endif

#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define ASM_FLAG_OUT(yes, no) yes
#else
# define ASM_FLAG_OUT(yes, no) no
#endif

/* Mark a function or variable as being used only to interface with asm */
#ifndef asmlinkage
#define asmlinkage
#endif

/*
 * NB: we need to disable the gcc-compat warnings for clang in some places or
 * else it will complain with: "'break' is bound to loop, GCC binds it to
 * switch" when a switch is used inside of a while expression inside of a
 * switch statement, ie:
 *
 * switch ( ... )
 * {
 * case ...:
 *      while ( ({ int x; switch ( foo ) { case 1: x = 1; break; } x }) )
 *      {
 *              ...
 *
 * This has already been reported upstream:
 * http://bugs.llvm.org/show_bug.cgi?id=32595 
 */
#ifdef __clang__
# define CLANG_DISABLE_WARN_GCC_COMPAT_START                    \
    _Pragma("clang diagnostic push")                            \
    _Pragma("clang diagnostic ignored \"-Wgcc-compat\"")
# define CLANG_DISABLE_WARN_GCC_COMPAT_END                      \
    _Pragma("clang diagnostic pop")
#else
# define CLANG_DISABLE_WARN_GCC_COMPAT_START
# define CLANG_DISABLE_WARN_GCC_COMPAT_END
#endif

#endif /* __LINUX_COMPILER_H */
