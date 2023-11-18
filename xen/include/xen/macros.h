#ifndef __MACROS_H__
#define __MACROS_H__

#define ROUNDUP(x, a) (((x) + (a) - 1) & ~((a) - 1))

#define IS_ALIGNED(val, align) (!((val) & ((align) - 1)))

#define DIV_ROUND(n, d) (((n) + (d) / 2) / (d))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/*
 * Given an unsigned integer argument, expands to a mask where just the least
 * significant nonzero bit of the argument is set, or 0 if no bits are set.
 */
#define ISOLATE_LSB(x) ((x) & -(x))

#define MASK_EXTR(v, m) (((v) & (m)) / ISOLATE_LSB(m))
#define MASK_INSR(v, m) (((v) * ISOLATE_LSB(m)) & (m))

#define count_args_(dot, a1, a2, a3, a4, a5, a6, a7, a8, x, ...) x
#define count_args(args...) \
    count_args_(., ## args, 8, 7, 6, 5, 4, 3, 2, 1, 0)

/* Indirect macros required for expanded argument pasting. */
#define PASTE_(a, b) a ## b
#define PASTE(a, b) PASTE_(a, b)

#define __STR(...) #__VA_ARGS__
#define STR(...) __STR(__VA_ARGS__)

#ifndef __ASSEMBLY__

/* All clang versions supported by Xen have _Static_assert. */
#if defined(__clang__) || \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(cond) ({ _Static_assert(!(cond), "!(" #cond ")"); })

/*
 * Force a compilation error if condition is true, but also produce a
 * result (of value 0 and type size_t), so the expression can be used
 * e.g. in a structure initializer (or where-ever else comma expressions
 * aren't permitted).
 */
#define BUILD_BUG_ON_ZERO(cond) \
    (sizeof(struct { char c; _Static_assert(!(cond), "!(" #cond ")"); }) & 0)
#else
#define BUILD_BUG_ON_ZERO(cond) \
    (sizeof(struct { unsigned u : !(cond); }) & 0)
#define BUILD_BUG_ON(cond) ((void)BUILD_BUG_ON_ZERO(cond))
#endif

#define ABS(x) ({                              \
    typeof(x) x_ = (x);                        \
    (x_ < 0) ? -x_ : x_;                       \
})

#define SWAP(a, b) \
   do { typeof(a) t_ = (a); (a) = (b); (b) = t_; } while ( 0 )

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]) + __must_be_array(x))

/**
 * typeof_field(type, member)
 *
 * @type: The structure containing the field of interest
 * @member: The field whose type is returned
 */
#define typeof_field(type, member) typeof(((type *)NULL)->member)

/**
 * sizeof_field(type, member)
 *
 * @type: The structure containing the field of interest
 * @member: The field to return the size of
 */
#define sizeof_field(type, member) sizeof(((type *)NULL)->member)

#endif /* __ASSEMBLY__ */

#endif /* __MACROS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
