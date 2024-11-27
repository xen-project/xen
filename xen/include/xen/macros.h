#ifndef __MACROS_H__
#define __MACROS_H__

#define ROUNDUP(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define ROUNDDOWN(x, a) ((x) & ~((a) - 1))

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

#define ARG1_(x, y...) (x)
#define ARG2_(x, y...) ARG1_(y)
#define ARG3_(x, y...) ARG2_(y)
#define ARG4_(x, y...) ARG3_(y)

#define ARG__(nr) ARG ## nr ## _
#define ARG_(nr)  ARG__(nr)
#define LASTARG(x, y...) ARG_(count_args(x, ## y))(x, ## y)

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

/*
 * Force a compilation error.  This is for code which, in the normal case,
 * should be Dead Code Eliminated, but a failure to eliminate constitutes an
 * error.  e.g. behind a __builtin_constant_p(), or an illegal case within a
 * switch(sizeof(...)) construct.
 */
#define BUILD_ERROR(msg) asm ( ".error \"" msg "\"" )

/* Hide a value from the optimiser. */
#define HIDE(x)                                 \
    ({                                          \
        typeof(x) _x = (x);                     \
        asm volatile ( "" : "+r" (_x) );        \
        _x;                                     \
    })

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

/* Cast an arbitrary integer to a pointer. */
#define _p(x) ((void *)(unsigned long)(x))

/*
 * min()/max() macros that also do strict type-checking..
 */
#define min(x, y)                               \
    ({                                          \
        const typeof(x) _x = (x);               \
        const typeof(y) _y = (y);               \
        (void)(&_x == &_y); /* typecheck */     \
        _x < _y ? _x : _y;                      \
    })
#define max(x, y)                               \
    ({                                          \
        const typeof(x) _x = (x);               \
        const typeof(y) _y = (y);               \
        (void)(&_x == &_y); /* typecheck */     \
        _x > _y ? _x : _y;                      \
    })

/*
 * ..and if you can't take the strict types, you can specify one yourself.
 */
#define min_t(type, x, y)                       \
    ({                                          \
        type __x = (x);                         \
        type __y = (y);                         \
        __x < __y ? __x: __y;                   \
    })
#define max_t(type, x, y)                       \
    ({                                          \
        type __x = (x);                         \
        type __y = (y);                         \
        __x > __y ? __x: __y;                   \
    })

/*
 * pre-processor, array size, and bit field width suitable variants;
 * please don't use in "normal" expressions.
 */
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

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
