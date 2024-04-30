#ifndef __XEN_TOOLS_COMMON_MACROS__
#define __XEN_TOOLS_COMMON_MACROS__

/*
 * Caution:
 *
 * This header must be completely self-contained. There are no external
 * references to variables or functions allowed, as the file might be included
 * for different runtime environments, such as firmware or target and build
 * host programs.
 */

#ifndef BUILD_BUG_ON
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#define BUILD_BUG_ON(p) ({ _Static_assert(!(p), "!(" #p ")"); })
#else
#define BUILD_BUG_ON(p) ((void)sizeof(char[1 - 2 * !!(p)]))
#endif
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef min
#define min(x, y)                               \
    ({                                          \
        const typeof(x) _x = (x);               \
        const typeof(y) _y = (y);               \
        (void) (&_x == &_y);                    \
        (_x < _y) ? _x : _y;                    \
    })
#endif

#ifndef max
#define max(x, y)                               \
    ({                                          \
        const typeof(x) _x = (x);               \
        const typeof(y) _y = (y);               \
        (void)(&_x == &_y);                     \
        (_x > _y) ? _x : _y;                    \
    })
#endif

#ifndef min_t
#define min_t(type, x, y)                       \
    ({                                          \
        const type _x = (x);                    \
        const type _y = (y);                    \
        (_x < _y) ? _x: _y;                     \
    })
#endif

#ifndef max_t
#define max_t(type, x, y)                       \
    ({                                          \
        const type _x = (x);                    \
        const type _y = (y);                    \
        (_x > _y) ? _x: _y;                     \
    })
#endif

#ifndef ROUNDUP
#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))
#endif

#define MASK_EXTR(v, m) (((v) & (m)) / ((m) & -(m)))
#define MASK_INSR(v, m) (((v) * ((m) & -(m))) & (m))

#ifndef __must_check
#define __must_check __attribute__((__warn_unused_result__))
#endif

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

#define container_of(ptr, type, member) ({              \
    typeof(((type *)0)->member) *mptr__ = (ptr);        \
    (type *)((char *)mptr__ - offsetof(type, member));  \
})

#define __AC(X, Y)   (X ## Y)
#define _AC(X, Y)    __AC(X, Y)

/* Size macros. */
#define MB(_mb)     (_AC(_mb, ULL) << 20)
#define GB(_gb)     (_AC(_gb, ULL) << 30)

#define get_unaligned_t(type, ptr) ({                               \
    const struct { type x; } __packed *ptr_ = (typeof(ptr_))(ptr);  \
    ptr_->x;                                                        \
})

#define put_unaligned_t(type, val, ptr) do {                        \
    struct { type x; } __packed *ptr_ = (typeof(ptr_))(ptr);        \
    ptr_->x = (val);                                                \
} while (0)

#define get_unaligned(ptr)      get_unaligned_t(typeof(*(ptr)), ptr)
#define put_unaligned(val, ptr) put_unaligned_t(typeof(*(ptr)), val, ptr)

#endif	/* __XEN_TOOLS_COMMON_MACROS__ */
