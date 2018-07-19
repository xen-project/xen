#ifndef __XEN_TOOLS_LIBS__
#define __XEN_TOOLS_LIBS__

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

#endif	/* __XEN_TOOLS_LIBS__ */
