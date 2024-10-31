#ifndef __XEN_BYTEORDER_SWAB_H__
#define __XEN_BYTEORDER_SWAB_H__

/*
 * Byte-swapping, independently from CPU endianness
 *     swabXX[ps]?(foo)
 *
 * Francois-Rene Rideau <fare@tunes.org> 19971205
 *    separated swab functions from cpu_to_XX,
 *    to clean up support for bizarre-endian architectures.
 */

#define ___swab16(x)                                    \
({                                                      \
    uint16_t x_ = (x);                                  \
    (uint16_t)(                                         \
        (((uint16_t)(x_) & 0x00ffU) << 8) |             \
        (((uint16_t)(x_) & 0xff00U) >> 8));             \
})

#define ___swab32(x)                                            \
({                                                              \
    uint32_t x_ = (x);                                          \
    (uint32_t)(                                                 \
        (((uint32_t)(x_) & 0x000000ffU) << 24) |                \
        (((uint32_t)(x_) & 0x0000ff00U) <<  8) |                \
        (((uint32_t)(x_) & 0x00ff0000U) >>  8) |                \
        (((uint32_t)(x_) & 0xff000000U) >> 24));                \
})

#define ___swab64(x)                                                       \
({                                                                         \
    uint64_t x_ = (x);                                                     \
    (uint64_t)(                                                            \
        (((uint64_t)(x_) & 0x00000000000000ffULL) << 56) |                 \
        (((uint64_t)(x_) & 0x000000000000ff00ULL) << 40) |                 \
        (((uint64_t)(x_) & 0x0000000000ff0000ULL) << 24) |                 \
        (((uint64_t)(x_) & 0x00000000ff000000ULL) <<  8) |                 \
        (((uint64_t)(x_) & 0x000000ff00000000ULL) >>  8) |                 \
        (((uint64_t)(x_) & 0x0000ff0000000000ULL) >> 24) |                 \
        (((uint64_t)(x_) & 0x00ff000000000000ULL) >> 40) |                 \
        (((uint64_t)(x_) & 0xff00000000000000ULL) >> 56));                 \
})

#define ___constant_swab16(x)                   \
    ((uint16_t)(                                \
        (((uint16_t)(x) & 0x00ffU) << 8) |      \
        (((uint16_t)(x) & 0xff00U) >> 8)))
#define ___constant_swab32(x)                           \
    ((uint32_t)(                                        \
        (((uint32_t)(x) & 0x000000ffU) << 24) |         \
        (((uint32_t)(x) & 0x0000ff00U) <<  8) |         \
        (((uint32_t)(x) & 0x00ff0000U) >>  8) |         \
        (((uint32_t)(x) & 0xff000000U) >> 24)))
#define ___constant_swab64(x)                                            \
    ((uint64_t)(                                                         \
        (((uint64_t)(x) & 0x00000000000000ffULL) << 56) |                \
        (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) |                \
        (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) |                \
        (((uint64_t)(x) & 0x00000000ff000000ULL) <<  8) |                \
        (((uint64_t)(x) & 0x000000ff00000000ULL) >>  8) |                \
        (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) |                \
        (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) |                \
        (((uint64_t)(x) & 0xff00000000000000ULL) >> 56)))

/*
 * provide defaults when no architecture-specific optimization is detected
 */
#ifndef __arch__swab16
#  define __arch__swab16(x) ___swab16(x)
#endif
#ifndef __arch__swab32
#  define __arch__swab32(x) ___swab32(x)
#endif
#ifndef __arch__swab64
#  define __arch__swab64(x) ___swab64(x)
#endif

#ifndef __arch__swab16p
#  define __arch__swab16p(x) __arch__swab16(*(x))
#endif
#ifndef __arch__swab32p
#  define __arch__swab32p(x) __arch__swab32(*(x))
#endif
#ifndef __arch__swab64p
#  define __arch__swab64p(x) __arch__swab64(*(x))
#endif

#ifndef __arch__swab16s
#  define __arch__swab16s(x) do { *(x) = __arch__swab16p((x)); } while (0)
#endif
#ifndef __arch__swab32s
#  define __arch__swab32s(x) do { *(x) = __arch__swab32p((x)); } while (0)
#endif
#ifndef __arch__swab64s
#  define __arch__swab64s(x) do { *(x) = __arch__swab64p((x)); } while (0)
#endif


/*
 * Allow constant folding
 */
#if defined(__GNUC__) && defined(__OPTIMIZE__)
#  define __swab16(x) \
(__builtin_constant_p((uint16_t)(x)) ? \
 ___swab16((x)) : \
 __fswab16((x)))
#  define __swab32(x) \
(__builtin_constant_p((uint32_t)(x)) ? \
 ___swab32((x)) : \
 __fswab32((x)))
#  define __swab64(x) \
(__builtin_constant_p((uint64_t)(x)) ? \
 ___swab64((x)) : \
 __fswab64((x)))
#else
#  define __swab16(x) __fswab16(x)
#  define __swab32(x) __fswab32(x)
#  define __swab64(x) __fswab64(x)
#endif /* OPTIMIZE */


static inline attr_const uint16_t __fswab16(uint16_t x)
{
    return __arch__swab16(x);
}
static inline uint16_t __swab16p(const uint16_t *x)
{
    return __arch__swab16p(x);
}
static inline void __swab16s(uint16_t *addr)
{
    __arch__swab16s(addr);
}

static inline attr_const uint32_t __fswab32(uint32_t x)
{
    return __arch__swab32(x);
}
static inline uint32_t __swab32p(const uint32_t *x)
{
    return __arch__swab32p(x);
}
static inline void __swab32s(uint32_t *addr)
{
    __arch__swab32s(addr);
}

#ifdef __BYTEORDER_HAS_U64__
static inline attr_const uint64_t __fswab64(uint64_t x)
{
#  ifdef __SWAB_64_THRU_32__
    uint32_t h = x >> 32, l = x;
    return ((uint64_t)__swab32(l) << 32) | __swab32(h);
#  else
    return __arch__swab64(x);
#  endif
}
static inline uint64_t __swab64p(const uint64_t *x)
{
    return __arch__swab64p(x);
}
static inline void __swab64s(uint64_t *addr)
{
    __arch__swab64s(addr);
}
#endif /* __BYTEORDER_HAS_U64__ */

#define swab16 __swab16
#define swab32 __swab32
#define swab64 __swab64
#define swab16p __swab16p
#define swab32p __swab32p
#define swab64p __swab64p
#define swab16s __swab16s
#define swab32s __swab32s
#define swab64s __swab64s

#endif /* __XEN_BYTEORDER_SWAB_H__ */
