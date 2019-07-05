#ifdef INT_SIZE
# define ELEM_SIZE INT_SIZE
#else
# define ELEM_SIZE FLOAT_SIZE
#endif

#define VEC_SIZE (IDX_SIZE <= ELEM_SIZE ? VEC_MAX \
                                        : VEC_MAX * ELEM_SIZE / IDX_SIZE)
#if VEC_SIZE < 16
# undef VEC_SIZE
# define VEC_SIZE 16
#endif

#include "simd.h"

ENTRY(sg_test);

#undef MODE
#if IDX_SIZE == 4
# define MODE SI
#elif IDX_SIZE == 8
# define MODE DI
#endif

#define IVEC_SIZE (ELEM_SIZE <= IDX_SIZE ? VEC_MAX \
                                         : VEC_MAX * IDX_SIZE / ELEM_SIZE)
#if IVEC_SIZE < 16
# undef IVEC_SIZE
# define IVEC_SIZE 16
#endif

typedef signed int __attribute__((mode(MODE), vector_size(IVEC_SIZE))) idx_t;
typedef long long __attribute__((vector_size(IVEC_SIZE))) idi_t;

#define ITEM_COUNT (VEC_SIZE / ELEM_SIZE < IVEC_SIZE / IDX_SIZE ? \
                    VEC_SIZE / ELEM_SIZE : IVEC_SIZE / IDX_SIZE)

#if defined(__AVX512F__)
# define ALL_TRUE (~0ULL >> (64 - ELEM_COUNT))
# if ELEM_SIZE == 4
#  if IDX_SIZE == 4 || defined(__AVX512VL__)
#   define to_mask(msk) B(ptestmd, , (vsi_t)(msk), (vsi_t)(msk), ~0)
#   define eq(x, y) (B(pcmpeqd, _mask, (vsi_t)(x), (vsi_t)(y), -1) == ALL_TRUE)
#  else
#   define widen(x) __builtin_ia32_pmovzxdq512_mask((vsi_t)(x), (idi_t){}, ~0)
#   define to_mask(msk) __builtin_ia32_ptestmq512(widen(msk), widen(msk), ~0)
#   define eq(x, y) (__builtin_ia32_pcmpeqq512_mask(widen(x), widen(y), ~0) == ALL_TRUE)
#  endif
#  define BG_(dt, it, reg, mem, idx, msk, scl) \
    __builtin_ia32_gather##it##dt(reg, mem, idx, to_mask(msk), scl)
#  define BS_(dt, it, mem, idx, reg, msk, scl) \
    __builtin_ia32_scatter##it##dt(mem, to_mask(msk), idx, reg, scl)
# else
#  define eq(x, y) (B(pcmpeqq, _mask, (vdi_t)(x), (vdi_t)(y), -1) == ALL_TRUE)
#  define BG_(dt, it, reg, mem, idx, msk, scl) \
    __builtin_ia32_gather##it##dt(reg, mem, idx, B(ptestmq, , (vdi_t)(msk), (vdi_t)(msk), ~0), scl)
#  define BS_(dt, it, mem, idx, reg, msk, scl) \
    __builtin_ia32_scatter##it##dt(mem, B(ptestmq, , (vdi_t)(msk), (vdi_t)(msk), ~0), idx, reg, scl)
# endif
/*
 * Instead of replicating the main IDX_SIZE conditional below three times, use
 * a double layer of macro invocations, allowing for substitution of the
 * respective relevant macro argument tokens.
 */
# define BG(dt, it, reg, mem, idx, msk, scl) BG_(dt, it, reg, mem, idx, msk, scl)
# define BS(dt, it, mem, idx, reg, msk, scl) BS_(dt, it##i, mem, idx, reg, msk, scl)
# if VEC_MAX < 64
/*
 * The sub-512-bit built-ins have an extra "3" infix, presumably because the
 * 512-bit names were chosen without the AVX512VL extension in mind (and hence
 * making the latter collide with the AVX2 ones).
 */
#  define si 3si
#  define di 3di
# endif
# if VEC_MAX == 16
#  define v8df v2df
#  define v8di v2di
#  define v16sf v4sf
#  define v16si v4si
# elif VEC_MAX == 32
#  define v8df v4df
#  define v8di v4di
#  define v16sf v8sf
#  define v16si v8si
# endif
# if IDX_SIZE == 4
#  if INT_SIZE == 4
#   define gather(reg, mem, idx, msk, scl) BG(v16si, si, reg, mem, idx, msk, scl)
#   define scatter(mem, idx, reg, msk, scl) BS(v16si, s, mem, idx, reg, msk, scl)
#  elif INT_SIZE == 8
#   define gather(reg, mem, idx, msk, scl) (vec_t)(BG(v8di, si, (vdi_t)(reg), mem, idx, msk, scl))
#   define scatter(mem, idx, reg, msk, scl) BS(v8di, s, mem, idx, (vdi_t)(reg), msk, scl)
#  elif FLOAT_SIZE == 4
#   define gather(reg, mem, idx, msk, scl) BG(v16sf, si, reg, mem, idx, msk, scl)
#   define scatter(mem, idx, reg, msk, scl) BS(v16sf, s, mem, idx, reg, msk, scl)
#  elif FLOAT_SIZE == 8
#   define gather(reg, mem, idx, msk, scl) BG(v8df, si, reg, mem, idx, msk, scl)
#   define scatter(mem, idx, reg, msk, scl) BS(v8df, s, mem, idx, reg, msk, scl)
#  endif
# elif IDX_SIZE == 8
#  if INT_SIZE == 4
#   define gather(reg, mem, idx, msk, scl) BG(v16si, di, reg, mem, (idi_t)(idx), msk, scl)
#   define scatter(mem, idx, reg, msk, scl) BS(v16si, d, mem, (idi_t)(idx), reg, msk, scl)
#  elif INT_SIZE == 8
#   define gather(reg, mem, idx, msk, scl) (vec_t)(BG(v8di, di, (vdi_t)(reg), mem, (idi_t)(idx), msk, scl))
#   define scatter(mem, idx, reg, msk, scl) BS(v8di, d, mem, (idi_t)(idx), (vdi_t)(reg), msk, scl)
#  elif FLOAT_SIZE == 4
#   define gather(reg, mem, idx, msk, scl) BG(v16sf, di, reg, mem, (idi_t)(idx), msk, scl)
#   define scatter(mem, idx, reg, msk, scl) BS(v16sf, d, mem, (idi_t)(idx), reg, msk, scl)
#  elif FLOAT_SIZE == 8
#   define gather(reg, mem, idx, msk, scl) BG(v8df, di, reg, mem, (idi_t)(idx), msk, scl)
#   define scatter(mem, idx, reg, msk, scl) BS(v8df, d, mem, (idi_t)(idx), reg, msk, scl)
#  endif
# endif
#elif defined(__AVX2__)
# if VEC_SIZE == 16
#  define to_bool(cmp) __builtin_ia32_ptestc128(cmp, (vec_t){} == 0)
# else
#  define to_bool(cmp) __builtin_ia32_ptestc256(cmp, (vec_t){} == 0)
# endif

# if VEC_MAX == 16
#  if IDX_SIZE == 4
#   if INT_SIZE == 4
#    define gather __builtin_ia32_gathersiv4si
#   elif INT_SIZE == 8
#    define gather(reg, mem, idx, msk, scl) \
            (vec_t)(__builtin_ia32_gathersiv2di((vdi_t)(reg), \
                                                (const void *)(mem), \
                                                idx, (vdi_t)(msk), scl))
#   elif FLOAT_SIZE == 4
#    define gather __builtin_ia32_gathersiv4sf
#   elif FLOAT_SIZE == 8
#    define gather __builtin_ia32_gathersiv2df
#   endif
#  elif IDX_SIZE == 8
#   if INT_SIZE == 4
#    define gather(reg, mem, idx, msk, scl) \
            __builtin_ia32_gatherdiv4si(reg, mem, (vdi_t)(idx), msk, scl)
#   elif INT_SIZE == 8
#    define gather(reg, mem, idx, msk, scl) \
            (vec_t)(__builtin_ia32_gatherdiv2di((vdi_t)(reg), \
                                                (const void *)(mem), \
                                                (vdi_t)(idx), (vdi_t)(msk), \
                                                scl))
#   elif FLOAT_SIZE == 4
#    define gather(reg, mem, idx, msk, scl) \
            __builtin_ia32_gatherdiv4sf(reg, mem, (vdi_t)(idx), msk, scl)
#   elif FLOAT_SIZE == 8
#    define gather(reg, mem, idx, msk, scl) \
            __builtin_ia32_gatherdiv2df(reg, mem, (vdi_t)(idx), msk, scl)
#   endif
#  endif
# elif VEC_MAX == 32
#  if IDX_SIZE == 4
#   if INT_SIZE == 4
#    define gather __builtin_ia32_gathersiv8si
#   elif INT_SIZE == 8
#    define gather(reg, mem, idx, msk, scl) \
            (vec_t)(__builtin_ia32_gathersiv4di((vdi_t)(reg), \
                                                (const void *)(mem), \
                                                idx, (vdi_t)(msk), scl))

#   elif FLOAT_SIZE == 4
#    define gather __builtin_ia32_gathersiv8sf
#   elif FLOAT_SIZE == 8
#    define gather __builtin_ia32_gathersiv4df
#   endif
#  elif IDX_SIZE == 8
#   if INT_SIZE == 4
#    define gather(reg, mem, idx, msk, scl) \
            __builtin_ia32_gatherdiv4si256(reg, mem, (idi_t)(idx), msk, scl)
#   elif INT_SIZE == 8
#    define gather(reg, mem, idx, msk, scl) \
            (vec_t)(__builtin_ia32_gatherdiv4di((vdi_t)(reg), \
                                                (const void *)(mem), \
                                                (vdi_t)(idx), (vdi_t)(msk), \
                                                scl))

#   elif FLOAT_SIZE == 4
#    define gather(reg, mem, idx, msk, scl) \
            __builtin_ia32_gatherdiv4sf256(reg, mem, (idi_t)(idx), msk, scl)
#   elif FLOAT_SIZE == 8
#    define gather(reg, mem, idx, msk, scl) \
            __builtin_ia32_gatherdiv4df(reg, mem, (vdi_t)(idx), msk, scl)
#   endif
#  endif
# endif
#endif

#ifndef eq
# define eq(x, y) to_bool((x) == (y))
#endif

#define GLUE_(x, y) x ## y
#define GLUE(x, y) GLUE_(x, y)

#define PUT2(n)      (n),        (n) +  1
#define PUT4(n)  PUT2(n),   PUT2((n) +  2)
#define PUT8(n)  PUT4(n),   PUT4((n) +  4)
#define PUT16(n) PUT8(n),   PUT8((n) +  8)
#define PUT32(n) PUT16(n), PUT16((n) + 16)
#define PUT64(n) PUT32(n), PUT32((n) + 32)

const typeof((vec_t){}[0]) array[] = {
    GLUE(PUT, VEC_MAX)(1),
    GLUE(PUT, VEC_MAX)(VEC_MAX + 1)
};

typeof((vec_t){}[0]) out[VEC_MAX * 2];

int sg_test(void)
{
    unsigned int i;
    vec_t x, y, full = (vec_t){} == 0;
    idx_t idx, inv;

    for ( i = 0; i < IVEC_SIZE / IDX_SIZE; ++i )
    {
        idx[i] = i + 1;
        inv[i] = ITEM_COUNT - i;
    }

    touch(idx);
    touch(inv);

    x = gather(full, array, (idx_t){}, full, 1);
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( x[i] != 1 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( x[i] )
            return __LINE__;

    x = gather(full, array, idx, full, ELEM_SIZE);
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( x[i] != i + 2 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( x[i] )
            return __LINE__;

    x = gather(full, array, idx * ELEM_SIZE, full, 2);
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( x[i] != i * 2 + 3 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( x[i] )
            return __LINE__;

    x = gather(full, array, inv, full, ELEM_SIZE);
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( x[i] != inv[i] + 1 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( x[i] )
            return __LINE__;

    y = gather(full, array + ITEM_COUNT, -idx, full, ELEM_SIZE);
#if ITEM_COUNT == ELEM_COUNT
    if ( !eq(y, x - 1) )
        return __LINE__;
#else
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( y[i] != x[i] - 1 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( y[i] )
            return __LINE__;
#endif

#if ELEM_SIZE > 1
    x = gather(full, array, inv * 2, full, ELEM_SIZE / 2);
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( x[i] != inv[i] + 1 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( x[i] )
            return __LINE__;

# if ELEM_SIZE == IDX_SIZE
    y = gather(x, array, idx, (idx & inv) != 0, ELEM_SIZE);
    for ( i = 0; i < ITEM_COUNT; ++i )
        if ( y[i] != ((i + 1) & (ITEM_COUNT - i) ? idx : inv)[i] + 1 )
            return __LINE__;
    for ( ; i < ELEM_COUNT; ++i )
        if ( y[i] )
            return __LINE__;
# endif
#endif

#ifdef scatter

    for ( i = 0; i < sizeof(out) / sizeof(*out); ++i )
        out[i] = 0;

    for ( i = 0; i < ITEM_COUNT; ++i )
        x[i] = i + 1;

    touch(x);

    scatter(out, (idx_t){}, x, (vec_t){ 1 } != 0, 1);
    if ( out[0] != 1 )
        return __LINE__;
    for ( i = 1; i < ITEM_COUNT; ++i )
        if ( out[i] )
            return __LINE__;

    scatter(out, (idx_t){}, x, full, 1);
    if ( out[0] != ITEM_COUNT )
        return __LINE__;
    for ( i = 1; i < ITEM_COUNT; ++i )
        if ( out[i] )
            return __LINE__;

    scatter(out, idx, x, full, ELEM_SIZE);
    for ( i = 1; i <= ITEM_COUNT; ++i )
        if ( out[i] != i )
            return __LINE__;

    scatter(out, inv, x, full, ELEM_SIZE);
    for ( i = 1; i <= ITEM_COUNT; ++i )
        if ( out[i] != ITEM_COUNT + 1 - i )
            return __LINE__;

#endif

    return 0;
}
