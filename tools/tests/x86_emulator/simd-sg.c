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

#if VEC_SIZE == 16
# define to_bool(cmp) __builtin_ia32_ptestc128(cmp, (vec_t){} == 0)
#else
# define to_bool(cmp) __builtin_ia32_ptestc256(cmp, (vec_t){} == 0)
#endif

#if defined(__AVX2__)
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

#define GLUE_(x, y) x ## y
#define GLUE(x, y) GLUE_(x, y)

#define PUT2(n)      (n),        (n) +  1
#define PUT4(n)  PUT2(n),   PUT2((n) +  2)
#define PUT8(n)  PUT4(n),   PUT4((n) +  4)
#define PUT16(n) PUT8(n),   PUT8((n) +  8)
#define PUT32(n) PUT16(n), PUT16((n) + 16)

const typeof((vec_t){}[0]) array[] = {
    GLUE(PUT, VEC_MAX)(1),
    GLUE(PUT, VEC_MAX)(VEC_MAX + 1)
};

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
    if ( !to_bool(y == x - 1) )
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

    return 0;
}
