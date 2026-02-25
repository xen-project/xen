#ifndef __XEN_FRAME_NUM_H__
#define __XEN_FRAME_NUM_H__

#include <xen/kernel.h>
#include <xen/typesafe.h>

TYPE_SAFE(unsigned long, mfn);
#define PRI_mfn          "05lx"
#define INVALID_MFN      ((mfn_t){ ~0UL })

#if 0
#define mfn_t /* Grep fodder: mfn_t, _mfn() and mfn_x() are defined above */
#define _mfn
#define mfn_x
#endif

static inline mfn_t __must_check mfn_add(mfn_t mfn, unsigned long i)
{
    return _mfn(mfn_x(mfn) + i);
}

static inline mfn_t mfn_max(mfn_t x, mfn_t y)
{
    return _mfn(max(mfn_x(x), mfn_x(y)));
}

static inline mfn_t mfn_min(mfn_t x, mfn_t y)
{
    return _mfn(min(mfn_x(x), mfn_x(y)));
}

static inline bool mfn_eq(mfn_t x, mfn_t y)
{
    return mfn_x(x) == mfn_x(y);
}

TYPE_SAFE(unsigned long, gfn);
#define PRI_gfn          "05lx"
#define INVALID_GFN      ((gfn_t){ ~0UL })

#if 0
#define gfn_t /* Grep fodder: gfn_t, _gfn() and gfn_x() are defined above */
#define _gfn
#define gfn_x
#endif

static inline gfn_t __must_check gfn_add(gfn_t gfn, unsigned long i)
{
    return _gfn(gfn_x(gfn) + i);
}

static inline gfn_t gfn_max(gfn_t x, gfn_t y)
{
    return _gfn(max(gfn_x(x), gfn_x(y)));
}

static inline gfn_t gfn_min(gfn_t x, gfn_t y)
{
    return _gfn(min(gfn_x(x), gfn_x(y)));
}

static inline bool gfn_eq(gfn_t x, gfn_t y)
{
    return gfn_x(x) == gfn_x(y);
}

TYPE_SAFE(unsigned long, pfn);
#define PRI_pfn          "05lx"

#if 0
#define pfn_t /* Grep fodder: pfn_t, _pfn() and pfn_x() are defined above */
#define _pfn
#define pfn_x
#endif

#endif /* __XEN_FRAME_NUM_H__ */
