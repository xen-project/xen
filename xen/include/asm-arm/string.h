#ifndef __ARM_STRING_H__
#define __ARM_STRING_H__

#include <xen/config.h>

#define __HAVE_ARCH_MEMCPY
extern void * memcpy(void *, const void *, __kernel_size_t);

/* Some versions of gcc don't have this builtin. It's non-critical anyway. */
#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dest, const void *src, size_t n);

#define __HAVE_ARCH_MEMSET
extern void * memset(void *, int, __kernel_size_t);

extern void __memzero(void *ptr, __kernel_size_t n);

#define memset(p,v,n)                                                   \
        ({                                                              \
                void *__p = (p); size_t __n = n;                        \
                if ((__n) != 0) {                                       \
                        if (__builtin_constant_p((v)) && (v) == 0)      \
                                __memzero((__p),(__n));                 \
                        else                                            \
                                memset((__p),(v),(__n));                \
                }                                                       \
                (__p);                                                  \
        })

#endif /* __ARM_STRING_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
