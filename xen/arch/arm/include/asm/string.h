#ifndef __ARM_STRING_H__
#define __ARM_STRING_H__


/*
 * We don't do inline string functions, since the
 * optimised inline asm versions are not small.
 */

#define __HAVE_ARCH_STRRCHR
#define __HAVE_ARCH_STRCHR
#if defined(CONFIG_ARM_64)
#define __HAVE_ARCH_STRCMP
#define __HAVE_ARCH_STRNCMP
#define __HAVE_ARCH_STRLEN
#define __HAVE_ARCH_STRNLEN
#endif

#define __HAVE_ARCH_MEMCPY
#if defined(CONFIG_ARM_64)
#define __HAVE_ARCH_MEMCMP
#endif
#define __HAVE_ARCH_MEMMOVE
#define __HAVE_ARCH_MEMSET
#define __HAVE_ARCH_MEMCHR

#if defined(CONFIG_ARM_32)

void __memzero(void *ptr, size_t n);

#define memset(p, v, n)                                                 \
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

#endif

#endif /* __ARM_STRING_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
