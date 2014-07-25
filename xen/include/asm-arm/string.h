#ifndef __ARM_STRING_H__
#define __ARM_STRING_H__

#include <xen/config.h>

/*
 * We don't do inline string functions, since the
 * optimised inline asm versions are not small.
 */

#define __HAVE_ARCH_STRRCHR
extern char * strrchr(const char * s, int c);

#define __HAVE_ARCH_STRCHR
extern char * strchr(const char * s, int c);

#if defined(CONFIG_ARM_64)
#define __HAVE_ARCH_STRCMP
extern int strcmp(const char *, const char *);

#define __HAVE_ARCH_STRNCMP
extern int strncmp(const char *, const char *, __kernel_size_t);

#define __HAVE_ARCH_STRLEN
extern __kernel_size_t strlen(const char *);

#define __HAVE_ARCH_STRNLEN
extern __kernel_size_t strnlen(const char *, __kernel_size_t);
#endif

#define __HAVE_ARCH_MEMCPY
extern void * memcpy(void *, const void *, __kernel_size_t);

#if defined(CONFIG_ARM_64)
#define __HAVE_ARCH_MEMCMP
extern int memcmp(const void *, const void *, __kernel_size_t);
#endif

/* Some versions of gcc don't have this builtin. It's non-critical anyway. */
#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dest, const void *src, size_t n);

#define __HAVE_ARCH_MEMSET
extern void * memset(void *, int, __kernel_size_t);

#define __HAVE_ARCH_MEMCHR
extern void * memchr(const void *, int, __kernel_size_t);

#if defined(CONFIG_ARM_32)

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
