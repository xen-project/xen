#ifndef __ARM_STRING_H__
#define __ARM_STRING_H__


/*
 * We don't do inline string functions, since the
 * optimised inline asm versions are not small.
 */

#define __HAVE_ARCH_STRRCHR
char *strrchr(const char *s, int c);

#define __HAVE_ARCH_STRCHR
char *strchr(const char *s, int c);

#if defined(CONFIG_ARM_64)
#define __HAVE_ARCH_STRCMP
int strcmp(const char *, const char *);

#define __HAVE_ARCH_STRNCMP
int strncmp(const char *, const char *, size_t);

#define __HAVE_ARCH_STRLEN
size_t strlen(const char *);

#define __HAVE_ARCH_STRNLEN
size_t strnlen(const char *, size_t);
#endif

#define __HAVE_ARCH_MEMCPY
void *memcpy(void *, const void *, size_t);

#if defined(CONFIG_ARM_64)
#define __HAVE_ARCH_MEMCMP
int memcmp(const void *, const void *, size_t);
#endif

#define __HAVE_ARCH_MEMMOVE
void *memmove(void *dest, const void *src, size_t n);

#define __HAVE_ARCH_MEMSET
void *memset(void *, int, size_t);

#define __HAVE_ARCH_MEMCHR
void *memchr(const void *, int, size_t);

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
