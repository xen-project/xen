#ifndef __XEN_STRING_H__
#define __XEN_STRING_H__

#include <xen/types.h>	/* for size_t */

/*
 * Include machine specific inline routines
 */
#include <asm/string.h>

/*
 * These string functions are considered too dangerous for normal use.
 * Use safe_strcpy(), safe_strcat(), strlcpy(), strlcat() as appropriate.
 */
#define strcpy  __xen_has_no_strcpy__
#define strcat  __xen_has_no_strcat__
#define strncpy __xen_has_no_strncpy__
#define strncat __xen_has_no_strncat__

#ifndef __HAVE_ARCH_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#ifndef __HAVE_ARCH_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif

#ifndef __HAVE_ARCH_STRCMP
int strcmp(const char *, const char *);
#define strcmp(s1, s2) __builtin_strcmp(s1, s2)
#endif

#ifndef __HAVE_ARCH_STRNCMP
int strncmp(const char *, const char *, size_t);
#define strncmp(s1, s2, n) __builtin_strncmp(s1, s2, n)
#endif

#ifndef __HAVE_ARCH_STRNICMP
int strnicmp(const char *, const char *, size_t);
#endif

#ifndef __HAVE_ARCH_STRCASECMP
int strcasecmp(const char *, const char *);
#define strcasecmp(s1, s2) __builtin_strcasecmp(s1, s2)
#endif

#ifndef __HAVE_ARCH_STRCHR
char *strchr(const char *, int);
#define strchr(s1, c) __builtin_strchr(s1, c)
#endif

#ifndef __HAVE_ARCH_STRRCHR
char *strrchr(const char *, int);
#define strrchr(s1, c) __builtin_strrchr(s1, c)
#endif

#ifndef __HAVE_ARCH_STRSTR
char *strstr(const char *, const char *);
#define strstr(s1, s2) __builtin_strstr(s1, s2)
#endif

#ifndef __HAVE_ARCH_STRLEN
size_t strlen(const char *);
#define strlen(s1) __builtin_strlen(s1)
#endif

#ifndef __HAVE_ARCH_STRNLEN
size_t strnlen(const char *, size_t);
#endif

#ifndef __HAVE_ARCH_STRPBRK
char *strpbrk(const char *, const char *);
#endif

#ifndef __HAVE_ARCH_STRSEP
char *strsep(char **, const char *);
#endif

#ifndef __HAVE_ARCH_STRSPN
size_t strspn(const char *, const char *);
#endif


#ifndef __HAVE_ARCH_MEMSET
void *memset(void *, int, size_t);
#define memset(s, c, n) __builtin_memset(s, c, n)
#endif

#ifndef __HAVE_ARCH_MEMCPY
void *memcpy(void *, const void *, size_t);
#define memcpy(d, s, n) __builtin_memcpy(d, s, n)
#endif

#ifndef __HAVE_ARCH_MEMMOVE
void *memmove(void *, const void *, size_t);
#define memmove(d, s, n) __builtin_memmove(d, s, n)
#endif

#ifndef __HAVE_ARCH_MEMSCAN
void *memscan(void *, int, size_t);
#endif

#ifndef __HAVE_ARCH_MEMCMP
int memcmp(const void *, const void *, size_t);
#define memcmp(s1, s2, n) __builtin_memcmp(s1, s2, n)
#endif

#ifndef __HAVE_ARCH_MEMCHR
void *memchr(const void *, int, size_t);
#define memchr(s, c, n) __builtin_memchr(s, c, n)
#endif

#define is_char_array(x) __builtin_types_compatible_p(typeof(x), char[])

/* safe_xxx always NUL-terminates and returns !=0 if result is truncated. */
#define safe_strcpy(d, s) ({                    \
    BUILD_BUG_ON(!is_char_array(d));            \
    (strlcpy(d, s, sizeof(d)) >= sizeof(d));    \
})
#define safe_strcat(d, s) ({                    \
    BUILD_BUG_ON(!is_char_array(d));            \
    (strlcat(d, s, sizeof(d)) >= sizeof(d));    \
})

#endif /* __XEN_STRING_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
