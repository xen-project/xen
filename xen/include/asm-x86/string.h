#ifndef __X86_STRING_H__
#define __X86_STRING_H__

#include <xen/config.h>

#define __HAVE_ARCH_MEMCPY
#define memcpy(t,f,n) (__builtin_memcpy((t),(f),(n)))

/* Some versions of gcc don't have this builtin. It's non-critical anyway. */
#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dest, const void *src, size_t n);

#define __HAVE_ARCH_MEMSET
#define memset(s,c,n) (__builtin_memset((s),(c),(n)))

#endif /* __X86_STRING_H__ */
