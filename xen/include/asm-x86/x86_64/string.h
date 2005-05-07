#ifndef _X86_64_STRING_H_
#define _X86_64_STRING_H_

#define __HAVE_ARCH_MEMCPY
#define memcpy(t,f,n) (__memcpy((t),(f),(n)))
#define __memcpy(t,f,n) (__builtin_memcpy((t),(f),(n)))

#define __HAVE_ARCH_MEMSET
#define memset(s, c, count) (__memset((s),(c),(count)))
#define __memset(s, c, count) (__builtin_memset((s),(c),(count)))

/* Some versions of 64-bit gcc don't have this built in. */
#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dest, const void *src, size_t n);

#endif
