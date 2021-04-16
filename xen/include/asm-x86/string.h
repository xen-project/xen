#ifndef __X86_STRING_H__
#define __X86_STRING_H__

#define __HAVE_ARCH_MEMCPY
#define memcpy(d, s, n) __builtin_memcpy(d, s, n)

#define __HAVE_ARCH_MEMMOVE
#define memmove(d, s, n) __builtin_memmove(d, s, n)

#define __HAVE_ARCH_MEMSET
#define memset(s, c, n) __builtin_memset(s, c, n)

#endif /* __X86_STRING_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
