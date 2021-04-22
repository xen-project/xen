#ifndef __X86_STRING_H__
#define __X86_STRING_H__

#define __HAVE_ARCH_MEMMOVE
#define memmove(d, s, n) __builtin_memmove(d, s, n)

#endif /* __X86_STRING_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
