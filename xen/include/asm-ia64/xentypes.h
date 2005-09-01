#ifndef _ASM_IA64_XENTYPES_H
#define _ASM_IA64_XENTYPES_H

#ifndef __ASSEMBLY__
typedef unsigned long ssize_t;
typedef unsigned long size_t;
typedef long long loff_t;

#ifdef __KERNEL__
/* these lines taken from linux/types.h.  they belong in xen/types.h */
#ifdef __CHECKER__
#define __bitwise __attribute__((bitwise))
#else
#define __bitwise
#endif

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;
#endif

# endif /* __KERNEL__ */
#endif /* !__ASSEMBLY__ */

#endif /* _ASM_IA64_XENTYPES_H */
