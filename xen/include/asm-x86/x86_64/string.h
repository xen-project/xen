#ifndef _X86_64_STRING_H_
#define _X86_64_STRING_H_

#define __HAVE_ARCH_MEMMOVE
#define memmove(dest,src,n) (__memmove((dest),(src),(n)))
#define __memmove(dest,src,n) (__builtin_memmove((dest),(src),(n)))

#define __HAVE_ARCH_MEMCPY
#define memcpy(t,f,n) (__memcpy((t),(f),(n)))
#define __memcpy(t,f,n) (__builtin_memcpy((t),(f),(n)))

#define __HAVE_ARCH_MEMSET
#define memset(s, c, count) (__memset((s),(c),(count)))
#define __memset(s, c, count) (__builtin_memset((s),(c),(count)))

#endif
