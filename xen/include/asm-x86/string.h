#ifndef __X86_STRING_H__
#define __X86_STRING_H__

#include <xen/config.h>

#define __HAVE_ARCH_STRCPY
static inline char *strcpy(char *dest, const char *src)
{
    long d0, d1, d2;
    __asm__ __volatile__ (
        "1: lodsb          \n"
        "   stosb          \n"
        "   test %%al,%%al \n"
        "   jne  1b        \n"
        : "=&S" (d0), "=&D" (d1), "=&a" (d2)
        : "0" (src), "1" (dest) : "memory" );
    return dest;
}

#define __HAVE_ARCH_STRNCPY
static inline char *strncpy(char *dest, const char *src, size_t count)
{
    long d0, d1, d2, d3;
    __asm__ __volatile__ (
        "1: dec  %2        \n"
        "   js   2f        \n"
        "   lodsb          \n"
        "   stosb          \n"
        "   test %%al,%%al \n"
        "   jne  1b        \n"
        "   rep ; stosb    \n"
        "2:                \n"
        : "=&S" (d0), "=&D" (d1), "=&c" (d2), "=&a" (d3)
        : "0" (src), "1" (dest), "2" (count) : "memory" );
    return dest;
}

#define __HAVE_ARCH_STRCAT
static inline char *strcat(char *dest, const char *src)
{
    long d0, d1, d2, d3;
    __asm__ __volatile__ (
        "   repne ; scasb  \n"
        "   dec  %1        \n"
        "1: lodsb          \n"
        "   stosb          \n"
        "   test %%al,%%al \n"
        "   jne  1b        \n"
        : "=&S" (d0), "=&D" (d1), "=&a" (d2), "=&c" (d3)
        : "0" (src), "1" (dest), "2" (0UL), "3" (0xffffffffUL) : "memory" );
    return dest;
}

#define __HAVE_ARCH_STRNCAT
static inline char *strncat(char *dest, const char *src, size_t count)
{
    long d0, d1, d2, d3;
    __asm__ __volatile__ (
        "   repne ; scasb   \n"
        "   dec  %1         \n"
        "   mov  %8,%3      \n"
        "1: dec  %3         \n"
        "   js   2f         \n"
        "   lodsb           \n"
        "   stosb           \n"
        "   test %%al,%%al  \n"
        "   jne  1b         \n"
        "2: xor  %%eax,%%eax\n"
        "   stosb"
        : "=&S" (d0), "=&D" (d1), "=&a" (d2), "=&c" (d3)
        : "0" (src), "1" (dest), "2" (0UL), "3" (0xffffffffUL), "g" (count)
        : "memory" );
    return dest;
}

#define __HAVE_ARCH_STRCMP
static inline int strcmp(const char *cs, const char *ct)
{
    long d0, d1;
    register int __res;
    __asm__ __volatile__ (
        "1: lodsb           \n"
        "   scasb           \n"
        "   jne  2f         \n"
        "   test %%al,%%al  \n"
        "   jne  1b         \n"
        "   xor  %%eax,%%eax\n"
        "   jmp  3f         \n"
        "2: sbb  %%eax,%%eax\n"
        "   or   $1,%%al    \n"
        "3:                 \n"
        : "=a" (__res), "=&S" (d0), "=&D" (d1)
        : "1" (cs), "2" (ct) );
    return __res;
}

#define __HAVE_ARCH_STRNCMP
static inline int strncmp(const char *cs, const char *ct, size_t count)
{
    long d0, d1, d2;
    register int __res;
    __asm__ __volatile__ (
        "1: dec  %3         \n"
        "   js   2f         \n"
        "   lodsb           \n"
        "   scasb           \n"
        "   jne  3f         \n"
        "   test %%al,%%al  \n"
        "   jne  1b         \n"
        "2: xor  %%eax,%%eax\n"
        "   jmp  4f         \n"
        "3: sbb  %%eax,%%eax\n"
        "   or   $1,%%al    \n"
        "4:                 \n"
        : "=a" (__res), "=&S" (d0), "=&D" (d1), "=&c" (d2)
        : "1" (cs), "2" (ct), "3" (count) );
    return __res;
}

#define __HAVE_ARCH_STRCHR
static inline char *strchr(const char *s, int c)
{
    long d0;
    register char *__res;
    __asm__ __volatile__ (
        "   mov  %%al,%%ah  \n"
        "1: lodsb           \n"
        "   cmp  %%ah,%%al  \n"
        "   je   2f         \n"
        "   test %%al,%%al  \n"
        "   jne  1b         \n"
        "   mov  $1,%1      \n"
        "2: mov  %1,%0      \n"
        "   dec  %0         \n"
        : "=a" (__res), "=&S" (d0) : "1" (s), "0" (c) );
    return __res;
}

#define __HAVE_ARCH_STRRCHR
static inline char *strrchr(const char *s, int c)
{
    long d0, d1;
    register char *__res;
    __asm__ __volatile__ (
        "   mov  %%al,%%ah  \n"
        "1: lodsb           \n"
        "   cmp  %%ah,%%al  \n"
        "   jne  2f         \n"
        "   lea  -1(%1),%0  \n"
        "2: test %%al,%%al  \n"
        "   jne  1b         \n"
        : "=g" (__res), "=&S" (d0), "=&a" (d1) : "0" (0), "1" (s), "2" (c) );
    return __res;
}

#define __HAVE_ARCH_STRLEN
static inline size_t strlen(const char *s)
{
    long d0;
    register int __res;
    __asm__ __volatile__ (
        "   repne ; scasb  \n"
        "   notl %0        \n"
        "   decl %0        \n"
        : "=c" (__res), "=&D" (d0) : "1" (s), "a" (0), "0" (0xffffffffUL) );
    return __res;
}

static inline void *__variable_memcpy(void *to, const void *from, size_t n)
{
    long d0, d1, d2;
    __asm__ __volatile__ (
        "   rep ; movs"__OS"\n"
        "   mov %4,%3       \n"
        "   rep ; movsb     \n"
        : "=&c" (d0), "=&D" (d1), "=&S" (d2)
        : "0" (n/BYTES_PER_LONG), "r" (n%BYTES_PER_LONG), "1" (to), "2" (from)
        : "memory" );
    return to;
}

/*
 * This looks horribly ugly, but the compiler can optimize it totally,
 * as the count is constant.
 */
static always_inline void * __constant_memcpy(
    void * to, const void * from, size_t n)
{
    switch ( n )
    {
    case 0:
        return to;
    case 1:
        *(u8 *)to = *(const u8 *)from;
        return to;
    case 2:
        *(u16 *)to = *(const u16 *)from;
        return to;
    case 3:
        *(u16 *)to = *(const u16 *)from;
        *(2+(u8 *)to) = *(2+(const u8 *)from);
        return to;
    case 4:
        *(u32 *)to = *(const u32 *)from;
        return to;
    case 5:
        *(u32 *)to = *(const u32 *)from;
        *(4+(u8 *)to) = *(4+(const u8 *)from);
        return to;
    case 6:
        *(u32 *)to = *(const u32 *)from;
        *(2+(u16 *)to) = *(2+(const u16 *)from);
        return to;
    case 7:
        *(u32 *)to = *(const u32 *)from;
        *(2+(u16 *)to) = *(2+(const u16 *)from);
        *(6+(u8 *)to) = *(6+(const u8 *)from);
        return to;
    case 8:
        *(u64 *)to = *(const u64 *)from;
        return to;
    case 12:
        *(u64 *)to = *(const u64 *)from;
        *(2+(u32 *)to) = *(2+(const u32 *)from);
        return to;
    case 16:
        *(u64 *)to = *(const u64 *)from;
        *(1+(u64 *)to) = *(1+(const u64 *)from);
        return to;
    case 20:
        *(u64 *)to = *(const u64 *)from;
        *(1+(u64 *)to) = *(1+(const u64 *)from);
        *(4+(u32 *)to) = *(4+(const u32 *)from);
        return to;
    }
#define COMMON(x)                                       \
    __asm__ __volatile__ (                              \
        "rep ; movs"__OS                                \
        x                                               \
        : "=&c" (d0), "=&D" (d1), "=&S" (d2)            \
        : "0" (n/BYTES_PER_LONG), "1" (to), "2" (from)  \
        : "memory" );
    {
        long d0, d1, d2;
        switch ( n % BYTES_PER_LONG )
        {
        case 0: COMMON(""); return to;
        case 1: COMMON("\n\tmovsb"); return to;
        case 2: COMMON("\n\tmovsw"); return to;
        case 3: COMMON("\n\tmovsw\n\tmovsb"); return to;
        case 4: COMMON("\n\tmovsl"); return to;
        case 5: COMMON("\n\tmovsl\n\tmovsb"); return to;
        case 6: COMMON("\n\tmovsl\n\tmovsw"); return to;
        case 7: COMMON("\n\tmovsl\n\tmovsw\n\tmovsb"); return to;
        }
    }
#undef COMMON
}

#define __HAVE_ARCH_MEMCPY
#define memcpy(t,f,n) (__memcpy((t),(f),(n)))
static always_inline
void *__memcpy(void *t, const void *f, size_t n)
{
    return (__builtin_constant_p(n) ?
            __constant_memcpy((t),(f),(n)) :
            __variable_memcpy((t),(f),(n)));
}

/* Some version of gcc don't have this builtin. It's non-critical anyway. */
#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dest, const void *src, size_t n);

#define __HAVE_ARCH_MEMCMP
#define memcmp __builtin_memcmp

#define __HAVE_ARCH_MEMCHR
static inline void *memchr(const void *cs, int c, size_t count)
{
    long d0;
    register void *__res;
    if ( count == 0 )
        return NULL;
    __asm__ __volatile__ (
        "   repne ; scasb\n"
        "   je   1f      \n"
        "   mov  $1,%0   \n"
        "1: dec  %0      \n"
        : "=D" (__res), "=&c" (d0) : "a" (c), "0" (cs), "1" (count) );
    return __res;
}

static inline void *__memset_generic(void *s, char c, size_t count)
{
    long d0, d1;
    __asm__ __volatile__ (
        "rep ; stosb"
        : "=&c" (d0), "=&D" (d1) : "a" (c), "1" (s), "0" (count) : "memory" );
    return s;
}

/* we might want to write optimized versions of these later */
#define __constant_count_memset(s,c,count) __memset_generic((s),(c),(count))

/*
 * memset(x,0,y) is a reasonably common thing to do, so we want to fill
 * things 32 bits at a time even when we don't know the size of the
 * area at compile-time..
 */
static inline void *__constant_c_memset(void *s, unsigned long c, size_t count)
{
    long d0, d1;
    __asm__ __volatile__(
        "   rep ; stos"__OS"\n"
        "   mov  %3,%4      \n"
        "   rep ; stosb     \n"
        : "=&c" (d0), "=&D" (d1)
        : "a" (c), "r" (count%BYTES_PER_LONG),
          "0" (count/BYTES_PER_LONG), "1" (s)
        : "memory" );
    return s; 
}

#define __HAVE_ARCH_STRNLEN
static inline size_t strnlen(const char *s, size_t count)
{
    long d0;
    register int __res;
    __asm__ __volatile__ (
        "   jmp  2f       \n"
        "1: cmpb $0,(%3)  \n"
        "   je   3f       \n"
        "   inc  %3       \n"
        "2: dec  %1       \n"
        "   jns  1b       \n"
        "3: subl %2,%0    \n"
        : "=a" (__res), "=&d" (d0)
        : "c" ((int)(long)s), "0" (s), "1" (count) );
    return __res;
}

/*
 * This looks horribly ugly, but the compiler can optimize it totally,
 * as we by now know that both pattern and count is constant..
 */
static always_inline void *__constant_c_and_count_memset(
    void *s, unsigned long pattern, size_t count)
{
    switch ( count )
    {
    case 0:
        return s;
    case 1:
        *(u8 *)s = pattern;
        return s;
    case 2:
        *(u16 *)s = pattern;
        return s;
    case 3:
        *(u16 *)s = pattern;
        *(2+(u8 *)s) = pattern;
        return s;
    case 4:
        *(u32 *)s = pattern;
        return s;
    case 5:
        *(u32 *)s = pattern;
        *(4+(u8 *)s) = pattern;
        return s;
    case 6:
        *(u32 *)s = pattern;
        *(2+(u16 *)s) = pattern;
        return s;
    case 7:
        *(u32 *)s = pattern;
        *(2+(u16 *)s) = pattern;
        *(6+(u8 *)s) = pattern;
        return s;
    case 8:
        *(u64 *)s = pattern;
        return s;
    }
#define COMMON(x)                                               \
    __asm__  __volatile__ (                                     \
        "rep ; stos"__OS                                        \
        x                                                       \
        : "=&c" (d0), "=&D" (d1)                                \
        : "a" (pattern), "0" (count/BYTES_PER_LONG), "1" (s)    \
        : "memory" )
    {
        long d0, d1;
        switch ( count % BYTES_PER_LONG )
        {
        case 0: COMMON(""); return s;
        case 1: COMMON("\n\tstosb"); return s;
        case 2: COMMON("\n\tstosw"); return s;
        case 3: COMMON("\n\tstosw\n\tstosb"); return s;
        case 4: COMMON("\n\tstosl"); return s;
        case 5: COMMON("\n\tstosl\n\tstosb"); return s;
        case 6: COMMON("\n\tstosl\n\tstosw"); return s;
        case 7: COMMON("\n\tstosl\n\tstosw\n\tstosb"); return s;
        }
    }
#undef COMMON
}

#define __constant_c_x_memset(s, c, count) \
(__builtin_constant_p(count) ? \
 __constant_c_and_count_memset((s),(c),(count)) : \
 __constant_c_memset((s),(c),(count)))

#define __var_x_memset(s, c, count) \
(__builtin_constant_p(count) ? \
 __constant_count_memset((s),(c),(count)) : \
 __memset_generic((s),(c),(count)))

#ifdef CONFIG_X86_64
#define MEMSET_PATTERN_MUL 0x0101010101010101UL
#else
#define MEMSET_PATTERN_MUL 0x01010101UL
#endif

#define __HAVE_ARCH_MEMSET
#define memset(s, c, count) (__memset((s),(c),(count)))
#define __memset(s, c, count) \
(__builtin_constant_p(c) ? \
 __constant_c_x_memset((s),(MEMSET_PATTERN_MUL*(unsigned char)(c)),(count)) : \
 __var_x_memset((s),(c),(count)))

#define __HAVE_ARCH_MEMSCAN
static inline void *memscan(void *addr, int c, size_t size)
{
    if ( size == 0 )
        return addr;
    __asm__ (
        "   repnz; scasb \n"
        "   jnz  1f      \n"
        "   dec  %0      \n"
        "1:              \n"
        : "=D" (addr), "=c" (size)
        : "0" (addr), "1" (size), "a" (c) );
    return addr;
}

#endif /* __X86_STRING_H__ */
