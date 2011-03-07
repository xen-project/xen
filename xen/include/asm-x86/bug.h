#ifndef __X86_BUG_H__
#define __X86_BUG_H__

#ifdef __x86_64__
#include <asm/x86_64/bug.h>
#else
#include <asm/x86_32/bug.h>
#endif

struct bug_frame {
    unsigned char ud2[2];
    unsigned char ret;
    unsigned short id; /* BUGFRAME_??? */
} __attribute__((packed));

#define BUGFRAME_run_fn 0
#define BUGFRAME_warn   1
#define BUGFRAME_bug    2
#define BUGFRAME_assert 3

#define run_in_exception_handler(fn)               \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_run_fn),                 \
            "i" (&(fn)) )

#define WARN()                                     \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_warn | (__LINE__<<2)),   \
            "i" (__FILE__) )

#define BUG()                                      \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_bug | (__LINE__<<2)),    \
            "i" (__FILE__) )

#define assert_failed(p)                           \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1) BUG_STR(2)       \
        : : "i" (BUGFRAME_assert | (__LINE__<<2)), \
            "i" (__FILE__), "i" (p) )


#endif /* __X86_BUG_H__ */
